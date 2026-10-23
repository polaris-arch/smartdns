
#include "server.h"
#include "smartdns/dns.h"
#include "smartdns/dns_any.h"
#include "smartdns/http2.h"
#include "smartdns/util.h"
#include "gtest/gtest.h"
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <signal.h>
#include <pthread.h>
#include <set>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "smartdns/upstream_service.h"
namespace {
/* OpenSSL's socket BIO may write during read/handshake as well as SSL_write.
 * Block SIGPIPE only around this thread's TLS operation; preserve errno, SSL
 * return values, prior signal mask and pre-existing pending signals. Peer-close
 * remains a real transport error for assertions rather than killing test.bin. */
template <class Operation> int TlsIoWithoutSigpipe(Operation operation)
{
	sigset_t pipe_signal, previous, pending;
	sigemptyset(&pipe_signal); sigaddset(&pipe_signal, SIGPIPE);
	int error = pthread_sigmask(SIG_BLOCK, &pipe_signal, &previous);
	if (error) { errno = error; return -1; }
	if (sigpending(&pending) != 0) {
		int saved = errno; pthread_sigmask(SIG_SETMASK, &previous, nullptr); errno = saved; return -1;
	}
	bool consume = !sigismember(&previous, SIGPIPE) && !sigismember(&pending, SIGPIPE);
	int result = operation();
	int saved = errno;
	if (consume && result <= 0 && saved == EPIPE) {
		timespec zero{};
		while (sigtimedwait(&pipe_signal, nullptr, &zero) < 0 && errno == EINTR) {
			/* Retry only interrupted zero-time waits before restoring the mask. */
		}
	}
	pthread_sigmask(SIG_SETMASK, &previous, nullptr);
	errno = saved;
	return result;
}

const char *HTTP2_TEST_CERT_FILE = "/tmp/smartdns-service-transport-cert.pem";
const char *HTTP2_TEST_KEY_FILE = "/tmp/smartdns-service-transport-key.pem";

bool EnsureHTTP2TestCert()
{
	if (access(HTTP2_TEST_CERT_FILE, F_OK) == 0 && access(HTTP2_TEST_KEY_FILE, F_OK) == 0) {
		return true;
	}

	return generate_cert_key(HTTP2_TEST_KEY_FILE, HTTP2_TEST_CERT_FILE, NULL, "DNS:smartdns,IP:127.0.0.1", 1) == 0;
}

bool BuildDnsAResponse(const std::vector<uint8_t> &request, const char *ip, std::vector<uint8_t> *response,
					   std::string *error, bool answer_any = false, bool address_negatives = false)
{
	unsigned char request_packet_buff[DNS_PACKSIZE];
	unsigned char response_packet_buff[DNS_PACKSIZE];
	unsigned char encoded_buff[DNS_PACKSIZE];
	struct dns_packet *request_packet = (struct dns_packet *)request_packet_buff;
	struct dns_packet *response_packet = (struct dns_packet *)response_packet_buff;
	char domain[DNS_MAX_CNAME_LEN] = {0};
	int qtype = 0;
	int qclass = 0;
	int rr_count = 0;
	struct dns_rrs *rrs = nullptr;
	unsigned char addr[DNS_RR_A_LEN];

	response->clear();
	if (dns_decode(request_packet, sizeof(request_packet_buff), (unsigned char *)request.data(), request.size()) != 0) {
		*error = "decode DNS request failed";
		return false;
	}

	rrs = dns_get_rrs_start(request_packet, DNS_RRS_QD, &rr_count);
	if (rrs == nullptr || rr_count <= 0 || dns_get_domain(rrs, domain, sizeof(domain), &qtype, &qclass) != 0) {
		*error = "parse DNS question failed";
		return false;
	}

	struct dns_head head = {};
	head.id = request_packet->head.id;
	head.qr = DNS_QR_ANSWER;
	head.opcode = DNS_OP_QUERY;
	head.rd = request_packet->head.rd;
	head.ra = 1;
	head.rcode = DNS_RC_NOERROR;
	if (dns_packet_init(response_packet, sizeof(response_packet_buff), &head) != 0 ||
		dns_add_domain(response_packet, domain, qtype, qclass) != 0) {
		*error = "init DNS response failed";
		return false;
	}

	if (qtype == DNS_T_A || (answer_any && qtype == DNS_T_ANY)) {
		if (inet_pton(AF_INET, ip, addr) != 1) {
			*error = std::string("invalid response IP: ") + ip;
			return false;
		}
		dns_add_A(response_packet, DNS_RRS_AN, domain, 60, addr);
	}

	if (address_negatives && qtype == DNS_T_AAAA) {
		dns_soa soa{}; strcpy(soa.mname, "ns.example"); strcpy(soa.rname, "hostmaster.example");
		soa.minimum = 60;
		dns_add_SOA(response_packet, DNS_RRS_NS, "example", 60, &soa);
	}

	int encoded_len = dns_encode(encoded_buff, sizeof(encoded_buff), response_packet);
	if (encoded_len <= 0) {
		*error = "encode DNS response failed";
		return false;
	}

	response->assign(encoded_buff, encoded_buff + encoded_len);
	return true;
}

// Real TLS sockets. Workers have bounded handshakes and finite test lifetimes.
class PoolTlsPeer {
public:
    std::atomic<unsigned> requests{0}, connections{0};
    std::function<bool()> on_request;
    bool address_negatives = false;
    bool Start(const char *ip, unsigned port, bool h2) {
        h2_ = h2;
        if (!EnsureHTTP2TestCert()) return false;
        ctx_ = SSL_CTX_new(TLS_server_method());
        if (!ctx_ || SSL_CTX_use_certificate_file(ctx_, HTTP2_TEST_CERT_FILE, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx_, HTTP2_TEST_KEY_FILE, SSL_FILETYPE_PEM) != 1) return false;
        if (h2) SSL_CTX_set_alpn_select_cb(ctx_, [](SSL *, const unsigned char **out, unsigned char *len,
                const unsigned char *in, unsigned size, void *) {
            static const unsigned char protocol[] = {2, 'h', '2'};
            return SSL_select_next_proto(const_cast<unsigned char **>(out), len, protocol, sizeof(protocol), in, size)
                == OPENSSL_NPN_NEGOTIATED ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_ALERT_FATAL;
        }, nullptr);
        fd_ = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        int yes = 1; setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(port);
        if (inet_pton(AF_INET, ip, &address.sin_addr) != 1 ||
            bind(fd_, reinterpret_cast<sockaddr *>(&address), sizeof(address)) || listen(fd_, 4)) return false;
        run_ = true;
        accept_ = std::thread([this] {
            while (run_) {
                pollfd p{fd_, POLLIN, 0};
                if (poll(&p, 1, 20) <= 0 || !(p.revents & POLLIN)) continue;
                int fd = accept4(fd_, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
                if (fd >= 0) workers_.emplace_back(&PoolTlsPeer::Serve, this, fd);
            }
        });
        return true;
    }
    ~PoolTlsPeer() {
        run_ = false;
        if (accept_.joinable()) accept_.join();
        for (auto &worker : workers_) worker.join();
        if (fd_ >= 0) close(fd_);
        SSL_CTX_free(ctx_);
    }
private:
    static int Read(void *arg, uint8_t *data, int size) {
        SSL *ssl = static_cast<SSL *>(arg);
        int n = TlsIoWithoutSigpipe([&] { return SSL_read(ssl, data, size); });
        int error = n > 0 ? 0 : SSL_get_error(ssl, n);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) { errno = EAGAIN; return -1; }
        return n;
    }
    static int Write(void *arg, const uint8_t *data, int size) {
        SSL *ssl = static_cast<SSL *>(arg);
        int n = TlsIoWithoutSigpipe([&] { return SSL_write(ssl, data, size); });
        int error = n > 0 ? 0 : SSL_get_error(ssl, n);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) { errno = EAGAIN; return -1; }
        return n;
    }
    bool Exact(SSL *ssl, uint8_t *data, size_t size, bool writing) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        size_t offset = 0;
        while (run_ && offset < size && std::chrono::steady_clock::now() < deadline) {
            int n = writing ? Write(ssl, data + offset, size - offset) : Read(ssl, data + offset, size - offset);
            if (n > 0) offset += n;
            else if (n == 0 || errno != EAGAIN) return false;
            else { pollfd p{SSL_get_fd(ssl), static_cast<short>(writing ? POLLOUT : POLLIN), 0}; poll(&p, 1, 10); }
        }
        return offset == size;
    }
    void Serve(int fd) {
        SSL *ssl = SSL_new(ctx_); SSL_set_fd(ssl, fd);
        bool ready = false;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (run_ && std::chrono::steady_clock::now() < deadline) {
            int n = TlsIoWithoutSigpipe([&] { return SSL_accept(ssl); });
            if (n == 1) { ready = true; break; }
            int e = SSL_get_error(ssl, n);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) break;
            pollfd p{fd, static_cast<short>(e == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN), 0}; poll(&p, 1, 10);
        }
        if (ready) {
            connections++;
            if (h2_) ServeH2(ssl); else ServeDot(ssl);
        }
        SSL_free(ssl); close(fd);
    }
    void ServeDot(SSL *ssl) {
        while (run_) {
            uint8_t prefix[2];
            if (!Exact(ssl, prefix, 2, false)) break;
            unsigned size = (prefix[0] << 8) | prefix[1];
            if (!size || size > DNS_IN_PACKSIZE) break;
            std::vector<uint8_t> body(size), response;
            if (!Exact(ssl, body.data(), body.size(), false)) break;
            std::string error;
            if (!BuildDnsAResponse(body, "192.0.2.88", &response, &error, false, address_negatives)) break;
            requests++; if (on_request) on_request();
            prefix[0] = response.size() >> 8; prefix[1] = response.size();
            if (!Exact(ssl, prefix, 2, true) || !Exact(ssl, response.data(), response.size(), true)) break;
        }
    }
    void ServeH2(SSL *ssl) {
        http2_settings settings{}; settings.max_concurrent_streams = 8;
        auto *ctx = http2_ctx_server_new("pool-peer", Read, Write, ssl, &settings);
        if (!ctx) return;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        int handshake = 0;
        while (run_ && std::chrono::steady_clock::now() < deadline && !(handshake = http2_ctx_handshake(ctx))) {
            pollfd p{SSL_get_fd(ssl), POLLIN, 0}; poll(&p, 1, 5);
        }
        std::map<http2_stream *, std::vector<uint8_t>> bodies;
        std::set<http2_stream *> answered;
        while (run_ && handshake == 1) {
            http2_poll_item items[16]{}; int count = 0;
            int ret = http2_ctx_poll(ctx, items, 16, &count);
            if (ret < 0 && ret != HTTP2_ERR_EAGAIN) break;
            for (int i = 0; i < count; i++) {
                if (!items[i].stream && items[i].readable) {
                    while (auto *stream = http2_ctx_accept_stream(ctx)) bodies[stream] = {};
                }
                if (items[i].stream) http2_stream_put(items[i].stream);
            }
            for (auto it = bodies.begin(); it != bodies.end();) {
                auto *stream = it->first;
                if (!answered.count(stream)) {
                    uint8_t data[1024]; int n;
                    while ((n = http2_stream_read_body(stream, data, sizeof(data))) > 0) it->second.insert(it->second.end(), data, data + n);
                    if (it->second.size() > DNS_IN_PACKSIZE) { run_ = false; break; }
                    if (http2_stream_is_remote_end(stream)) {
                        requests++; bool throttle = on_request && on_request();
                        std::vector<uint8_t> response; std::string error;
                        if (throttle) {
                            http2_header_pair headers[] = {{"retry-after", "1"}, {"content-length", "0"}};
                            http2_stream_set_response(stream, 429, headers, 2);
                        } else {
                            if (!BuildDnsAResponse(it->second, "192.0.2.89", &response, &error, false, address_negatives)) { run_ = false; break; }
                            std::string length = std::to_string(response.size());
                            http2_header_pair headers[] = {{"content-type", "application/dns-message"}, {"content-length", length.c_str()}};
                            http2_stream_set_response(stream, 200, headers, 2);
                        }
                        http2_stream_write_body(stream, response.data(), response.size(), 1); answered.insert(stream);
                    }
                }
                if (answered.count(stream) && http2_stream_is_end(stream)) {
                    answered.erase(stream); http2_stream_close(stream); it = bodies.erase(it);
                } else ++it;
            }
            pollfd p{SSL_get_fd(ssl), static_cast<short>(POLLIN | (http2_ctx_want_write(ctx) ? POLLOUT : 0)), 0}; poll(&p, 1, 5);
        }
        for (auto &body : bodies) http2_stream_close(body.first);
        http2_ctx_close(ctx);
    }
    bool h2_ = false; int fd_ = -1; SSL_CTX *ctx_ = nullptr;
    std::atomic<bool> run_{false}; std::thread accept_; std::vector<std::thread> workers_;
};
bool query_udp(const std::string &name, unsigned port, int qtype = DNS_T_A)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    timeval timeout{2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    sockaddr_in target{}; target.sin_family = AF_INET; target.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &target.sin_addr);
    alignas(dns_packet) unsigned char storage[DNS_PACKSIZE];
    unsigned char wire[DNS_IN_PACKSIZE];
    auto *packet = reinterpret_cast<dns_packet *>(storage);
    dns_head head{}; head.id = 4321; head.rd = 1;
    dns_packet_init(packet, sizeof(storage), &head);
    dns_add_domain(packet, name.c_str(), qtype, DNS_C_IN);
    int length = dns_encode(wire, sizeof(wire), packet);
    bool good = length > 0 && sendto(fd, wire, length, 0, reinterpret_cast<sockaddr *>(&target), sizeof(target)) == length;
    if (good) {
        length = recv(fd, wire, sizeof(wire), 0);
        good = length > 0 && !dns_decode(packet, sizeof(storage), wire, length) &&
            packet->head.id == 4321 && packet->head.rcode == DNS_RC_NOERROR && packet->head.ancount == (qtype == DNS_T_A ? 1 : 0) &&
            (qtype == DNS_T_A || packet->head.nscount == 1);
    }
    close(fd);
    return good;
}

void transport_case(bool h2, bool throttle, unsigned nodata_rate = 0) {
    PoolTlsPeer first, second;
    first.address_negatives = second.address_negatives = nodata_rate != 0;
    std::mutex lock; std::vector<std::chrono::steady_clock::time_point> wire_times;
    std::vector<unsigned> wire_backend;
    auto observe = [&](unsigned backend) {
        std::lock_guard<std::mutex> guard(lock); wire_times.push_back(std::chrono::steady_clock::now());
        wire_backend.push_back(backend);
        return throttle && wire_times.size() == 1;
    };
    first.on_request = [&] { return observe(0); }; second.on_request = [&] { return observe(1); };
    unsigned port = h2 ? 62982 : 62981, listen = h2 ? 62782 : 62781;
    ASSERT_TRUE(first.Start("127.0.0.1", port, h2));
    ASSERT_TRUE(second.Start("127.0.0.2", port, h2));
    smartdns::Server resolver(smartdns::Server::CREATE_MODE_THREAD);
    std::string config = "bind 127.0.0.1:" + std::to_string(listen) + "\nserver " + (h2 ? "https://" : "tls://") +
        "resolver.transport.example:" + std::to_string(port) + (h2 ? "/dns-query" : "") +
        " -upstream-ip-pool -host-ip 127.0.0.1,127.0.0.2 -no-check-certificate" + (h2 ? " -alpn h2" : "") +
        (nodata_rate ? " -max-query-rate " + std::to_string(nodata_rate) + " -query-burst 1" : "") +
        "\ncache-size 0\ncache-persist no\nprefetch-domain no\nserve-expired no\n"
        "dualstack-ip-selection no\nspeed-check-mode none\nresponse-mode fastest-response\n";
    ASSERT_TRUE(resolver.Start(config));
    unsigned queries = nodata_rate ? 12 : 4;
    for (unsigned i = 0; i < queries; i++)
        ASSERT_TRUE(query_udp("transport-" + std::to_string(i) + ".example", listen,
                              nodata_rate && (i / 2) % 2 ? DNS_T_AAAA : DNS_T_A));
    dns_upstream_service_snapshot_v1 snapshot{};
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    do {
        ASSERT_EQ(dns_client_get_service_snapshot_v1(&snapshot, 1), 1);
        if (snapshot.success_count == queries && !snapshot.in_flight) break;
        poll(nullptr, 0, 5);
    } while (std::chrono::steady_clock::now() < deadline);
    EXPECT_EQ(snapshot.endpoint_count, 2U); EXPECT_EQ(snapshot.query_count, queries);
    EXPECT_EQ(snapshot.success_count, queries); EXPECT_EQ(snapshot.failure_count, 0U); EXPECT_EQ(snapshot.skip_count, 0U);
    EXPECT_EQ(snapshot.attempt_count, queries + (throttle ? 1 : 0));
    EXPECT_EQ(first.requests + second.requests, queries + (throttle ? 1 : 0));
    EXPECT_LE(std::abs(static_cast<int>(first.requests) - static_cast<int>(second.requests)), 1);
    EXPECT_EQ(first.connections, 1U); EXPECT_EQ(second.connections, 1U);
    std::lock_guard<std::mutex> guard(lock);
    for (size_t i = 1; i < wire_backend.size(); i++) EXPECT_NE(wire_backend[i - 1], wire_backend[i]);
    if (throttle) {
        ASSERT_GE(wire_times.size(), 2U);
        EXPECT_GE(std::chrono::duration_cast<std::chrono::milliseconds>(wire_times[1] - wire_times[0]).count(), 900);
    }
}
} // namespace
TEST(UpstreamServiceTransport, RealTlsDualBackendRoundRobinAndConnectionReuse) {
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    ASSERT_EXIT({ transport_case(false, false); _exit(::testing::Test::HasFailure() ? 1 : 0); }, ::testing::ExitedWithCode(0), "");
}
TEST(UpstreamServiceTransport, RealH2DualBackendShared429CooldownAndRoundRobin) {
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    ASSERT_EXIT({ transport_case(true, true); _exit(::testing::Test::HasFailure() ? 1 : 0); }, ::testing::ExitedWithCode(0), "");
}

TEST(UpstreamServiceTransport, RealTlsNodataCompletesServiceWithoutDuplicateAttempt) {
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    ASSERT_EXIT({ transport_case(false, false, 20); _exit(::testing::Test::HasFailure() ? 1 : 0); }, ::testing::ExitedWithCode(0), "");
}
TEST(UpstreamServiceTransport, RealH2Nodata20CompletesServiceWithoutDuplicateAttempt) {
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    ASSERT_EXIT({ transport_case(true, false, 20); _exit(::testing::Test::HasFailure() ? 1 : 0); }, ::testing::ExitedWithCode(0), "");
}
TEST(UpstreamServiceTransport, RealH2Nodata40CompletesServiceWithoutDuplicateAttempt) {
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    ASSERT_EXIT({ transport_case(true, false, 40); _exit(::testing::Test::HasFailure() ? 1 : 0); }, ::testing::ExitedWithCode(0), "");
}
