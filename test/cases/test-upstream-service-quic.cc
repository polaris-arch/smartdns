
#include "server.h"
#include "smartdns/dns.h"
#include "smartdns/dns_any.h"
#include "smartdns/http2.h"
#include "smartdns/util.h"
#include "gtest/gtest.h"
#ifdef SMARTDNS_TEST_PINNED_QUIC
#include "include/openssl-quic-probe.h"
#endif
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
extern "C" {
#include "dns_client/dns_client.h"
#include "dns_client/upstream_policy.h"
#include "smartdns/upstream_service.h"
}

// Test-only datagram loss: the peer's real plaintext ACK callback arms a
// one-shot drop of its next syscall batch. Returning the real byte counts makes
// the SDK observe a successful write followed by genuine wire loss.
namespace {
struct QuicWireFault {int fd=-1;bool pending=false;std::atomic<unsigned> *drops=nullptr;};
thread_local QuicWireFault quic_wire_fault;
bool drop_quic_datagram(int fd) {
    if(!quic_wire_fault.pending||fd!=quic_wire_fault.fd)return false;
    quic_wire_fault.pending=false;++*quic_wire_fault.drops;return true;
}
size_t message_bytes(const msghdr *message) {
    size_t size=0;for(size_t i=0;i<message->msg_iovlen;++i)size+=message->msg_iov[i].iov_len;return size;
}
}
extern "C" ssize_t __real_sendmsg(int,const msghdr *,int);
extern "C" int __real_sendmmsg(int,mmsghdr *,unsigned,int);
extern "C" ssize_t __real_sendto(int,const void *,size_t,int,const sockaddr *,socklen_t);
extern "C" ssize_t __wrap_sendmsg(int fd,const msghdr *message,int flags) {
    size_t size=message_bytes(message);
    if(size&&drop_quic_datagram(fd))return static_cast<ssize_t>(size);
    return __real_sendmsg(fd,message,flags);
}
extern "C" int __wrap_sendmmsg(int fd,mmsghdr *messages,unsigned count,int flags) {
    if(count&&drop_quic_datagram(fd)) {
        for(unsigned i=0;i<count;++i)messages[i].msg_len=message_bytes(&messages[i].msg_hdr);
        return static_cast<int>(count);
    }
    return __real_sendmmsg(fd,messages,count,flags);
}
extern "C" ssize_t __wrap_sendto(int fd,const void *data,size_t size,int flags,const sockaddr *address,socklen_t length) {
    if(size&&drop_quic_datagram(fd))return static_cast<ssize_t>(size);
    return __real_sendto(fd,data,size,flags,address,length);
}

#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC) && OPENSSL_VERSION_NUMBER >= 0x30500000L
namespace {
const char *HTTP2_TEST_CERT_FILE = "/tmp/smartdns-service-quic-cert.pem";
const char *HTTP2_TEST_KEY_FILE = "/tmp/smartdns-service-quic-key.pem";

bool EnsureHTTP2TestCert()
{
	if (access(HTTP2_TEST_CERT_FILE, F_OK) == 0 && access(HTTP2_TEST_KEY_FILE, F_OK) == 0) {
		return true;
	}

	return generate_cert_key(HTTP2_TEST_KEY_FILE, HTTP2_TEST_CERT_FILE, NULL, "DNS:smartdns,IP:127.0.0.1", 1) == 0;
}

bool BuildDnsAResponse(const std::vector<uint8_t> &request, const char *ip, std::vector<uint8_t> *response,
					   std::string *error, bool answer_any = false)
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

	int encoded_len = dns_encode(encoded_buff, sizeof(encoded_buff), response_packet);
	if (encoded_len <= 0) {
		*error = "encode DNS response failed";
		return false;
	}

	response->assign(encoded_buff, encoded_buff + encoded_len);
	return true;
}

bool query_udp(const std::string &name, unsigned port)
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
    dns_add_domain(packet, name.c_str(), DNS_T_A, DNS_C_IN);
    int length = dns_encode(wire, sizeof(wire), packet);
    bool good = length > 0 && sendto(fd, wire, length, 0, reinterpret_cast<sockaddr *>(&target), sizeof(target)) == length;
    if (good) {
        length = recv(fd, wire, sizeof(wire), 0);
        good = length > 0 && !dns_decode(packet, sizeof(storage), wire, length) &&
            packet->head.id == 4321 && packet->head.rcode == DNS_RC_NOERROR && packet->head.ancount == 1;
    }
    close(fd);
    return good;
}

// Independent minimal peer framing: real QUIC packets, not core selector hooks.
static bool varint(const std::vector<uint8_t> &bytes, size_t &offset, uint64_t &value) {
    if (offset >= bytes.size()) return false;
    unsigned size = 1u << (bytes[offset] >> 6);
    if (bytes.size() - offset < size) return false;
    value = bytes[offset++] & 63;
    while (--size) value = (value << 8) | bytes[offset++];
    return true;
}
static void append_varint(std::vector<uint8_t> &bytes, unsigned value) {
    if (value < 64) bytes.push_back(value);
    else { bytes.push_back(0x40 | (value >> 8)); bytes.push_back(value); }
}
class PoolQuicPeer {
    struct Stream {
        SSL *ssl = nullptr;
        std::vector<uint8_t> input, output;
        size_t written = 0;
        bool answered = false, concluded = false, hold = false;
    };
    struct Connection {
        SSL *ssl = nullptr;
        std::vector<Stream> streams;
        bool control_created = false;
    };
public:
    std::atomic<unsigned> requests{0}, connections{0};
    std::atomic<bool> failed{false};
    std::function<void()> on_request;
    std::set<std::string> reset_names, hold_names; // frozen before worker starts
    std::atomic<unsigned> dropped_ack_datagrams{0}, closed_connections{0}, emitted_closes{0};
    std::atomic<unsigned> ack_frames{0}, reset_requests{0}, held_requests{0};
#ifdef SMARTDNS_TEST_PINNED_QUIC
    bool FreshStreamSnapshot(openssl_quic_stream_snapshot &snapshot) {
        uint64_t requested;
        { std::lock_guard<std::mutex> lock(snapshot_mutex_); requested=++snapshot_requested_; }
        auto until=std::chrono::steady_clock::now()+std::chrono::seconds(1);
        do {
            {
                std::lock_guard<std::mutex> lock(snapshot_mutex_);
                if(snapshot_completed_>=requested) {
                    snapshot=stream_snapshot_;return snapshot_valid_;
                }
            }
            if(!run_||failed)return false;
            poll(nullptr,0,1);
        }while(std::chrono::steady_clock::now()<until);
        return false;
    }
#endif
    void DropNextAck() { drop_ack_requested_ = true; }
    void RequestClose() { close_requested_ = true; }
    bool Start(const char *ip, unsigned port, bool h3) {
        h3_ = h3;
        if (!EnsureHTTP2TestCert()) return false;
        ctx_ = SSL_CTX_new(OSSL_QUIC_server_method());
        if (!ctx_ || SSL_CTX_use_certificate_file(ctx_, HTTP2_TEST_CERT_FILE, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx_, HTTP2_TEST_KEY_FILE, SSL_FILETYPE_PEM) != 1) return false;
        SSL_CTX_set_msg_callback(ctx_,Message);
        SSL_CTX_set_msg_callback_arg(ctx_,this);
        SSL_CTX_set_alpn_select_cb(ctx_, [](SSL *, const unsigned char **out, unsigned char *len,
                const unsigned char *in, unsigned size, void *arg) {
            static const unsigned char h3_protocol[] = {2,'h','3'}, doq_protocol[] = {3,'d','o','q'};
            auto *self = static_cast<PoolQuicPeer *>(arg);
            const unsigned char *protocol = self->h3_ ? h3_protocol : doq_protocol;
            return SSL_select_next_proto(const_cast<unsigned char **>(out), len, protocol, self->h3_ ? 3 : 4, in, size)
                == OPENSSL_NPN_NEGOTIATED ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_ALERT_FATAL;
        }, this);
        fd_ = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(port);
        if (fd_ < 0 || inet_pton(AF_INET, ip, &address.sin_addr) != 1 ||
            bind(fd_, reinterpret_cast<sockaddr *>(&address), sizeof(address))) return false;
        listener_ = SSL_new_listener(ctx_, 0);
        if (!listener_ || SSL_set_fd(listener_, fd_) != 1 || SSL_set_blocking_mode(listener_, 0) != 1 ||
            SSL_listen(listener_) != 1) return false;
        run_ = true; worker_ = std::thread(&PoolQuicPeer::Run, this); return true;
    }
    ~PoolQuicPeer() {
        run_ = false; if (worker_.joinable()) worker_.join();
        SSL_free(listener_); SSL_CTX_free(ctx_); if (fd_ >= 0) close(fd_);
    }
private:
    static void Message(int writing,int version,int type,const void *bytes,size_t size,SSL *,void *arg) {
        auto *self=static_cast<PoolQuicPeer *>(arg);
        if(writing&&version==OSSL_QUIC1_VERSION&&type==SSL3_RT_QUIC_FRAME_FULL&&size) {
            unsigned frame=*static_cast<const unsigned char *>(bytes);
            if(frame==0x1c||frame==0x1d)self->emitted_closes++;
            if(frame==2||frame==3) {
                self->ack_frames++;
                if(self->drop_ack_requested_.exchange(false)) {
                    quic_wire_fault.fd=self->fd_;quic_wire_fault.pending=true;
                    quic_wire_fault.drops=&self->dropped_ack_datagrams;
                }
            }
        }
    }
    bool Request(Stream &stream, std::vector<uint8_t> &dns) {
        if (!h3_) {
            if (stream.input.size() < 2) return false;
            size_t size = (stream.input[0] << 8) | stream.input[1];
            if (!size || size > DNS_IN_PACKSIZE) { failed = true; return false; }
            if (stream.input.size() < size + 2) return false;
            dns.assign(stream.input.begin()+2, stream.input.begin()+2+size); return true;
        }
        size_t pos = 0;
        while (pos < stream.input.size()) {
            uint64_t type, size;
            if (!varint(stream.input, pos, type) || !varint(stream.input, pos, size)) return false;
            if (size > DNS_IN_PACKSIZE) { failed = true; return false; }
            if (size > stream.input.size() - pos) return false;
            if (type == 0) { dns.assign(stream.input.begin()+pos, stream.input.begin()+pos+size); return true; }
            pos += size;
        }
        return false;
    }
    void Process(Stream &stream) {
        uint8_t bytes[2048]; size_t got = 0;
        while (SSL_read_ex(stream.ssl, bytes, sizeof(bytes), &got) == 1 && got) {
            stream.input.insert(stream.input.end(), bytes, bytes+got);
            if (stream.input.size() > 32768) { failed = true; return; }
        }
        // Peer control/QPACK streams are consumed but never interpreted as DNS.
        if (SSL_get_stream_id(stream.ssl) & 2u) return;
        if (!stream.answered) {
            std::vector<uint8_t> request, response; std::string error;
            if (!Request(stream, request)) return;
            if (!BuildDnsAResponse(request, "192.0.2.90", &response, &error)) { failed = true; return; }
            requests++; if (on_request) on_request();
            if (!reset_names.empty() || !hold_names.empty()) {
                alignas(dns_packet) unsigned char storage[DNS_PACKSIZE];
                auto *packet = reinterpret_cast<dns_packet *>(storage);
                char name[DNS_MAX_CNAME_LEN]{}; int n=0, type=0, klass=0;
                if (dns_decode(packet,sizeof(storage),request.data(),request.size())) { failed=true; return; }
                dns_rrs *rr=dns_get_rrs_start(packet,DNS_RRS_QD,&n);
                if (!rr || dns_get_domain(rr,name,sizeof(name),&type,&klass)) { failed=true; return; }
                if (reset_names.count(name)) {
                    reset_requests++;
                    SSL_STREAM_RESET_ARGS args{}; args.quic_error_code=h3_?0x10c:3;
                    if (SSL_stream_reset(stream.ssl,&args,sizeof(args)) != 1) failed=true;
                    stream.answered=true; stream.concluded=true; return;
                }
                if (hold_names.count(name)) { held_requests++;stream.answered=true; stream.hold=true; return; }
            }
            if (h3_) {
                // HEADERS: Required Insert Count=0, Delta Base=0, static :status=200.
                stream.output = {1,3,0,0,0xd9,0}; append_varint(stream.output, response.size());
            } else stream.output = {static_cast<uint8_t>(response.size() >> 8), static_cast<uint8_t>(response.size())};
            stream.output.insert(stream.output.end(), response.begin(), response.end()); stream.answered = true;
        }
    }
    void Flush(Stream &stream, bool fin) {
        if (stream.hold) return;
        if (stream.written < stream.output.size()) {
            size_t wrote = 0;
            SSL_write_ex(stream.ssl, stream.output.data()+stream.written, stream.output.size()-stream.written, &wrote);
            stream.written += wrote;
        }
        if (fin && stream.answered && stream.written == stream.output.size() && !stream.concluded)
            stream.concluded = SSL_stream_conclude(stream.ssl, 0) == 1;
    }
    void Run() {
        std::vector<Connection> peers;
        while (run_ && !failed) {
            if (close_requested_.exchange(false)) {
                for (auto &peer : peers) {
                    // Only the worker touches its SDK objects. Explicitly skip
                    // stream flush; RAPID alone only skips the terminating wait.
                    unsigned before=emitted_closes;
                    int result=SSL_shutdown_ex(peer.ssl,
                        SSL_SHUTDOWN_FLAG_RAPID|SSL_SHUTDOWN_FLAG_NO_STREAM_FLUSH,nullptr,0);
                    bool signaled=result>=0&&(SSL_get_shutdown(peer.ssl)&SSL_SENT_SHUTDOWN)
                        &&emitted_closes>before;
                    if(!signaled)failed=true;
                    for (auto &stream : peer.streams) SSL_free(stream.ssl);
                    SSL_free(peer.ssl);if(signaled)closed_connections++;
                }
                peers.clear();
            }
            SSL_handle_events(listener_);
            while (SSL *peer = SSL_accept_connection(listener_, SSL_ACCEPT_CONNECTION_NO_BLOCK)) {
                if (peers.size() >= 4) { SSL_free(peer); failed = true; break; }
                // Incoming QUIC channels do not inherit the ctx frame hook.
                // Bind it to the real accepted connection before application I/O.
                SSL_set_msg_callback(peer,Message);SSL_set_msg_callback_arg(peer,this);
                SSL_set_blocking_mode(peer, 0); SSL_set_default_stream_mode(peer, SSL_DEFAULT_STREAM_MODE_NONE);
                Connection conn; conn.ssl = peer; peers.push_back(std::move(conn)); connections++;
            }
            for (auto &peer : peers) {
                SSL_do_handshake(peer.ssl); SSL_handle_events(peer.ssl);
                if (!SSL_is_init_finished(peer.ssl)) continue;
                if (h3_ && !peer.control_created) {
                    SSL *control = SSL_new_stream(peer.ssl, SSL_STREAM_FLAG_UNI);
                    if (control) {
                        Stream stream; stream.ssl = control; stream.output = {0,4,0}; stream.answered = true;
                        peer.streams.push_back(std::move(stream)); peer.control_created = true;
                    }
                }
                while (SSL *ssl = SSL_accept_stream(peer.ssl, SSL_ACCEPT_STREAM_NO_BLOCK)) {
                    if (peer.streams.size() >= 24) { SSL_free(ssl); failed = true; break; }
                    Stream stream; stream.ssl = ssl; peer.streams.push_back(std::move(stream));
                }
                for (auto &stream : peer.streams) {
                    // Locally initiated control stream stays open for connection lifetime.
                    bool own_control = (SSL_get_stream_id(stream.ssl) & 3u) == 3u;
                    if (!own_control) Process(stream);
                    Flush(stream, !own_control);
                }
                // Bound live streams, not the connection's lifetime request
                // count. Free only normally finished bidirectional streams;
                // QUIC keeps any remaining protocol state in the connection.
                for (auto it = peer.streams.begin(); it != peer.streams.end();) {
                    auto terminal=[](int state) { return state==SSL_STREAM_STATE_FINISHED ||
                        state==SSL_STREAM_STATE_RESET_LOCAL || state==SSL_STREAM_STATE_RESET_REMOTE ||
                        state==SSL_STREAM_STATE_CONN_CLOSED; };
                    if (!(SSL_get_stream_id(it->ssl) & 2u) &&
                        terminal(SSL_get_stream_read_state(it->ssl)) && terminal(SSL_get_stream_write_state(it->ssl))) {
                        SSL_free(it->ssl); it = peer.streams.erase(it);
                    } else ++it;
                }
            }
#ifdef SMARTDNS_TEST_PINNED_QUIC
            // Sample only after observing the consumer's request, then publish
            // the complete SDK-owner-thread snapshot. No stale zero atomic or
            // second live read, and no additional SDK or I/O tick.
            uint64_t requested;
            { std::lock_guard<std::mutex> lock(snapshot_mutex_); requested=snapshot_requested_; }
            openssl_quic_stream_snapshot snapshot{};
            bool valid=peers.size()==1&&test_openssl_quic_snapshot(peers.front().ssl,&snapshot);
            {
                std::lock_guard<std::mutex> lock(snapshot_mutex_);
                stream_snapshot_=snapshot;snapshot_valid_=valid;snapshot_completed_=requested;
            }
#endif
            pollfd p{fd_, POLLIN, 0}; poll(&p, 1, 1);
        }
        for (auto &peer : peers) { for (auto &stream : peer.streams) SSL_free(stream.ssl); SSL_free(peer.ssl); }
        quic_wire_fault=QuicWireFault{};
    }
#ifdef SMARTDNS_TEST_PINNED_QUIC
    std::mutex snapshot_mutex_;
    openssl_quic_stream_snapshot stream_snapshot_{};
    uint64_t snapshot_requested_=0,snapshot_completed_=0;
    bool snapshot_valid_=false;
#endif
    bool h3_ = false; int fd_ = -1; SSL_CTX *ctx_ = nullptr; SSL *listener_ = nullptr;
    std::atomic<bool> run_{false}, close_requested_{false}, drop_ack_requested_{false}; std::thread worker_;
};
void quic_error_ready_case(bool h3) {
    auto peer = std::make_unique<PoolQuicPeer>();
    unsigned port = h3 ? 62994 : 62993, listen = h3 ? 62794 : 62793;
    ASSERT_TRUE(peer->Start("127.0.0.1", port, h3));
    smartdns::Server resolver(smartdns::Server::CREATE_MODE_THREAD);
    std::string config = "bind 127.0.0.1:" + std::to_string(listen) + "\nserver " + (h3 ? "h3://" : "quic://") +
        "resolver.quic-error.example:" + std::to_string(port) + (h3 ? "/dns-query" : "") +
        " -upstream-ip-pool -host-ip 127.0.0.1 -no-check-certificate\n"
        "cache-size 0\ncache-persist no\nprefetch-domain no\nserve-expired no\n"
        "dualstack-ip-selection no\nspeed-check-mode none\nresponse-mode fastest-response\nlog-level error\n";
    ASSERT_TRUE(resolver.Start(config));
    ASSERT_TRUE(query_udp("warm.quic-error.example", listen));
    dns_server_info *endpoint = nullptr, *candidate;
    pthread_mutex_lock(&client.server_list_lock);
    list_for_each_entry(candidate, &client.dns_server_list, list) {
        if (candidate->type == (h3 ? DNS_SERVER_HTTP3 : DNS_SERVER_QUIC)) { endpoint = candidate; break; }
    }
    pthread_mutex_unlock(&client.server_list_lock);
    ASSERT_NE(endpoint, nullptr);
    pthread_mutex_lock(&endpoint->lock);
    peer.reset();
    int fd = endpoint->fd;
    unsigned char discard[2048];
    while (recv(fd, discard, sizeof(discard), MSG_DONTWAIT) > 0) {}
    int sent = send(fd, "x", 1, MSG_DONTWAIT);
    pollfd ready{fd, POLLIN | POLLERR, 0};
    int polled = poll(&ready, 1, 200);
    dns_client_loop_diagnostics_v1 before{}, after{};
    int got_before = dns_client_get_loop_diagnostics_v1(&before);
    pthread_mutex_unlock(&endpoint->lock);
    fprintf(stderr, "QUIC error fixture: h3=%d sent=%d poll=%d revents=0x%x snapshot=%d\n",
            h3, sent, polled, ready.revents, got_before);
    ASSERT_EQ(sent, 1); ASSERT_EQ(polled, 1); ASSERT_TRUE(ready.revents & POLLERR);
    ASSERT_FALSE(ready.revents & POLLIN); ASSERT_EQ(got_before, 0);
    poll(nullptr, 0, 1200);
    ASSERT_EQ(dns_client_get_loop_diagnostics_v1(&after), 0);
    int pending_error = 0; socklen_t length = sizeof(pending_error);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &pending_error, &length); // bounded cleanup on the old implementation
    printf("QUIC error result: h3=%d iterations=%llu ready=%llu pending_error=%d\n", h3,
            (unsigned long long)(after.iterations - before.iterations),
            (unsigned long long)(after.ready_events - before.ready_events), pending_error);
    fflush(stdout);
    EXPECT_LT(after.iterations - before.iterations, 1000U)
        << "error-only ready events=" << after.ready_events - before.ready_events
        << ", pending socket error=" << pending_error;
}
#ifdef SMARTDNS_TEST_PINNED_QUIC
// SSL_free marks streams deleted without ticking the reactor itself. Completed
// tails from the current cohort may wait for a real event; their count alone
// does not establish a leak or the size of the last SDK turn. Every older
// cohort must disappear on this same connection. All retained current IDs must
// be acknowledged, fully read, deleted and GC-ready, within the exact number
// allocated by this cohort. Unfinished streams get no exemption.
bool quic_cohort_retention_valid(const openssl_quic_stream_snapshot &s, uint64_t begin,
                                 uint64_t end) {
    if (end <= begin || s.requests > end-begin ||
        s.deleted_requests != s.requests || s.deleted_ready_requests != s.requests ||
        s.fully_acked_requests != s.requests || s.fully_read_requests != s.requests)
        return false;
    return s.requests == 0 ||
        (s.oldest_request_id >= (begin << 2) && s.newest_request_id < (end << 2));
}

bool quic_batch_quiescent(const openssl_quic_stream_snapshot &s, uint64_t begin,
                          uint64_t end) {
    return s.next_local_bidi_ordinal==end&&quic_cohort_retention_valid(s,begin,end);
}

void quic_reclamation_child_result() {
    const auto *result=::testing::UnitTest::GetInstance()->current_test_info()->result();
    for(int i=0;i<result->total_part_count();++i) {
        const auto &part=result->GetTestPartResult(i);
        if(part.failed())fprintf(stderr,"%s:%d: %s\n",part.file_name(),part.line_number(),part.summary());
    }
    fflush(stdout);fflush(stderr);
}

void quic_reclamation_case(bool h3) {
    PoolQuicPeer peer;
    peer.reset_names.insert("reset.reclamation.example");
    peer.hold_names.insert("timeout.reclamation.example");
    unsigned port=h3?62986:62985, listen=h3?62786:62785;
    ASSERT_TRUE(peer.Start("127.0.0.1",port,h3));
    smartdns::Server resolver(smartdns::Server::CREATE_MODE_THREAD);
    std::string config="bind 127.0.0.1:"+std::to_string(listen)+"\nserver "+(h3?"h3://":"quic://")+
        "memory.test:"+std::to_string(port)+(h3?"/dns-query":"")+
        " -upstream-ip-pool -host-ip 127.0.0.1 -no-check-certificate -max-query-rate 200 -query-burst 16"
        " -max-concurrent-queries 16 -upstream-query-timeout-ms 600 -upstream-response-timeout-ms 500"
        " -upstream-connect-timeout-ms 400\n"
        "cache-size 0\ncache-persist no\nprefetch-domain no\nserve-expired no\ndualstack-ip-selection no\n"
        "speed-check-mode none\nresponse-mode fastest-response\nlog-level error\n";
    ASSERT_TRUE(resolver.Start(config));ASSERT_TRUE(query_udp("warm.reclamation.example",listen));
    dns_server_info *endpoint=nullptr,*item;
    pthread_mutex_lock(&client.server_list_lock);
    list_for_each_entry(item,&client.dns_server_list,list) {
        if(item->type==(h3?DNS_SERVER_HTTP3:DNS_SERVER_QUIC)) {endpoint=item;break;}
    }
    pthread_mutex_unlock(&client.server_list_lock);ASSERT_NE(endpoint,nullptr);
    pthread_mutex_lock(&endpoint->lock);SSL *connection=endpoint->ssl;pthread_mutex_unlock(&endpoint->lock);
    ASSERT_NE(connection,nullptr);
    bool same=false,valid=false;int infinite=1,timeout_valid=0;timeval timeout{};
    auto capture=[&](openssl_quic_stream_snapshot &snapshot) {
        pthread_mutex_lock(&endpoint->lock);
        same=endpoint->ssl==connection;
        valid=same&&test_openssl_quic_snapshot(endpoint->ssl,&snapshot);
        // The probe has released the SDK mutex; this public getter only reads
        // its cached deadline and never forces event processing.
        infinite=1;timeout_valid=valid&&SSL_get_event_timeout(endpoint->ssl,&timeout,&infinite);
        pthread_mutex_unlock(&endpoint->lock);
    };
    struct CohortObservation {
        openssl_quic_stream_snapshot client{},peer{};
        bool peer_valid=false;
    };
    auto wait_quiescent=[&](uint64_t begin,uint64_t end,unsigned batch) {
        auto until=std::chrono::steady_clock::now()+std::chrono::seconds(6);
        CohortObservation observed;
        auto &snapshot=observed.client;
        do {
            capture(snapshot);
            observed.peer_valid=peer.FreshStreamSnapshot(observed.peer);
            if(valid&&quic_batch_quiescent(snapshot,begin,end)&&observed.peer_valid&&
               quic_cohort_retention_valid(observed.peer,begin,end))break;
            poll(nullptr,0,10);
        }while(std::chrono::steady_clock::now()<until);
        fprintf(stderr,"QUIC retained h3=%d batch=%u requests=%zu deleted=%zu ready=%zu acked=%zu read=%zu"
            " ids=%llu..%llu ordinals=%llu..%llu actual_next=%llu state=%u/%u control=%zu peer_deleted=%zu"
            " connections=%u acks=%u drops=%u timeout_valid=%d infinite=%d timeout_us=%lld\n",h3,batch,
            snapshot.requests,snapshot.deleted_requests,snapshot.deleted_ready_requests,
            snapshot.fully_acked_requests,snapshot.fully_read_requests,
            (unsigned long long)snapshot.oldest_request_id,(unsigned long long)snapshot.newest_request_id,
            (unsigned long long)begin,(unsigned long long)end,(unsigned long long)snapshot.next_local_bidi_ordinal,
            snapshot.oldest_request_send_state,snapshot.oldest_request_recv_state,snapshot.control,
            observed.peer.deleted_requests,peer.connections.load(),peer.ack_frames.load(),peer.dropped_ack_datagrams.load(),timeout_valid,infinite,
            infinite?-1LL:(long long)timeout.tv_sec*1000000+timeout.tv_usec);
        fprintf(stderr,"QUIC peer h3=%d batch=%u valid=%d requests=%zu deleted=%zu ready=%zu acked=%zu read=%zu"
            " ids=%llu..%llu state=%u/%u\n",h3,batch,observed.peer_valid,observed.peer.requests,
            observed.peer.deleted_requests,observed.peer.deleted_ready_requests,
            observed.peer.fully_acked_requests,observed.peer.fully_read_requests,
            (unsigned long long)observed.peer.oldest_request_id,(unsigned long long)observed.peer.newest_request_id,
            observed.peer.oldest_request_send_state,observed.peer.oldest_request_recv_state);
        return observed;
    };
    openssl_quic_stream_snapshot initial{};capture(initial);ASSERT_TRUE(same&&valid);
    auto wait_endpoint_ready=[&](const char *stage) {
        auto until=std::chrono::steady_clock::now()+std::chrono::seconds(6);
        unsigned long retry=0,cooldown=0;unsigned active=0;uint64_t in_flight=0;int copied=0;
        do {
            pthread_mutex_lock(&endpoint->lock);
            same=endpoint->ssl==connection;
            unsigned long now=get_tick_count();
            unsigned long retry_at=__atomic_load_n(&endpoint->service_retry_at,__ATOMIC_ACQUIRE);
            retry=retry_at>now?retry_at-now:0;
            cooldown=_dns_policy_endpoint_cooldown(endpoint,now);
            active=__atomic_load_n(&endpoint->active_attempts,__ATOMIC_ACQUIRE);
            pthread_mutex_unlock(&endpoint->lock);
            dns_upstream_service_snapshot_v1 service{};
            copied=dns_client_get_service_snapshot_v1(&service,1);in_flight=service.in_flight;
            if(!same||peer.connections!=1||peer.failed)break;
            if(copied==1&&!in_flight&&!active&&!retry&&!cooldown)return true;
            poll(nullptr,0,10);
        }while(std::chrono::steady_clock::now()<until);
        fprintf(stderr,"QUIC admission stage=%s same=%d peer_failed=%d connections=%u active=%u"
            " in_flight=%llu copied=%d retry_ms=%lu cooldown_ms=%lu resets=%u held=%u\n",stage,same,
            (int)peer.failed.load(),peer.connections.load(),active,(unsigned long long)in_flight,copied,
            retry,cooldown,peer.reset_requests.load(),peer.held_requests.load());
        return false;
    };
    uint64_t before=initial.next_local_bidi_ordinal;
    for(unsigned batch=0;batch<6;++batch) {
        peer.DropNextAck();
        if(batch<3) {
            for(unsigned n=0;n<32;++n)ASSERT_TRUE(query_udp("batch"+std::to_string(batch)+"-"+std::to_string(n)+".reclamation.example",listen));
        } else {
            std::atomic<unsigned> successes{0};std::vector<std::thread> clients;
            for(unsigned n=0;n<8;++n)clients.emplace_back([&,n] {
                for(unsigned j=0;j<4;++j)if(query_udp("parallel"+std::to_string(n)+"-"+std::to_string(j)+".reclamation.example",listen))++successes;
            });
            for(auto &thread:clients)thread.join();ASSERT_EQ(successes,32U);
        }
        auto observed=wait_quiescent(before,before+32,batch);
        auto &snapshot=observed.client;
        ASSERT_TRUE(same&&valid);EXPECT_TRUE(quic_batch_quiescent(snapshot,before,before+32));
        EXPECT_TRUE(observed.peer_valid&&quic_cohort_retention_valid(observed.peer,before,before+32))<<batch;
        EXPECT_EQ(peer.connections,1U);EXPECT_FALSE(peer.failed);
        EXPECT_GE(peer.dropped_ack_datagrams,batch+1)<<"real ACK-bearing datagram loss must execute";
        before=snapshot.next_local_bidi_ordinal;
    }
    // Real stream reset and local deadline cancellation must preserve siblings.
    // Let deliberately failed operations settle and honor their existing retry
    // cooldown; a new 600ms request cannot outwait a legitimate 1000ms block.
    ASSERT_TRUE(wait_endpoint_ready("before-reset"));
    EXPECT_FALSE(query_udp("reset.reclamation.example",listen));
    EXPECT_GT(peer.reset_requests,0U);ASSERT_TRUE(wait_endpoint_ready("after-reset"));
    EXPECT_FALSE(query_udp("timeout.reclamation.example",listen));
    EXPECT_GT(peer.held_requests,0U);ASSERT_TRUE(wait_endpoint_ready("after-timeout"));
    openssl_quic_stream_snapshot canceled{};capture(canceled);ASSERT_TRUE(same&&valid);
    before=canceled.next_local_bidi_ordinal;
    ASSERT_TRUE(query_udp("sibling.reclamation.example",listen));
    auto observed=wait_quiescent(before,before+1,6);
    ASSERT_TRUE(same&&valid);EXPECT_TRUE(quic_batch_quiescent(observed.client,before,before+1));
    EXPECT_TRUE(observed.peer_valid&&quic_cohort_retention_valid(observed.peer,before,before+1));
    EXPECT_EQ(peer.connections,1U);EXPECT_FALSE(peer.failed);
    // Connection shutdown/reconnect is a separate phase, never the reason that
    // the preceding six same-connection cohorts pass their retention checks.
    peer.RequestClose();auto until=std::chrono::steady_clock::now()+std::chrono::seconds(6);
    bool closed=false;
    do {
        pthread_mutex_lock(&endpoint->lock);closed=endpoint->ssl!=connection;pthread_mutex_unlock(&endpoint->lock);
        if(closed&&peer.closed_connections==1)break;
        poll(nullptr,0,10);
    }while(std::chrono::steady_clock::now()<until);
    ASSERT_EQ(peer.closed_connections,1U);ASSERT_TRUE(closed);
    ASSERT_TRUE(query_udp("reconnected.reclamation.example",listen));
    EXPECT_EQ(peer.connections,2U);EXPECT_FALSE(peer.failed);
}
#endif
void quic_pool_case(bool h3, bool keepalive = false, unsigned queries = 4) {
    PoolQuicPeer first, second;
    std::mutex lock; std::vector<unsigned> order;
    first.on_request = [&] { std::lock_guard<std::mutex> guard(lock); order.push_back(0); };
    second.on_request = [&] { std::lock_guard<std::mutex> guard(lock); order.push_back(1); };
    unsigned port = h3 ? 62992 : 62991, listen = h3 ? 62792 : 62791;
    ASSERT_TRUE(first.Start("127.0.0.1", port, h3)); ASSERT_TRUE(second.Start("127.0.0.2", port, h3));
    smartdns::Server resolver(smartdns::Server::CREATE_MODE_THREAD);
    std::string config = "bind 127.0.0.1:" + std::to_string(listen) + "\nserver " + (h3 ? "h3://" : "quic://") +
        "resolver.quic-pool.example:" + std::to_string(port) + (h3 ? "/dns-query" : "") +
        " -upstream-ip-pool -host-ip 127.0.0.1,127.0.0.2 -no-check-certificate" +
        (keepalive ? std::string(" -upstream-keepalive-ms 1000") : std::string()) + "\ncache-size 0\ncache-persist no\nprefetch-domain no\nserve-expired no\n"
        "dualstack-ip-selection no\nspeed-check-mode none\nresponse-mode fastest-response\n";
    ASSERT_TRUE(resolver.Start(config));
    unsigned first_warm=0, second_warm=0;
    if(h3){
        ASSERT_TRUE(query_udp("quic-warm-0.example",listen));
        auto warm_deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
        for(;;){
            dns_upstream_service_snapshot_v1 warm{};ASSERT_EQ(dns_client_get_service_snapshot_v1(&warm,1),1);
            dns_upstream_endpoint_snapshot_v1 paths[2]{};
            int n=dns_client_get_service_endpoints_v1(warm.service_id,paths,2);
            bool ready=false;for(int i=0;i<n&&i<2;i++)ready|=paths[i].state==DNS_ENDPOINT_READY;
            if(ready&&warm.connection_count==1&&first.requests&&!warm.in_flight)break;
            ASSERT_LT(std::chrono::steady_clock::now(),warm_deadline);poll(nullptr,0,25);
        }
        first_warm=first.requests;second_warm=second.requests;
        std::lock_guard<std::mutex> guard(lock);order.clear();
    }
    dns_upstream_service_snapshot_v1 baseline{};ASSERT_EQ(dns_client_get_service_snapshot_v1(&baseline,1),1);
    for (unsigned i = 0; i < queries; i++) ASSERT_TRUE(query_udp("quic-pool-" + std::to_string(i) + ".example", listen));
    dns_upstream_service_snapshot_v1 snapshot{};
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    do {
        ASSERT_EQ(dns_client_get_service_snapshot_v1(&snapshot, 1), 1);
        if (snapshot.success_count == baseline.success_count+queries && !snapshot.in_flight) break;
        poll(nullptr, 0, 5);
    } while (std::chrono::steady_clock::now() < deadline);
    fprintf(stderr,"Pool QUIC snapshot: h3=%d queries=%llu attempts=%llu successes=%llu failures=%llu skips=%llu active=%llu requests=%u/%u connections=%u/%u peer_failed=%d/%d\n",h3,
        (unsigned long long)snapshot.query_count,(unsigned long long)snapshot.attempt_count,(unsigned long long)snapshot.success_count,
        (unsigned long long)snapshot.failure_count,(unsigned long long)snapshot.skip_count,(unsigned long long)snapshot.in_flight,
        first.requests.load(),second.requests.load(),first.connections.load(),second.connections.load(),first.failed.load(),second.failed.load());
    EXPECT_TRUE(snapshot.pool_enabled); EXPECT_GE(snapshot.endpoint_count, 1U); EXPECT_LE(snapshot.endpoint_count, 2U);
    EXPECT_EQ(snapshot.connection_count, 1U);
    EXPECT_EQ(snapshot.transport, h3 ? DNS_SERVER_HTTP3 : DNS_SERVER_QUIC);
    EXPECT_EQ(snapshot.query_count, baseline.query_count+queries); EXPECT_EQ(snapshot.attempt_count, baseline.attempt_count+queries); EXPECT_EQ(snapshot.success_count, baseline.success_count+queries);
    EXPECT_EQ(snapshot.failure_count, 0U); EXPECT_EQ(snapshot.skip_count, 0U); EXPECT_EQ(snapshot.in_flight, 0U);
    EXPECT_EQ(first.requests-first_warm, queries); EXPECT_EQ(second.requests-second_warm, 0U);
    EXPECT_EQ(first.connections, 1U); EXPECT_EQ(second.connections, 0U);
    EXPECT_FALSE(first.failed); EXPECT_FALSE(second.failed);
    if(keepalive){
        dns_client_loop_diagnostics_v1 idle_before{},idle_after{};
        ASSERT_EQ(dns_client_get_loop_diagnostics_v1(&idle_before),0);
        poll(nullptr,0,2400);
        ASSERT_EQ(dns_client_get_loop_diagnostics_v1(&idle_after),0);
        EXPECT_LT(idle_after.iterations-idle_before.iterations,1000U)
            << "buffered continuation must stop after draining application data";
        dns_upstream_policy_snapshot_v1 policy{};
        ASSERT_EQ(dns_client_get_service_policy_v1(snapshot.service_id,&policy),0);
        EXPECT_GE(policy.kind_counts[DNS_DETAIL_KEEPALIVE_SENT],2U);
        EXPECT_EQ(first.requests+second.requests,queries+first_warm+second_warm);
        ASSERT_TRUE(query_udp("quic-pool-after-idle.example",listen));
        EXPECT_EQ(first.connections,1U);EXPECT_EQ(second.connections,0U);
        EXPECT_FALSE(first.failed);EXPECT_FALSE(second.failed);return;
    }
    std::lock_guard<std::mutex> guard(lock);
    ASSERT_EQ(order.size(), queries);
    for (size_t i = 1; i < order.size(); i++) EXPECT_EQ(order[i-1], order[i]);
}
} // namespace
#endif
TEST(UpstreamServiceQuic, RealDoqSingleWanReusesOneHealthyAddress) {
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC) && OPENSSL_VERSION_NUMBER >= 0x30500000L
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    ASSERT_EXIT({ quic_pool_case(false); _exit(::testing::Test::HasFailure() ? 1 : 0); }, ::testing::ExitedWithCode(0), "");
#else
    GTEST_SKIP() << "Real pool DoQ listener requires OpenSSL >= 3.5 QUIC; mandatory in quic CI profile";
#endif
}
TEST(UpstreamServiceQuic, RealH3SingleWanReusesOneHealthyAddress) {
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC) && OPENSSL_VERSION_NUMBER >= 0x30500000L
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    ASSERT_EXIT({ quic_pool_case(true); fflush(stdout); fflush(stderr); _exit(::testing::Test::HasFailure() ? 1 : 0); }, ::testing::ExitedWithCode(0), "");
#else
    GTEST_SKIP() << "Real pool H3 listener requires OpenSSL >= 3.5 QUIC; mandatory in quic CI profile";
#endif
}
TEST(UpstreamServiceQuic, ErrorOnlyDoqReadinessDoesNotSpin) {
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC) && OPENSSL_VERSION_NUMBER >= 0x30500000L
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    ASSERT_EXIT({ quic_error_ready_case(false); _exit(::testing::Test::HasFailure() ? 1 : 0); }, ::testing::ExitedWithCode(0), "");
#else
    GTEST_SKIP() << "Real QUIC listener requires OpenSSL >= 3.5 QUIC; mandatory in quic CI profile";
#endif
}
TEST(UpstreamServiceQuic, ErrorOnlyH3ReadinessDoesNotSpin) {
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC) && OPENSSL_VERSION_NUMBER >= 0x30500000L
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    ASSERT_EXIT({ quic_error_ready_case(true); _exit(::testing::Test::HasFailure() ? 1 : 0); }, ::testing::ExitedWithCode(0), "");
#else
    GTEST_SKIP() << "Real QUIC listener requires OpenSSL >= 3.5 QUIC; mandatory in quic CI profile";
#endif
}

TEST(UpstreamServiceQuic, H3IdleControlKeepaliveUsesNoDnsStreamAndPreservesConnections) {
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC) && OPENSSL_VERSION_NUMBER >= 0x30500000L
    ::testing::FLAGS_gtest_death_test_style="threadsafe";
    ASSERT_EXIT({
        quic_pool_case(true,true);
        const auto *result = ::testing::UnitTest::GetInstance()->current_test_info()->result();
        for (int i = 0; i < result->total_part_count(); i++) {
            const auto &part = result->GetTestPartResult(i);
            if (part.failed()) fprintf(stderr, "%s:%d: %s\n", part.file_name(), part.line_number(), part.summary());
        }
        fflush(stdout); fflush(stderr); _exit(::testing::Test::HasFailure()?1:0);
    },::testing::ExitedWithCode(0),"");
#else
    GTEST_SKIP()<<"Requires the mandatory QUIC CI profile";
#endif
}

TEST(UpstreamServiceQuic, H3CompletedStreamsDoNotConsumeTheLiveStreamLimit) {
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC) && OPENSSL_VERSION_NUMBER >= 0x30500000L
    ::testing::FLAGS_gtest_death_test_style="threadsafe";
    ASSERT_EXIT({
        quic_pool_case(true,false,48);
        const auto *result=::testing::UnitTest::GetInstance()->current_test_info()->result();
        for(int i=0;i<result->total_part_count();i++) {
            const auto &part=result->GetTestPartResult(i);
            if(part.failed())fprintf(stderr,"%s:%d: %s\n",part.file_name(),part.line_number(),part.summary());
        }
        fflush(stdout);fflush(stderr);_exit(::testing::Test::HasFailure()?1:0);
    },::testing::ExitedWithCode(0),"");
#else
    GTEST_SKIP() << "Real H3 listener requires OpenSSL >= 3.5 QUIC";
#endif
}

TEST(UpstreamServiceQuic, PersistentH3ReclaimsRetiredStreams) {
#ifdef SMARTDNS_TEST_PINNED_QUIC
    ::testing::FLAGS_gtest_death_test_style="threadsafe";
    ASSERT_EXIT({quic_reclamation_case(true);quic_reclamation_child_result();_exit(::testing::Test::HasFailure()?1:0);},::testing::ExitedWithCode(0),"");
#else
    GTEST_SKIP()<<"Requires exact private dependency inspection in the mandatory QUIC profile";
#endif
}
TEST(UpstreamServiceQuic, PersistentDoqReclaimsRetiredStreams) {
#ifdef SMARTDNS_TEST_PINNED_QUIC
    ::testing::FLAGS_gtest_death_test_style="threadsafe";
    ASSERT_EXIT({quic_reclamation_case(false);quic_reclamation_child_result();_exit(::testing::Test::HasFailure()?1:0);},::testing::ExitedWithCode(0),"");
#else
    GTEST_SKIP()<<"Requires exact private dependency inspection in the mandatory QUIC profile";
#endif
}
