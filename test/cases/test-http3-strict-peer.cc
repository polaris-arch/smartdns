#include "gtest/gtest.h"
extern "C" {
#include "dns_client/client_http3_control.h"
#include "dns_client/client_quic.h"
#include "dns_client/client_http3.h"
#include "dns_client/conn_stream.h"
#include "dns_client/upstream_policy.h"
#include "smartdns/util.h"
}
#include <arpa/inet.h>
#include <chrono>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <cstring>
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC) && OPENSSL_VERSION_NUMBER >= 0x30500000L
namespace {
class StrictPeer : public ::testing::Test {
protected:
    SSL_CTX *peer_ctx = nullptr, *client_ctx = nullptr;
    SSL *listener = nullptr, *peer = nullptr, *peer_control = nullptr;
    int peer_fd = -1, client_fd = -1;
    dns_server_info client{};
    std::vector<SSL *> incoming;
    std::vector<unsigned char> observed;
    bool mutex_ready = false;
    bool handshake_confirmed = false;
    int test_epoll = -1, saved_epoll = -1;
    void SetUp() override {
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&client.lock, &attr);
        pthread_mutexattr_destroy(&attr);
        mutex_ready = true;
        INIT_LIST_HEAD(&client.conn_stream_list);
        atomic_set(&client.refcnt, 1);
        ASSERT_EQ(generate_cert_key("/tmp/smartdns-h3-strict.key", "/tmp/smartdns-h3-strict.pem", nullptr,
                                    "DNS:localhost,IP:127.0.0.1", 1), 0);
        peer_ctx = SSL_CTX_new(OSSL_QUIC_server_method());
        client_ctx = SSL_CTX_new(OSSL_QUIC_client_method());
        ASSERT_NE(peer_ctx, nullptr); ASSERT_NE(client_ctx, nullptr);
        ASSERT_EQ(SSL_CTX_use_certificate_file(peer_ctx, "/tmp/smartdns-h3-strict.pem", SSL_FILETYPE_PEM), 1);
        ASSERT_EQ(SSL_CTX_use_PrivateKey_file(peer_ctx, "/tmp/smartdns-h3-strict.key", SSL_FILETYPE_PEM), 1);
        SSL_CTX_set_alpn_select_cb(peer_ctx, [](SSL *, const unsigned char **out, unsigned char *len,
                                             const unsigned char *in, unsigned int n, void *) {
            static const unsigned char protocols[] = {2,'h','3'};
            return SSL_select_next_proto(const_cast<unsigned char **>(out), len, protocols, sizeof(protocols), in, n)
                == OPENSSL_NPN_NEGOTIATED ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_ALERT_FATAL;
        }, nullptr);
        SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, nullptr); // loopback fixture certificate only
        SSL_CTX_set_msg_callback(client_ctx, [](int writing, int version, int type,
                                                const void *data, size_t len, SSL *ssl, void *arg) {
            auto *fixture = static_cast<StrictPeer *>(arg);
            // The receive callback follows successful processing of this QUIC
            // frame, unlike SSL_is_init_finished (TLS completion only).
            if (!writing && version == OSSL_QUIC1_VERSION && type == SSL3_RT_QUIC_FRAME_FULL &&
                ssl == fixture->client.ssl && len == 1 &&
                *static_cast<const unsigned char *>(data) == 0x1e)
                fixture->handshake_confirmed = true;
        });
        SSL_CTX_set_msg_callback_arg(client_ctx, this);
        peer_fd = socket(AF_INET, SOCK_DGRAM, 0);
        client_fd = socket(AF_INET, SOCK_DGRAM, 0);
        ASSERT_GE(peer_fd, 0); ASSERT_GE(client_fd, 0);
        sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ASSERT_EQ(bind(peer_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)), 0);
        socklen_t addr_len = sizeof(addr);
        ASSERT_EQ(getsockname(peer_fd, reinterpret_cast<sockaddr *>(&addr), &addr_len), 0);
        fcntl(peer_fd, F_SETFL, O_NONBLOCK); fcntl(client_fd, F_SETFL, O_NONBLOCK);
        listener = SSL_new_listener(peer_ctx, 0);
        ASSERT_NE(listener, nullptr);
        ASSERT_EQ(SSL_set_fd(listener, peer_fd), 1);
        ASSERT_EQ(SSL_set_blocking_mode(listener, 0), 1);
        ASSERT_EQ(SSL_listen(listener), 1);
        client.ssl = SSL_new(client_ctx); ASSERT_NE(client.ssl, nullptr);
        ASSERT_EQ(SSL_set_fd(client.ssl, client_fd), 1);
        ASSERT_EQ(SSL_set_blocking_mode(client.ssl, 0), 1);
        ASSERT_EQ(SSL_set_default_stream_mode(client.ssl, SSL_DEFAULT_STREAM_MODE_NONE), 1);
        const unsigned char alpn[] = {2,'h','3'};
        ASSERT_EQ(SSL_set_alpn_protos(client.ssl, alpn, sizeof(alpn)), 0);
        BIO_ADDR *address = BIO_ADDR_new(); ASSERT_NE(address, nullptr);
        ASSERT_EQ(BIO_ADDR_rawmake(address, AF_INET, &addr.sin_addr, sizeof(addr.sin_addr), addr.sin_port), 1);
        ASSERT_EQ(SSL_set1_initial_peer_addr(client.ssl, address), 1);
        BIO_ADDR_free(address);
        client.type = DNS_SERVER_HTTP3;
        auto until = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        bool connected = false;
        while (std::chrono::steady_clock::now() < until) {
            if (SSL_connect(client.ssl) == 1) connected = true;
            SSL_handle_events(listener);
            if (!peer) peer = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
            if (peer) {
                SSL_set_blocking_mode(peer, 0);
                SSL_set_default_stream_mode(peer, SSL_DEFAULT_STREAM_MODE_NONE);
                SSL_do_handshake(peer); SSL_handle_events(peer);
            }
            if (connected && peer && SSL_is_init_finished(peer)) break;
            usleep(1000);
        }
        ASSERT_TRUE(connected); ASSERT_NE(peer, nullptr); ASSERT_TRUE(SSL_is_init_finished(peer));
        client.status = DNS_SERVER_STATUS_CONNECTED;
        client.fd = client_fd;
        saved_epoll = ::client.epoll_fd;
        test_epoll = epoll_create1(EPOLL_CLOEXEC);
        ASSERT_GE(test_epoll, 0);
        epoll_event event{}; event.events = EPOLLIN | EPOLLOUT; event.data.ptr = &client;
        ASSERT_EQ(epoll_ctl(test_epoll, EPOLL_CTL_ADD, client_fd, &event), 0);
        ::client.epoll_fd = test_epoll;
        ASSERT_EQ(_dns_policy_attach(&client), 0);
    }
    int Pump() {
        SSL_handle_events(listener); SSL_handle_events(peer); SSL_handle_events(client.ssl);
        client.http3_control_epoch++;
        int result = _dns_http3_control_poll(&client);
        for (unsigned i = 0; i < 8; i++) {
            SSL *stream = SSL_accept_stream(peer, SSL_ACCEPT_STREAM_NO_BLOCK);
            if (!stream) break;
            incoming.push_back(stream);
        }
        for (SSL *stream : incoming) {
            unsigned char data[256]; size_t got = 0;
            if (SSL_read_ex(stream, data, sizeof(data), &got)) observed.insert(observed.end(), data, data+got);
        }
        return result;
    }
    bool WritePeer(const std::vector<unsigned char> &data, bool fragment = false) {
        if (!peer_control) peer_control = SSL_new_stream(peer, SSL_STREAM_FLAG_UNI);
        if (!peer_control) return false;
        size_t offset = 0;
        auto until = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (offset < data.size() && std::chrono::steady_clock::now() < until) {
            size_t wrote = 0, len = fragment ? 1 : data.size()-offset;
            SSL_write_ex(peer_control, data.data()+offset, len, &wrote);
            offset += wrote;
            Pump(); usleep(1000);
        }
        return offset == data.size();
    }
    void TearDown() override {
        _dns_http3_control_free(&client);
        _dns_policy_detach(&client);
        if (test_epoll >= 0) { ::client.epoll_fd = saved_epoll; close(test_epoll); }
        SSL_free(client.ssl);
        for (SSL *stream : incoming) SSL_free(stream);
        SSL_free(peer_control); SSL_free(peer); SSL_free(listener);
        SSL_CTX_free(client_ctx); SSL_CTX_free(peer_ctx);
        if (client_fd >= 0) close(client_fd);
        if (peer_fd >= 0) close(peer_fd);
        if (mutex_ready) pthread_mutex_destroy(&client.lock);
        unlink("/tmp/smartdns-h3-strict.key"); unlink("/tmp/smartdns-h3-strict.pem");
    }
};
}
TEST_F(StrictPeer, EmitsSettingsWithoutWaitingForPeerSettings) {
    for (int i = 0; i < 100 && observed.size() < 7; i++) { ASSERT_GE(Pump(), 0); usleep(1000); }
    const std::vector<unsigned char> expected = {0,4,4,1,0,7,0};
    EXPECT_EQ(observed, expected);
    EXPECT_TRUE(_dns_http3_request_allowed(&client, 0, 0));
    ASSERT_TRUE(WritePeer({0x40,0,0x40,4,0x40,0}, true));
    EXPECT_GE(Pump(), 0);
}
TEST_F(StrictPeer, GoawayStopsNewRequestsAndCriticalFinFails) {
    ASSERT_TRUE(WritePeer({0,4,0,7,1,8}, true));
    for (int i = 0; i < 30; i++) { Pump(); usleep(1000); }
    EXPECT_FALSE(_dns_http3_request_allowed(&client, 0, 0));
    EXPECT_TRUE(_dns_http3_request_allowed(&client, 4, 1));
    ASSERT_EQ(SSL_stream_conclude(peer_control, 0), 1);
    int result = 0;
    for (int i = 0; i < 100 && result >= 0; i++) { result = Pump(); usleep(1000); }
    EXPECT_LT(result, 0);
    EXPECT_EQ(_dns_http3_control_shutdown(&client), 1);
}
TEST_F(StrictPeer, IdleLocalControlStopSendingSelectsClosedCriticalStream) {
    for (int i = 0; i < 100 && observed.size() < 7; i++) { ASSERT_GE(Pump(), 0); usleep(1000); }
    ASSERT_EQ(observed.size(), 7u); ASSERT_FALSE(incoming.empty());
    // OpenSSL SSL_free on an unfinished receive stream emits STOP_SENDING.
    SSL_free(incoming.front()); incoming.erase(incoming.begin());
    int result = 0;
    for (int i = 0; i < 100 && result >= 0; i++) { result = Pump(); usleep(1000); }
    EXPECT_LT(result, 0);
    EXPECT_EQ(_dns_http3_error(&client), 0x104u);
}
namespace {
struct StrictQuery {
    dns_query_struct q{};
    dns_server_info *s;
    explicit StrictQuery(dns_server_info *server) : s(server) {
        pthread_mutex_init(&q.lock, nullptr);
        INIT_LIST_HEAD(&q.conn_stream_list);
        atomic_set(&q.refcnt, 2);
        atomic_set(&q.dns_request_sent, 0);
        q.budget = dns_query_budget_new(2, 2000);
    }
    ~StrictQuery() {
        _dns_client_conn_server_streams_free(s, &q);
        // Release any query-only references retained after stream completion.
        while (!list_empty(&q.conn_stream_list)) {
            auto *stream = list_first_entry(&q.conn_stream_list, dns_conn_stream, query_list);
            list_del_init(&stream->query_list); stream->query = nullptr;
            _dns_client_conn_stream_put(stream);
        }
        _dns_attempt_free_all(&q); dns_query_budget_put(q.budget);
        pthread_mutex_destroy(&q.lock);
    }
};
}
TEST_F(StrictPeer, ProductionQueueCancellationBeforeWriteSpendsNoSendBudget) {
    StrictQuery request(&client);
    client.status = DNS_SERVER_STATUS_CONNECTING;
    ASSERT_EQ(_dns_attempt_begin(&request.q, &client), DNS_ADMIT_OK);
    unsigned char data[] = {1,3,0,0,0xd9};
    ASSERT_EQ(_dns_client_send_quic_data(&request.q, &client, data, sizeof(data)), 0);
    EXPECT_FALSE(dns_query_budget_exhausted(request.q.budget));
    dns_query_budget_cancel(request.q.budget);
    client.status = DNS_SERVER_STATUS_CONNECTED;
    epoll_event event{}; event.events = EPOLLOUT;
    EXPECT_EQ(_dns_client_process_quic(&client, &event, get_tick_count()), 0);
    EXPECT_TRUE(list_empty(&client.conn_stream_list));
    EXPECT_EQ(atomic_read(&request.q.dns_request_sent), 0);
    EXPECT_NE(client.ssl, nullptr);
    for (int i = 0; i < 20; i++) { Pump(); usleep(1000); }
    for (SSL *stream : incoming) EXPECT_EQ(SSL_get_stream_id(stream) & 2u, 2u);
}
TEST_F(StrictPeer, AdmissionRechecksTerminalQueryAfterStreamAllocation) {
    StrictQuery request(&client);
    ASSERT_EQ(_dns_attempt_begin(&request.q, &client), DNS_ADMIT_OK);
    unsigned int generation = _dns_attempt_generation(&request.q, &client);
    ASSERT_TRUE(_dns_attempt_live(&request.q, &client, generation));
    SSL *stream = SSL_new_stream(client.ssl, 0);
    ASSERT_NE(stream, nullptr);
    // Deterministically place termination between the advisory live check and
    // the authoritative post-allocation wire admission used by the flush path.
    pthread_mutex_lock(&request.q.lock);
    request.q.terminal = 1;
    pthread_mutex_unlock(&request.q.lock);
    EXPECT_EQ(_dns_attempt_wire_begin(&request.q, &client, generation), DNS_ADMIT_DONE);
    SSL_free(stream);
    // This query-local termination leaves the shared parent budget intact.
    EXPECT_EQ(_dns_query_budget_take(request.q.budget), 0);
    EXPECT_EQ(_dns_query_budget_take(request.q.budget), 0);
    EXPECT_EQ(_dns_query_budget_take(request.q.budget), -1);
}
TEST_F(StrictPeer, ProductionQueuedGoawayRetiresRequestWithoutClosingConnection) {
    StrictQuery request(&client);
    client.status = DNS_SERVER_STATUS_CONNECTING;
    ASSERT_EQ(_dns_attempt_begin(&request.q, &client), DNS_ADMIT_OK);
    unsigned char data[] = {1,3,0,0,0xd9};
    ASSERT_EQ(_dns_client_send_quic_data(&request.q, &client, data, sizeof(data)), 0);
    client.status = DNS_SERVER_STATUS_CONNECTED;
    ASSERT_TRUE(WritePeer({0,4,0,7,1,8}, true));
    ASSERT_TRUE(_dns_http3_is_draining(&client));
    epoll_event event{}; event.events = EPOLLOUT;
    EXPECT_EQ(_dns_client_process_quic(&client, &event, get_tick_count()), 0);
    EXPECT_TRUE(list_empty(&client.conn_stream_list));
    EXPECT_EQ(atomic_read(&request.q.dns_request_sent), 0);
    EXPECT_NE(client.ssl, nullptr);
    EXPECT_EQ(client.prohibit, 0);
    EXPECT_FALSE(dns_query_budget_exhausted(request.q.budget));
}

TEST_F(StrictPeer, ProductionHttp3PayloadWithoutFinThenResetIsNotSuccess) {
    StrictQuery request(&client);
    ASSERT_EQ(_dns_attempt_begin(&request.q, &client), DNS_ADMIT_OK);
    unsigned char request_bytes[] = {1,3,0,0,0xd9};
    ASSERT_EQ(_dns_client_send_quic_data(&request.q, &client, request_bytes, sizeof(request_bytes)), 0);
    SSL *response = nullptr;
    for (int i = 0; i < 100 && !response; i++) {
        Pump(); usleep(1000);
        for (SSL *stream : incoming) if (!(SSL_get_stream_id(stream) & 2u)) response = stream;
    }
    ASSERT_NE(response, nullptr);
    const unsigned char body[] = {1,3,0,0,0xd9,0,12,0,0,0x81,0x80,0,0,0,0,0,0,0,0};
    size_t written = 0;
    ASSERT_EQ(SSL_write_ex(response, body, sizeof(body), &written), 1);
    ASSERT_EQ(written, sizeof(body));
    epoll_event event{}; event.events = EPOLLIN;
    for (int i = 0; i < 20; i++) { Pump(); _dns_client_process_quic(&client, &event, get_tick_count()); usleep(1000); }
    EXPECT_EQ(atomic_read(&request.q.dns_request_sent), 1);
    SSL_STREAM_RESET_ARGS reset{}; reset.quic_error_code = 0x10c;
    ASSERT_EQ(SSL_stream_reset(response, &reset, sizeof(reset)), 1);
    for (int i = 0; i < 100 && atomic_read(&request.q.dns_request_sent); i++) {
        Pump(); _dns_client_process_quic(&client, &event, get_tick_count()); usleep(1000);
    }
    EXPECT_EQ(atomic_read(&request.q.dns_request_sent), 0);
    EXPECT_EQ(request.q.has_result, 0);
}
TEST_F(StrictPeer, ProductionDoqFramingDoesNotTreatResetAsFin) {
    // Exercise the production DoQ framing/read path over the established fixture QUIC connection.
    // This is not an ALPN/provider interoperability assertion.
    client.type = DNS_SERVER_QUIC;
    StrictQuery request(&client);
    ASSERT_EQ(_dns_attempt_begin(&request.q, &client), DNS_ADMIT_OK);
    unsigned char framed[] = {0,12,0,0,0x81,0x80,0,0,0,0,0,0,0,0};
    ASSERT_EQ(_dns_client_send_quic_data(&request.q, &client, framed, sizeof(framed)), 0);
    SSL *response = nullptr;
    for (int i = 0; i < 100 && !response; i++) {
        Pump(); usleep(1000);
        for (SSL *stream : incoming) if (!(SSL_get_stream_id(stream) & 2u)) response = stream;
    }
    ASSERT_NE(response, nullptr);
    size_t written = 0;
    ASSERT_EQ(SSL_write_ex(response, framed, sizeof(framed), &written), 1);
    ASSERT_EQ(written, sizeof(framed));
    epoll_event event{}; event.events = EPOLLIN;
    for (int i = 0; i < 20; i++) { Pump(); _dns_client_process_quic(&client, &event, get_tick_count()); usleep(1000); }
    EXPECT_EQ(atomic_read(&request.q.dns_request_sent), 1);
    SSL_STREAM_RESET_ARGS reset{}; reset.quic_error_code = 2;
    ASSERT_EQ(SSL_stream_reset(response, &reset, sizeof(reset)), 1);
    for (int i = 0; i < 100 && atomic_read(&request.q.dns_request_sent); i++) {
        Pump(); _dns_client_process_quic(&client, &event, get_tick_count()); usleep(1000);
    }
    EXPECT_EQ(atomic_read(&request.q.dns_request_sent), 0);
    EXPECT_EQ(request.q.has_result, 0);
}

TEST_F(StrictPeer, RequestSettingsErrorReachesPeerAsApplicationConnectionClose) {
    // OpenSSL 3.5 selects the lowest still-provisioned encryption level for
    // close. Wait for HANDSHAKE_DONE to discard client Handshake keys before
    // testing an application close; the server already discarded those keys.
    for (int i = 0; i < 100 && !handshake_confirmed; i++) {
        ASSERT_EQ(SSL_handle_events(listener), 1);
        ASSERT_EQ(SSL_handle_events(peer), 1);
        ASSERT_EQ(SSL_handle_events(client.ssl), 1);
        usleep(1000);
    }
    ASSERT_TRUE(handshake_confirmed) << "client did not process peer HANDSHAKE_DONE";
    dns_conn_stream response{};
    unsigned char malformed[] = {4,0};
    response.recv_buff.data = malformed; response.recv_buff.len = sizeof(malformed);
    client.process_depth = 1;
    ASSERT_EQ(_dns_client_process_recv_http3(&client, &response), -1);
    ASSERT_EQ(_dns_http3_error(&client), 0x105u);
    ASSERT_EQ(client.close_deferred, 1);
    ASSERT_EQ(_dns_http3_control_shutdown(&client), 1);
    SSL_CONN_CLOSE_INFO local{};
    ASSERT_EQ(SSL_get_conn_close_info(client.ssl, &local, sizeof(local)), 1);
    EXPECT_EQ(local.error_code, 0x105u);
    EXPECT_EQ(local.flags & (SSL_CONN_CLOSE_FLAG_LOCAL | SSL_CONN_CLOSE_FLAG_TRANSPORT),
              static_cast<uint32_t>(SSL_CONN_CLOSE_FLAG_LOCAL));
    SSL_CONN_CLOSE_INFO info{};
    int known = 0;
    for (int i = 0; i < 100 && !known; i++) {
        ASSERT_EQ(SSL_handle_events(client.ssl), 1);
        ASSERT_EQ(SSL_handle_events(listener), 1);
        ASSERT_EQ(SSL_handle_events(peer), 1);
        known = SSL_get_conn_close_info(peer, &info, sizeof(info));
        usleep(1000);
    }
    ASSERT_EQ(known, 1);
    EXPECT_EQ(info.error_code, 0x105u);
    EXPECT_EQ(info.flags & (SSL_CONN_CLOSE_FLAG_LOCAL | SSL_CONN_CLOSE_FLAG_TRANSPORT), 0u);
    client.process_depth = 0; client.close_deferred = 0;
}

#else
TEST(StrictPeer, RequiresOpenSSL35QuicServer) { GTEST_SKIP() << "OpenSSL 3.5 QUIC server support required"; }
#endif
