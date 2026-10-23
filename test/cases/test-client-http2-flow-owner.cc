#include "gtest/gtest.h"
extern "C" {
#include "dns_client/client_http2.h"
#include "dns_client/client_socket.h"
#include "dns_client/conn_stream.h"
#include "dns_client/upstream_policy.h"
#include "smartdns/http2.h"
#include "smartdns/util.h"
}
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <vector>
#include <thread>
#include <memory>
#include <atomic>

namespace {
struct FlowQuery {
    dns_query_struct query{};
    dns_server_info *server;
    FlowQuery(dns_server_info *s, unsigned timeout = 2000) : server(s) {
        pthread_mutex_init(&query.lock, nullptr);
        INIT_LIST_HEAD(&query.conn_stream_list);
        atomic_set(&query.refcnt, 2);
        atomic_set(&query.dns_request_sent, 0);
        query.budget = dns_query_budget_new(1, timeout);
    }
    ~FlowQuery() {
        _dns_attempt_retire(&query, server, 0);
        _dns_client_conn_server_streams_free(server, &query);
        while (!list_empty(&query.conn_stream_list)) {
            auto *s = list_first_entry(&query.conn_stream_list, dns_conn_stream, query_list);
            list_del_init(&s->query_list); s->query = nullptr; _dns_client_conn_stream_put(s);
        }
        _dns_attempt_free_all(&query); dns_query_budget_put(query.budget);
        pthread_mutex_destroy(&query.lock);
    }
    void DetachLikeQueryTeardown() {
        dns_query_budget_cancel(query.budget);
        _dns_attempt_retire(&query, server, 0);
        while (!list_empty(&query.conn_stream_list)) {
            auto *s = list_first_entry(&query.conn_stream_list, dns_conn_stream, query_list);
            list_del_init(&s->query_list); s->query = nullptr; _dns_client_conn_stream_put(s);
        }
    }
};
class ClientH2FlowOwner : public ::testing::Test {
protected:
    dns_server_info server{};
    SSL_CTX *client_ctx = nullptr, *peer_ctx = nullptr;
    SSL *peer = nullptr;
    http2_ctx *peer_h2 = nullptr;
    int pair_fd = -1, epoll_fd = -1, saved_epoll = -1;
    bool ready = false;
    std::vector<unsigned char> observed;
    static int Read(void *p, uint8_t *data, int size) {
        auto *self = static_cast<ClientH2FlowOwner *>(p);
        int n = SSL_read(self->peer, data, size);
        if (n > 0) { self->observed.insert(self->observed.end(), data, data+n); return n; }
        int err = SSL_get_error(self->peer, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) { errno = EAGAIN; return -1; }
        return 0;
    }
    static int Write(void *p, const uint8_t *data, int size) {
        auto *self = static_cast<ClientH2FlowOwner *>(p);
        int n = SSL_write(self->peer, data, size);
        if (n > 0) return n;
        int err = SSL_get_error(self->peer, n);
        errno = err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ? EAGAIN : EIO;
        return -1;
    }
    int PumpClient() {
        epoll_event event{}; event.events = EPOLLIN | EPOLLOUT;
        return _dns_client_process_http2(&server, &event, get_tick_count());
    }
    void PumpPeer() {
        http2_ctx_handshake(peer_h2);
        http2_poll_item items[16]{}; int count = 0;
        http2_ctx_poll_readable(peer_h2, items, 16, &count);
        for (int i = 0; i < count; i++) if (items[i].stream) http2_stream_put(items[i].stream);
    }
    void Pump(unsigned rounds = 10) {
        for (unsigned i = 0; i < rounds; i++) { PumpPeer(); EXPECT_GE(PumpClient(), 0); }
        PumpPeer();
    }
    bool Frame(unsigned type, unsigned id, const std::vector<unsigned char> &payload, unsigned flags = 0) {
        std::vector<unsigned char> data(9 + payload.size());
        data[0] = payload.size() >> 16; data[1] = payload.size() >> 8; data[2] = payload.size();
        data[3] = type; data[4] = flags;
        data[5] = id >> 24; data[6] = id >> 16; data[7] = id >> 8; data[8] = id;
        memcpy(data.data()+9, payload.data(), payload.size());
        return SSL_write(peer, data.data(), data.size()) == static_cast<int>(data.size());
    }
    unsigned DataBytes(unsigned stream_id, bool *ended = nullptr) {
        unsigned result = 0;
        // The captured plaintext begins with the client connection preface.
        size_t offset = 24;
        while (offset + 9 <= observed.size()) {
            unsigned n = (observed[offset] << 16) | (observed[offset+1] << 8) | observed[offset+2];
            if (offset + 9 + n > observed.size()) break;
            unsigned id = ((observed[offset+5] & 0x7f) << 24) | (observed[offset+6] << 16) |
                          (observed[offset+7] << 8) | observed[offset+8];
            if (observed[offset+3] == 0 && id == stream_id) {
                result += n; if (ended && (observed[offset+4] & 1)) *ended = true;
            }
            offset += 9+n;
        }
        return result;
    }
    int Queue(FlowQuery &q) {
        unsigned char dns[12] = {};
        EXPECT_EQ(_dns_attempt_begin(&q.query, &server), DNS_ADMIT_OK);
        EXPECT_EQ(_dns_client_send_http2(&server, &q.query, dns, sizeof(dns)), 0);
        Pump();
        auto *owner = server.http2_write_owner;
        if (!owner || owner->query != &q.query || !owner->http2_stream) return -1;
        EXPECT_TRUE(http2_stream_has_pending_send(owner->http2_stream));
        EXPECT_FALSE(http2_ctx_want_write(server.http2_ctx));
        return http2_stream_get_id(owner->http2_stream);
    }
    virtual size_t BioCapacity() const { return 65536; }
    void SetUp() override {
        pthread_mutexattr_t attr; pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&server.lock, &attr); pthread_mutexattr_destroy(&attr);
        ready = true; INIT_LIST_HEAD(&server.conn_stream_list); atomic_set(&server.refcnt, 1);
        server.type = DNS_SERVER_HTTPS; server.status = DNS_SERVER_STATUS_CONNECTED;
        strcpy(server.alpn_selected, "h2"); strcpy(server.flags.https.path, "/dns-query");
        strcpy(server.flags.https.httphost, "localhost");
        ASSERT_EQ(_dns_policy_attach(&server), 0);
        ASSERT_EQ(generate_cert_key("/tmp/smartdns-h2-flow.key", "/tmp/smartdns-h2-flow.pem", nullptr,
                                    "DNS:localhost", 1), 0);
        client_ctx = SSL_CTX_new(TLS_client_method()); peer_ctx = SSL_CTX_new(TLS_server_method());
        ASSERT_NE(client_ctx, nullptr); ASSERT_NE(peer_ctx, nullptr);
        // No resumption is exercised here. On a 256-byte BIO, TLS 1.3 tickets
        // can otherwise keep the server handshake blocked after the client has
        // finished and stopped consuming post-handshake records.
        ASSERT_EQ(SSL_CTX_set_num_tickets(peer_ctx, 0), 1);
        ASSERT_EQ(SSL_CTX_use_certificate_file(peer_ctx, "/tmp/smartdns-h2-flow.pem", SSL_FILETYPE_PEM), 1);
        ASSERT_EQ(SSL_CTX_use_PrivateKey_file(peer_ctx, "/tmp/smartdns-h2-flow.key", SSL_FILETYPE_PEM), 1);
        SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, nullptr); // local memory BIO fixture only
        server.ssl = SSL_new(client_ctx); peer = SSL_new(peer_ctx);
        ASSERT_NE(server.ssl, nullptr); ASSERT_NE(peer, nullptr);
        BIO *left = nullptr, *right = nullptr;
        ASSERT_EQ(BIO_new_bio_pair(&left, BioCapacity(), &right, BioCapacity()), 1);
        SSL_set_bio(server.ssl, left, left); SSL_set_bio(peer, right, right);
        SSL_set_connect_state(server.ssl); SSL_set_accept_state(peer);
        SSL_set_mode(server.ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
        SSL_set_mode(peer, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
        for (int i = 0; i < 10000 && (!SSL_is_init_finished(server.ssl) || !SSL_is_init_finished(peer)); i++) {
            SSL_do_handshake(server.ssl); SSL_do_handshake(peer);
        }
        ASSERT_TRUE(SSL_is_init_finished(server.ssl)); ASSERT_TRUE(SSL_is_init_finished(peer));
        int sockets[2]; ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets), 0);
        server.fd = sockets[0]; pair_fd = sockets[1];
        saved_epoll = ::client.epoll_fd; epoll_fd = epoll_create1(EPOLL_CLOEXEC); ASSERT_GE(epoll_fd, 0);
        ::client.epoll_fd = epoll_fd;
        epoll_event event{}; event.events = EPOLLIN | EPOLLOUT; event.data.ptr = &server;
        ASSERT_EQ(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server.fd, &event), 0);
        peer_h2 = http2_ctx_server_new("fixture", Read, Write, this, nullptr); ASSERT_NE(peer_h2, nullptr);
        Pump();
        // Advertise SETTINGS_INITIAL_WINDOW_SIZE=0 before creating requests.
        ASSERT_TRUE(Frame(4, 0, {0,4,0,0,0,0})); Pump();
    }
    void TearDown() override {
        if (ready) _dns_client_close_socket(&server);
        if (peer_h2) http2_ctx_close(peer_h2);
        SSL_free(peer); SSL_CTX_free(client_ctx); SSL_CTX_free(peer_ctx);
        if (pair_fd >= 0) close(pair_fd);
        if (epoll_fd >= 0) { ::client.epoll_fd = saved_epoll; close(epoll_fd); }
        if (ready) { _dns_policy_detach(&server); pthread_mutex_destroy(&server.lock); }
        unlink("/tmp/smartdns-h2-flow.key"); unlink("/tmp/smartdns-h2-flow.pem");
    }
};
}

TEST_F(ClientH2FlowOwner, WindowUpdateAfterCancelDiscardsBodyAndPreservesLiveSibling) {
    FlowQuery canceled(&server), live(&server);
    int first = Queue(canceled); ASSERT_GT(first, 0); EXPECT_EQ(DataBytes(first), 0u);
    unsigned char dns[12] = {};
    ASSERT_EQ(_dns_attempt_begin(&live.query, &server), DNS_ADMIT_OK);
    ASSERT_EQ(_dns_client_send_http2(&server, &live.query, dns, sizeof(dns)), 0);
    EXPECT_FALSE(dns_query_budget_exhausted(live.query.budget)); // waiting behind the exact first owner
    dns_query_budget_cancel(canceled.query.budget);
    ASSERT_TRUE(Frame(8, first, {0,0,0xff,0xff})); // arrives before periodic query teardown
    Pump();
    EXPECT_EQ(DataBytes(first), 0u); EXPECT_EQ(atomic_read(&canceled.query.dns_request_sent), 0);
    ASSERT_NE(server.ssl, nullptr);
    ASSERT_NE(server.http2_write_owner, nullptr);
    ASSERT_EQ(server.http2_write_owner->query, &live.query);
    int second = http2_stream_get_id(server.http2_write_owner->http2_stream);
    ASSERT_GT(second, first);
    ASSERT_TRUE(Frame(8, second, {0,0,0xff,0xff})); Pump();
    bool ended = false;
    EXPECT_EQ(DataBytes(second, &ended), 12u); EXPECT_TRUE(ended);
    EXPECT_EQ(DataBytes(first), 0u);
    EXPECT_EQ(server.http2_write_owner, nullptr);
    EXPECT_EQ(atomic_read(&live.query.dns_request_sent), 1);
}
TEST_F(ClientH2FlowOwner, WindowUpdateAfterQueryPruneCannotResurrectBody) {
    FlowQuery canceled(&server);
    int first = Queue(canceled); ASSERT_GT(first, 0);
    canceled.DetachLikeQueryTeardown();
    EXPECT_EQ(_dns_client_conn_prune(&server), 0);
    ASSERT_TRUE(Frame(8, first, {0,0,0xff,0xff})); Pump();
    EXPECT_EQ(DataBytes(first), 0u); EXPECT_EQ(server.http2_write_owner, nullptr);
    EXPECT_TRUE(list_empty(&server.conn_stream_list));
}
TEST_F(ClientH2FlowOwner, WindowUpdateAfterDeadlineCannotEmitExpiredBody) {
    FlowQuery expired(&server, 100);
    int first = Queue(expired); ASSERT_GT(first, 0);
    usleep(120000); // authored boundary fixture, not executed during source work
    ASSERT_EQ(dns_query_budget_remaining_ms(expired.query.budget), 0u);
    ASSERT_TRUE(Frame(8, first, {0,0,0xff,0xff})); Pump();
    EXPECT_EQ(DataBytes(first), 0u); EXPECT_EQ(atomic_read(&expired.query.dns_request_sent), 0);
}

TEST_F(ClientH2FlowOwner, PeerCloseWithoutOrphanMustReachEOF) {
    SSL_shutdown(peer);
    EXPECT_LT(PumpClient(), 0);
}

TEST_F(ClientH2FlowOwner, LateCancelledResponseAndPeerCloseMustReachEOF) {
    FlowQuery canceled(&server);
    int first = Queue(canceled); ASSERT_GT(first, 0);
    ASSERT_TRUE(Frame(8, first, {0,0,0xff,0xff})); Pump();
    ASSERT_EQ(DataBytes(first), 12u);
    canceled.DetachLikeQueryTeardown();
    ASSERT_EQ(_dns_client_conn_prune(&server), 0);
    ASSERT_TRUE(list_empty(&server.conn_stream_list));
    // A response already in flight may legally arrive after our CANCEL.
    ASSERT_TRUE(Frame(1, first, {0x88}, 4)); // :status 200, END_HEADERS
    ASSERT_TRUE(Frame(0, first, std::vector<unsigned char>(12), 1)); // END_STREAM
    SSL_shutdown(peer);
    int ret = 0;
    for (unsigned i = 0; i < 4 && ret == 0; ++i) ret = PumpClient();
    EXPECT_LT(ret, 0) << "orphan readiness must not hide TLS EOF indefinitely";
}

TEST_F(ClientH2FlowOwner, LateCancelledResponseDoesNotRetainReadinessOrBreakSibling) {
    FlowQuery canceled(&server), live(&server);
    int first = Queue(canceled); ASSERT_GT(first, 0);
    ASSERT_TRUE(Frame(8, first, {0,0,0xff,0xff})); Pump();
    ASSERT_EQ(DataBytes(first), 12u);
    canceled.DetachLikeQueryTeardown();
    ASSERT_EQ(_dns_client_conn_prune(&server), 0);
    int second = Queue(live); ASSERT_GT(second, first);
    ASSERT_TRUE(Frame(1, first, {0x88}, 4));
    ASSERT_TRUE(Frame(0, first, std::vector<unsigned char>(12), 1));
    ASSERT_GE(PumpClient(), 0);
    http2_poll_item items[16]{}; int count = 0;
    ASSERT_GE(http2_ctx_poll_readable(server.http2_ctx, items, 16, &count), 0);
    EXPECT_EQ(count, 0) << "cancelled response has no consumer and must not stay ready";
    for (int i = 0; i < count; i++) if (items[i].stream) http2_stream_put(items[i].stream);
    ASSERT_NE(server.http2_write_owner, nullptr);
    EXPECT_EQ(server.http2_write_owner->query, &live.query);
    ASSERT_TRUE(Frame(8, second, {0,0,0xff,0xff})); Pump();
    EXPECT_EQ(DataBytes(second), 12u);
}

namespace {
class ClientH2PartialOwner : public ClientH2FlowOwner {
protected:
    size_t BioCapacity() const override { return 256; }
};
}
TEST_F(ClientH2PartialOwner, CancelWithEncodedPartialHeadersRequiresConnectionClose) {
    FlowQuery canceled(&server);
    memset(server.flags.https.path, '~', sizeof(server.flags.https.path)-1);
    server.flags.https.path[0] = '/';
    server.flags.https.path[sizeof(server.flags.https.path)-1] = 0;
    unsigned char dns[12] = {};
    ASSERT_EQ(_dns_attempt_begin(&canceled.query, &server), DNS_ADMIT_OK);
    ASSERT_EQ(_dns_client_send_http2(&server, &canceled.query, dns, sizeof(dns)), 0);
    ASSERT_EQ(_dns_client_http2_process_write(&server), 0); // consumer starts encoding
    ASSERT_TRUE(http2_ctx_want_write(server.http2_ctx));
    ASSERT_NE(server.http2_write_owner, nullptr);
    dns_query_budget_cancel(canceled.query.budget);
    EXPECT_LT(_dns_client_http2_process_write(&server), 0);
    _dns_client_close_socket(&server);
    EXPECT_EQ(server.ssl, nullptr);
    EXPECT_EQ(server.http2_write_owner, nullptr);
    EXPECT_EQ(atomic_read(&canceled.query.dns_request_sent), 0);
    // A partially encoded frame is not removed and followed by another request;
    // the transport is retired instead, with its attempt charged exactly once.
    EXPECT_TRUE(dns_query_budget_exhausted(canceled.query.budget));
}

TEST_F(ClientH2FlowOwner, ConcurrentSubmittersOnlyPublishUntilConsumerPumps) {
    constexpr unsigned count = 16;
    std::vector<std::unique_ptr<FlowQuery>> queries;
    for (unsigned i = 0; i < count; ++i) queries.emplace_back(new FlowQuery(&server));
    std::atomic<unsigned> queued{0};
    std::vector<std::thread> submitters;
    for (auto &query : queries) {
        FlowQuery *q = query.get();
        submitters.emplace_back([&, q] {
            unsigned char dns[12] = {};
            if (_dns_attempt_begin(&q->query, &server) == DNS_ADMIT_OK &&
                _dns_client_send_http2(&server, &q->query, dns, sizeof(dns)) == 0) ++queued;
        });
    }
    for (auto &thread : submitters) thread.join();
    ASSERT_EQ(queued.load(), count);
    EXPECT_EQ(server.http2_write_owner, nullptr);
    epoll_event wake{};
    ASSERT_EQ(epoll_wait(epoll_fd, &wake, 1, 0), 1);
    EXPECT_TRUE(wake.events & EPOLLOUT); // submission wakes the sole consumer
    for (auto &query : queries) {
        ASSERT_FALSE(list_empty(&query->query.conn_stream_list));
        auto *stream = list_first_entry(&query->query.conn_stream_list, dns_conn_stream, query_list);
        EXPECT_EQ(stream->http2_stream, nullptr);
        EXPECT_EQ(stream->send_buff.len, 12);
        EXPECT_FALSE(dns_query_budget_exhausted(query->query.budget));
    }
    // Restore the peer window, then let the sole consumer encode every request.
    ASSERT_TRUE(Frame(4, 0, {0,4,0,0,0xff,0xff})); Pump(40);
    for (auto &query : queries) {
        auto *stream = list_first_entry(&query->query.conn_stream_list, dns_conn_stream, query_list);
        ASSERT_NE(stream->http2_stream, nullptr);
        bool ended = false;
        EXPECT_EQ(DataBytes(http2_stream_get_id(stream->http2_stream), &ended), 12u);
        EXPECT_TRUE(ended);
        EXPECT_TRUE(dns_query_budget_exhausted(query->query.budget));
    }
    EXPECT_EQ(server.http2_write_owner, nullptr);
}

TEST_F(ClientH2FlowOwner, CancelQueuedSubmissionBeforeConsumerDoesNotEncode) {
    FlowQuery canceled(&server), live(&server);
    unsigned char dns[12] = {};
    ASSERT_EQ(_dns_attempt_begin(&canceled.query, &server), DNS_ADMIT_OK);
    ASSERT_EQ(_dns_client_send_http2(&server, &canceled.query, dns, sizeof(dns)), 0);
    canceled.DetachLikeQueryTeardown();
    ASSERT_EQ(_dns_attempt_begin(&live.query, &server), DNS_ADMIT_OK);
    ASSERT_EQ(_dns_client_send_http2(&server, &live.query, dns, sizeof(dns)), 0);
    ASSERT_EQ(_dns_client_conn_prune(&server), 0);
    ASSERT_TRUE(Frame(4, 0, {0,4,0,0,0xff,0xff})); Pump(40);
    ASSERT_FALSE(list_empty(&live.query.conn_stream_list));
    auto *stream = list_first_entry(&live.query.conn_stream_list, dns_conn_stream, query_list);
    ASSERT_NE(stream->http2_stream, nullptr);
    EXPECT_EQ(http2_stream_get_id(stream->http2_stream), 1u); // canceled request allocated no H2 stream
    bool ended = false;
    EXPECT_EQ(DataBytes(1, &ended), 12u);
    EXPECT_TRUE(ended);
    EXPECT_EQ(atomic_read(&canceled.query.dns_request_sent), 0);
    EXPECT_EQ(server.http2_write_owner, nullptr);
}

TEST_F(ClientH2FlowOwner, FailedWakePublicationWithdrawsBothQueueReferences) {
    FlowQuery query(&server);
    unsigned char dns[12] = {};
    ASSERT_EQ(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, server.fd, nullptr), 0);
    ASSERT_EQ(_dns_attempt_begin(&query.query, &server), DNS_ADMIT_OK);
    EXPECT_LT(_dns_client_send_http2(&server, &query.query, dns, sizeof(dns)), 0);
    EXPECT_TRUE(list_empty(&server.conn_stream_list));
    EXPECT_TRUE(list_empty(&query.query.conn_stream_list));
    EXPECT_EQ(server.http2_write_owner, nullptr);
    EXPECT_FALSE(dns_query_budget_exhausted(query.query.budget));
    // The send caller retires the unsuccessful admission, exactly once.
    EXPECT_EQ(_dns_attempt_retire(&query.query, &server, 0), 1);
    EXPECT_EQ(_dns_attempt_retire(&query.query, &server, 0), 0);
}

TEST_F(ClientH2FlowOwner, PingAckUsesControlFrameWithoutDnsStreamOrRequestBudget) {
    const uint64_t cookie=0x123456789abcdef0ULL;
    auto before=observed.size();ASSERT_GE(http2_ctx_ping(server.http2_ctx,cookie),0);
    Pump(20);EXPECT_TRUE(http2_ctx_ping_acked(server.http2_ctx,cookie));
    bool found=false;
    for(size_t offset=24;offset+9<=observed.size();){
        size_t n=(observed[offset]<<16)|(observed[offset+1]<<8)|observed[offset+2];
        if(offset+9+n>observed.size())break;
        if(observed[offset+3]==6&&!(observed[offset+4]&1)){EXPECT_EQ(n,8U);EXPECT_EQ(observed[offset+8],0);found=true;}
        offset+=9+n;
    }
    EXPECT_TRUE(found);EXPECT_GT(observed.size(),before);EXPECT_TRUE(list_empty(&server.conn_stream_list));
}
TEST_F(ClientH2FlowOwner, GracefulGoawayStopsAdmissionAndDoesNotBecomeProtocolError) {
    ASSERT_TRUE(Frame(7,0,{0,0,0,0,0,0,0,0}));
    epoll_event e{};e.events=EPOLLIN|EPOLLOUT;
    for(unsigned i=0;i<10&&!http2_ctx_draining(server.http2_ctx,nullptr,nullptr);i++)_dns_client_process_http2(&server,&e,get_tick_count());
    uint32_t last=99,error=99;EXPECT_TRUE(http2_ctx_draining(server.http2_ctx,&last,&error));
    EXPECT_EQ(last,0U);EXPECT_EQ(error,0U);EXPECT_EQ(http2_stream_new(server.http2_ctx),nullptr);
}
