#include "gtest/gtest.h"
extern "C" {
#include "dns_client/upstream_policy.h"
#include "dns_client/query.h"
#include "smartdns/util.h"
#include "dns_client/client_tcp.h"
#include "dns_client/client_https.h"
#include "dns_client/conn_stream.h"
#include "http_parse/hpack.h"
#include "smartdns/http_parse.h"
}
#include <cstring>
#include <climits>
#include <sys/socket.h>
#include <poll.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <vector>

namespace {
struct Endpoint {
    dns_server_info server{};
    dns_query_struct query{};
    Endpoint(unsigned rate = 0, unsigned burst = 0, const char *group = "") {
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&server.lock, &attr);
        pthread_mutexattr_destroy(&attr);
        pthread_mutex_init(&query.lock, nullptr);
        INIT_LIST_HEAD(&server.conn_stream_list);
        INIT_LIST_HEAD(&query.conn_stream_list);
        atomic_set(&server.refcnt, 1);
        atomic_set(&query.dns_request_sent, 0);
        server.type = DNS_SERVER_HTTPS;
        server.flags.max_query_rate = rate;
        server.flags.query_burst = burst;
        strncpy(server.flags.quota_group, group, sizeof(server.flags.quota_group)-1);
        EXPECT_EQ(_dns_policy_attach(&server), 0);
    }
    ~Endpoint() {
        _dns_attempt_free_all(&query);
        dns_query_budget_put(query.budget);
        _dns_policy_detach(&server);
        pthread_mutex_destroy(&server.lock);
        pthread_mutex_destroy(&query.lock);
    }
    int Begin() { return _dns_attempt_begin(&query, &server); }
    int Wire() { return _dns_attempt_wire_begin(&query, &server, _dns_attempt_generation(&query, &server)); }
    void Progress() { _dns_attempt_mark_sent(&query, &server, _dns_attempt_generation(&query, &server)); }
    int Retire() { return _dns_attempt_retire(&query, &server, _dns_attempt_generation(&query, &server)); }
};
int SaveHeader(void *p, const char *, const char *value) {
    *static_cast<std::string *>(p) = value; return 0;
}
}
TEST(UpstreamPolicy, BufferedAdmissionDoesNotSpendParentSendBudget) {
    Endpoint e;
    e.query.budget = dns_query_budget_new(1, 1000);
    EXPECT_EQ(e.Begin(), DNS_ADMIT_OK);
    EXPECT_FALSE(dns_query_budget_exhausted(e.query.budget));
    EXPECT_EQ(e.Wire(), DNS_ADMIT_OK);
    EXPECT_TRUE(dns_query_budget_exhausted(e.query.budget));
    e.Progress();
    EXPECT_EQ(e.Wire(), DNS_ADMIT_OK); // partial-write continuation
    EXPECT_EQ(e.Retire(), 1);
    EXPECT_EQ(e.Retire(), 0);
    EXPECT_EQ(atomic_read(&e.query.dns_request_sent), 0);
    EXPECT_EQ(e.Begin(), DNS_ADMIT_DONE);
}
TEST(UpstreamPolicy, ZeroRateIsDisabledAndPerDestinationAttemptsAreBounded) {
    Endpoint e;
    for (int i = 0; i < DNS_QUERY_RETRY; i++) {
        ASSERT_EQ(e.Begin(), DNS_ADMIT_OK);
        ASSERT_EQ(e.Wire(), DNS_ADMIT_OK);
        ASSERT_EQ(e.Retire(), 1);
    }
    EXPECT_EQ(e.Begin(), DNS_ADMIT_DONE);
}
TEST(UpstreamPolicy, DatagramRetryCapMatchesOrdinaryRetryPolicy) {
    Endpoint e;
    e.server.type = DNS_SERVER_UDP;
    // Extra parent capacity cannot bypass the per-destination cap.
    e.query.budget = dns_query_budget_new(DNS_QUERY_RETRY + 1, 10000);
    for (int i = 0; i < DNS_QUERY_RETRY; ++i) {
        ASSERT_EQ(e.Begin(), DNS_ADMIT_OK);
        EXPECT_EQ(atomic_read(&e.query.dns_request_sent), 1);
        EXPECT_EQ(e.Begin(), i + 1 == DNS_QUERY_RETRY ? DNS_ADMIT_DONE : DNS_ADMIT_WAIT); // no duplicate active attempt
        ASSERT_EQ(e.Retire(), 1);
        EXPECT_EQ(e.Retire(), 0);
    }
    EXPECT_FALSE(dns_query_budget_exhausted(e.query.budget));
    EXPECT_EQ(e.Begin(), DNS_ADMIT_DONE);
    EXPECT_EQ(atomic_read(&e.query.dns_request_sent), 0);
}
TEST(UpstreamPolicy, ExplicitSharedBudgetStillBoundsIndependentChildren) {
    Endpoint first, second;
    first.query.budget = dns_query_budget_new(2, 10000);
    second.query.budget = first.query.budget;
    dns_query_budget_get(second.query.budget);
    ASSERT_EQ(first.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(second.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(first.Wire(), DNS_ADMIT_OK);
    first.Progress();
    ASSERT_EQ(second.Wire(), DNS_ADMIT_OK);
    second.Progress();
    EXPECT_TRUE(dns_query_budget_exhausted(first.query.budget));
    // Already reserved partial writes may finish, but no new child/retry starts.
    EXPECT_EQ(first.Wire(), DNS_ADMIT_OK);
    EXPECT_EQ(second.Wire(), DNS_ADMIT_OK);
    ASSERT_EQ(first.Retire(), 1);
    ASSERT_EQ(second.Retire(), 1);
    EXPECT_EQ(first.Begin(), DNS_ADMIT_DONE);
    EXPECT_EQ(second.Begin(), DNS_ADMIT_DONE);
}
TEST(UpstreamPolicy, SharedRateDoesNotChargeUnrelatedEndpoint) {
    Endpoint a(1, 1, "fixture-shared"), b(1, 1, "fixture-shared"), other;
    ASSERT_EQ(a.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(b.Begin(), DNS_ADMIT_OK); // eligibility is not token spending
    ASSERT_EQ(a.Wire(), DNS_ADMIT_OK);
    EXPECT_EQ(b.Wire(), DNS_ADMIT_WAIT);
    ASSERT_EQ(other.Begin(), DNS_ADMIT_OK);
    EXPECT_EQ(other.Wire(), DNS_ADMIT_OK);
}
TEST(UpstreamPolicy, CooldownIsScopedAndDoesNotBecomeProhibition) {
  for (int status : {429, 503}) {
    Endpoint limited, healthy;
    _dns_policy_http_error(&limited.server, status, "3600");
    EXPECT_EQ(limited.Begin(), DNS_ADMIT_WAIT);
    EXPECT_EQ(limited.server.prohibit, 0);
    EXPECT_EQ(healthy.Begin(), DNS_ADMIT_OK);
    EXPECT_EQ(healthy.Wire(), DNS_ADMIT_OK);
  }
}
TEST(UpstreamPolicy, CancellationPreventsBufferedSend) {
    Endpoint e;
    e.query.budget = dns_query_budget_new(8, 1000);
    ASSERT_EQ(e.Begin(), DNS_ADMIT_OK);
    dns_query_budget_cancel(e.query.budget);
    EXPECT_EQ(e.Wire(), DNS_ADMIT_DONE);
}
TEST(UpstreamPolicy, ConflictingQuotaGroupRejected) {
    Endpoint e(10, 1, "fixture-conflict");
    dns_server_info second{};
    second.flags.max_query_rate = 11;
    second.flags.query_burst = 1;
    strcpy(second.flags.quota_group, "fixture-conflict");
    EXPECT_EQ(_dns_policy_attach(&second), -1);
}
TEST(HpackRFC7541, AppendixCEncodedAuthority) {
    const unsigned char data[] = {0x01,0x8c,0xf1,0xe3,0xc2,0xe5,0xf2,0x3a,0x6b,0xa0,0xab,0x90,0xf4,0xff};
    hpack_context ctx{}; hpack_init_context(&ctx);
    std::string result;
    EXPECT_EQ(hpack_decode_headers(&ctx, data, sizeof(data), SaveHeader, &result), 0);
    EXPECT_EQ(result, "www.example.com");
    hpack_free_context(&ctx);
}
TEST(HpackRFC7541, RejectEOSAndOverlongOrNonEOSPadding) {
    const std::vector<std::vector<unsigned char>> bad = {
        {0x01,0x84,0xff,0xff,0xff,0xff}, // EOS/overlong padding
        {0x01,0x81,0xff}, // eight padding bits
        {0x01,0x81,0x00} // decoded symbol followed by zero padding
    };
    for (const auto &data : bad) {
        hpack_context ctx{}; hpack_init_context(&ctx);
        std::string result;
        EXPECT_LT(hpack_decode_headers(&ctx, data.data(), data.size(), SaveHeader, &result), 0);
        hpack_free_context(&ctx);
    }
}
TEST(Http1OwnershipFraming, ZeroLengthDoesNotConsumeNextResponse) {
    const std::string data = "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nRetry-After: 1\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    http_head *head = http_head_init(4096, HTTP_VERSION_1_1);
    ASSERT_NE(head, nullptr);
    EXPECT_EQ(http_head_parse(head, reinterpret_cast<const unsigned char *>(data.data()), data.size()), data.find("HTTP/1.1 200"));
    EXPECT_EQ(http_head_get_data_len(head), 0);
    http_head_destroy(head);
}

TEST(HpackRFC7541, EveryPrintableOctetUsesAppendixBCode) {
    const std::vector<std::vector<unsigned char>> vectors = {
        {0x1,0x81,0x53},
        {0x1,0x82,0xfe,0x3f},
        {0x1,0x82,0xfe,0x7f},
        {0x1,0x82,0xff,0xaf},
        {0x1,0x82,0xff,0xcf},
        {0x1,0x81,0x57},
        {0x1,0x81,0xf8},
        {0x1,0x82,0xff,0x5f},
        {0x1,0x82,0xfe,0xbf},
        {0x1,0x82,0xfe,0xff},
        {0x1,0x81,0xf9},
        {0x1,0x82,0xff,0x7f},
        {0x1,0x81,0xfa},
        {0x1,0x81,0x5b},
        {0x1,0x81,0x5f},
        {0x1,0x81,0x63},
        {0x1,0x81,0x7},
        {0x1,0x81,0xf},
        {0x1,0x81,0x17},
        {0x1,0x81,0x67},
        {0x1,0x81,0x6b},
        {0x1,0x81,0x6f},
        {0x1,0x81,0x73},
        {0x1,0x81,0x77},
        {0x1,0x81,0x7b},
        {0x1,0x81,0x7f},
        {0x1,0x81,0xb9},
        {0x1,0x81,0xfb},
        {0x1,0x82,0xff,0xf9},
        {0x1,0x81,0x83},
        {0x1,0x82,0xff,0xbf},
        {0x1,0x82,0xff,0x3f},
        {0x1,0x82,0xff,0xd7},
        {0x1,0x81,0x87},
        {0x1,0x81,0xbb},
        {0x1,0x81,0xbd},
        {0x1,0x81,0xbf},
        {0x1,0x81,0xc1},
        {0x1,0x81,0xc3},
        {0x1,0x81,0xc5},
        {0x1,0x81,0xc7},
        {0x1,0x81,0xc9},
        {0x1,0x81,0xcb},
        {0x1,0x81,0xcd},
        {0x1,0x81,0xcf},
        {0x1,0x81,0xd1},
        {0x1,0x81,0xd3},
        {0x1,0x81,0xd5},
        {0x1,0x81,0xd7},
        {0x1,0x81,0xd9},
        {0x1,0x81,0xdb},
        {0x1,0x81,0xdd},
        {0x1,0x81,0xdf},
        {0x1,0x81,0xe1},
        {0x1,0x81,0xe3},
        {0x1,0x81,0xe5},
        {0x1,0x81,0xfc},
        {0x1,0x81,0xe7},
        {0x1,0x81,0xfd},
        {0x1,0x82,0xff,0xdf},
        {0x1,0x83,0xff,0xfe,0x1f},
        {0x1,0x82,0xff,0xe7},
        {0x1,0x82,0xff,0xf3},
        {0x1,0x81,0x8b},
        {0x1,0x82,0xff,0xfb},
        {0x1,0x81,0x1f},
        {0x1,0x81,0x8f},
        {0x1,0x81,0x27},
        {0x1,0x81,0x93},
        {0x1,0x81,0x2f},
        {0x1,0x81,0x97},
        {0x1,0x81,0x9b},
        {0x1,0x81,0x9f},
        {0x1,0x81,0x37},
        {0x1,0x81,0xe9},
        {0x1,0x81,0xeb},
        {0x1,0x81,0xa3},
        {0x1,0x81,0xa7},
        {0x1,0x81,0xab},
        {0x1,0x81,0x3f},
        {0x1,0x81,0xaf},
        {0x1,0x81,0xed},
        {0x1,0x81,0xb3},
        {0x1,0x81,0x47},
        {0x1,0x81,0x4f},
        {0x1,0x81,0xb7},
        {0x1,0x81,0xef},
        {0x1,0x81,0xf1},
        {0x1,0x81,0xf3},
        {0x1,0x81,0xf5},
        {0x1,0x81,0xf7},
        {0x1,0x82,0xff,0xfd},
        {0x1,0x82,0xff,0x9f},
        {0x1,0x82,0xff,0xf7},
        {0x1,0x82,0xff,0xef},
    };
    for (size_t i = 0; i < vectors.size(); i++) {
        hpack_context ctx{}; hpack_init_context(&ctx);
        std::string result;
        EXPECT_EQ(hpack_decode_headers(&ctx, vectors[i].data(), vectors[i].size(), SaveHeader, &result), 0);
        EXPECT_EQ(result, std::string(1, static_cast<char>(32+i)));
        hpack_free_context(&ctx);
    }
}

TEST(UpstreamPolicy, CancellationAlsoStopsPartialWriteContinuation) {
    Endpoint e;
    e.query.budget = dns_query_budget_new(1, 1000);
    ASSERT_EQ(e.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(e.Wire(), DNS_ADMIT_OK);
    e.Progress();
    dns_query_budget_cancel(e.query.budget);
    EXPECT_EQ(e.Wire(), DNS_ADMIT_DONE);
}
TEST(UpstreamPolicy, UnprogressedWriteMustRecheckSharedRate) {
    Endpoint e(1, 1);
    e.query.budget = dns_query_budget_new(1, 1000);
    ASSERT_EQ(e.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(e.Wire(), DNS_ADMIT_OK);
    // Simulated WANT_WRITE: no positive byte progress, so no 500ms wire timer.
    _dns_attempt_expire(&e.query, ULONG_MAX);
    EXPECT_EQ(atomic_read(&e.query.dns_request_sent), 1);
    EXPECT_EQ(e.Wire(), DNS_ADMIT_WAIT);
}

TEST(UpstreamPolicy, TcpProductionQueueCancelBeforeHandshakeWritesNoBytes) {
    Endpoint e;
    int sockets[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets), 0);
    e.server.type = DNS_SERVER_TCP;
    e.server.fd = sockets[0];
    e.server.status = DNS_SERVER_STATUS_CONNECTING;
    e.query.budget = dns_query_budget_new(1, 1000);
    unsigned char dns[12] = {};
    ASSERT_EQ(e.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(_dns_client_send_framed(&e.server, &e.query, dns, sizeof(dns)), 0);
    EXPECT_FALSE(dns_query_budget_exhausted(e.query.budget));
    dns_query_budget_cancel(e.query.budget);
    e.server.status = DNS_SERVER_STATUS_CONNECTED;
    EXPECT_EQ(_dns_client_process_stream_writes(&e.server), 0);
    EXPECT_TRUE(list_empty(&e.server.conn_stream_list));
    EXPECT_TRUE(list_empty(&e.query.conn_stream_list));
    unsigned char received[32];
    EXPECT_EQ(recv(sockets[1], received, sizeof(received), 0), -1);
    EXPECT_EQ(errno, EAGAIN);
    EXPECT_EQ(atomic_read(&e.query.dns_request_sent), 0);
    close(sockets[0]); close(sockets[1]); e.server.fd = -1;
}
TEST(UpstreamPolicy, TcpProductionQueueWritesOneFramedAttemptAfterHandshake) {
    Endpoint e;
    int sockets[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets), 0);
    e.server.type = DNS_SERVER_TCP; e.server.fd = sockets[0];
    e.server.status = DNS_SERVER_STATUS_CONNECTING;
    e.query.budget = dns_query_budget_new(1, 1000);
    unsigned char dns[12] = {0x12,0x34};
    ASSERT_EQ(e.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(_dns_client_send_framed(&e.server, &e.query, dns, sizeof(dns)), 0);
    EXPECT_FALSE(dns_query_budget_exhausted(e.query.budget));
    e.server.status = DNS_SERVER_STATUS_CONNECTED;
    ASSERT_EQ(_dns_client_process_stream_writes(&e.server), 0);
    unsigned char received[32];
    ASSERT_EQ(recv(sockets[1], received, sizeof(received), 0), 14);
    EXPECT_EQ(received[0], 0); EXPECT_EQ(received[1], 12);
    EXPECT_EQ(memcmp(received + 2, dns, 12), 0);
    EXPECT_TRUE(dns_query_budget_exhausted(e.query.budget));
    EXPECT_TRUE(list_empty(&e.server.conn_stream_list));
    EXPECT_EQ(e.Retire(), 1);
    close(sockets[0]); close(sockets[1]); e.server.fd = -1;
}

TEST(UpstreamPolicy, RetryAfterDateFormsAndInvalidCalendar) {
    // 1994-11-06T08:49:36Z; next second in all three HTTP-date forms.
    const time_t now = 784111776;
    uint64_t delay = 0;
    for (const char *date : {"Sun, 06 Nov 1994 08:49:37 GMT",
         "Sunday, 06-Nov-94 08:49:37 GMT", "Sun Nov  6 08:49:37 1994"}) {
        EXPECT_EQ(_dns_policy_retry_after_ms(date, now, &delay), 0);
        EXPECT_EQ(delay, 1000u);
    }
    EXPECT_LT(_dns_policy_retry_after_ms("Sun, 31 Feb 2094 08:49:37 GMT", now, &delay), 0);
    EXPECT_LT(_dns_policy_retry_after_ms("Sun, 06 Nov 2094 08:49:37 GMT junk", now, &delay), 0);
    EXPECT_EQ(_dns_policy_retry_after_ms("18446744073709551615000", now, &delay), 0);
    EXPECT_EQ(delay, UINT64_MAX);
    EXPECT_EQ(_dns_policy_retry_after_ms("0", now, &delay), 0);
    EXPECT_EQ(delay, 0u);
}

TEST(UpstreamPolicy, RetainedFailureDoesNotResendAlreadyRepliedEndpoint) {
    Endpoint e;
    e.query.budget = dns_query_budget_new(6, 1000);
    ASSERT_EQ(e.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(e.Wire(), DNS_ADMIT_OK); e.Progress();
    ASSERT_EQ(e.Retire(), 1);
    _dns_attempt_replied(&e.query, &e.server);
    EXPECT_EQ(e.Begin(), DNS_ADMIT_DONE);
}

TEST(UpstreamPolicy, Http1ProductionWriteOwnerBecomesCancellationTombstone) {
    Endpoint e;
    int sockets[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets), 0);
    e.server.fd = sockets[0]; e.server.status = DNS_SERVER_STATUS_CONNECTED;
    strcpy(e.server.flags.https.path, "/dns-query");
    strcpy(e.server.flags.https.httphost, "localhost");
    e.query.budget = dns_query_budget_new(1, 1000);
    unsigned char dns[12] = {};
    ASSERT_EQ(e.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(_dns_client_send_http1(&e.server, &e.query, dns, sizeof(dns)), 0);
    ASSERT_EQ(_dns_client_process_stream_writes(&e.server), 0);
    unsigned char received[1024];
    int bytes = recv(sockets[1], received, sizeof(received), 0);
    ASSERT_GT(bytes, 12);
    EXPECT_EQ(memcmp(received, "POST ", 5), 0);
    EXPECT_TRUE(dns_query_budget_exhausted(e.query.budget));
    ASSERT_FALSE(list_empty(&e.server.conn_stream_list));
    auto *stream = list_first_entry(&e.server.conn_stream_list, dns_conn_stream, server_list);
    EXPECT_EQ(stream->http1_sent, 1);
    EXPECT_EQ(stream->recv_buff.data, nullptr); // no unused receive allocation for an H1 write owner
    // Model query destruction: its list reference is dropped, FIFO owner remains.
    list_del_init(&stream->query_list); stream->query = nullptr;
    _dns_client_conn_stream_put(stream);
    EXPECT_EQ(_dns_client_conn_prune(&e.server), 1);
    list_del_init(&stream->server_list); stream->server_info = nullptr;
    _dns_client_conn_stream_put(stream);
    EXPECT_EQ(e.Retire(), 1);
    close(sockets[0]); close(sockets[1]); e.server.fd = -1;
}

// Recovery uses no provider-specific QPS and never opens all queued owners
// merely because their shared cooldown has expired.
TEST(UpstreamPolicy, RecoverySerializesPrebufferedSharedEndpointsUntilAcceptedReply) {
    Endpoint a(0, 0, "recover-buffered"), b(0, 0, "recover-buffered"), healthy;
    ASSERT_EQ(a.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(b.Begin(), DNS_ADMIT_OK);
    _dns_policy_http_error(&a.server, 429, "0");
    EXPECT_EQ(a.Wire(), DNS_ADMIT_WAIT);
    EXPECT_EQ(b.Wire(), DNS_ADMIT_WAIT);
    ASSERT_EQ(healthy.Begin(), DNS_ADMIT_OK);
    EXPECT_EQ(healthy.Wire(), DNS_ADMIT_OK);
    usleep(150000);
    ASSERT_EQ(a.Wire(), DNS_ADMIT_OK);
    // WANT_WRITE may continue its own lease before positive progress.
    EXPECT_EQ(a.Wire(), DNS_ADMIT_OK);
    EXPECT_EQ(b.Wire(), DNS_ADMIT_WAIT);
    a.Progress();
    ASSERT_EQ(a.Retire(), 1);
    _dns_attempt_replied(&a.query, &a.server);
    EXPECT_EQ(b.Wire(), DNS_ADMIT_OK);
}
TEST(UpstreamPolicy, RecoveryRetirementPermitsOneNextProbeWithoutOpeningPolicy) {
    Endpoint a(0, 0, "recover-retire"), b(0, 0, "recover-retire"), c(0, 0, "recover-retire");
    ASSERT_EQ(a.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(b.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(c.Begin(), DNS_ADMIT_OK);
    _dns_policy_http_error(&a.server, 503, "0");
    usleep(150000);
    ASSERT_EQ(a.Wire(), DNS_ADMIT_OK); a.Progress();
    EXPECT_EQ(_dns_attempt_retire(&a.query, &a.server,
        _dns_attempt_generation(&a.query, &a.server) + 1), 0);
    EXPECT_EQ(b.Wire(), DNS_ADMIT_WAIT);
    ASSERT_EQ(a.Retire(), 1);
    EXPECT_EQ(a.Retire(), 0);
    ASSERT_EQ(b.Wire(), DNS_ADMIT_OK);
    EXPECT_EQ(c.Wire(), DNS_ADMIT_WAIT);
    b.Progress(); ASSERT_EQ(b.Retire(), 1);
    _dns_attempt_replied(&b.query, &b.server);
    EXPECT_EQ(c.Wire(), DNS_ADMIT_OK);
}
TEST(UpstreamPolicy, NewBackpressureEpochRejectsOldProbeCompletion) {
    Endpoint a(0, 0, "recover-epoch"), b(0, 0, "recover-epoch"), c(0, 0, "recover-epoch");
    ASSERT_EQ(a.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(b.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(c.Begin(), DNS_ADMIT_OK);
    _dns_policy_http_error(&a.server, 429, "0");
    usleep(150000);
    ASSERT_EQ(a.Wire(), DNS_ADMIT_OK); a.Progress();
    _dns_policy_http_error(&a.server, 429, "0");
    ASSERT_EQ(a.Retire(), 1);
    _dns_attempt_replied(&a.query, &a.server); // prior epoch is stale
    EXPECT_EQ(b.Wire(), DNS_ADMIT_WAIT);
    usleep(150000);
    ASSERT_EQ(b.Wire(), DNS_ADMIT_OK); b.Progress();
    _dns_attempt_replied(&a.query, &a.server); // cannot release b's lease
    EXPECT_EQ(c.Wire(), DNS_ADMIT_WAIT);
    ASSERT_EQ(b.Retire(), 1);
    _dns_attempt_replied(&b.query, &b.server);
    EXPECT_EQ(c.Wire(), DNS_ADMIT_OK);
}
TEST(UpstreamPolicy, RecoveryCancellationAndDestructionReleaseLease) {
    Endpoint next(0, 0, "recover-free"), sibling(0, 0, "recover-free");
    ASSERT_EQ(next.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(sibling.Begin(), DNS_ADMIT_OK);
    {
        Endpoint canceled(0, 0, "recover-free");
        canceled.query.budget = dns_query_budget_new(4, 10000);
        ASSERT_EQ(canceled.Begin(), DNS_ADMIT_OK);
        _dns_policy_http_error(&canceled.server, 429, "0");
        usleep(150000);
        ASSERT_EQ(canceled.Wire(), DNS_ADMIT_OK);
        dns_query_budget_cancel(canceled.query.budget);
        EXPECT_EQ(canceled.Wire(), DNS_ADMIT_DONE);
        EXPECT_EQ(next.Wire(), DNS_ADMIT_WAIT);
    }
    ASSERT_EQ(next.Wire(), DNS_ADMIT_OK);
    EXPECT_EQ(sibling.Wire(), DNS_ADMIT_WAIT);
    next.Progress(); ASSERT_EQ(next.Retire(), 1);
    _dns_attempt_replied(&next.query, &next.server);
    EXPECT_EQ(sibling.Wire(), DNS_ADMIT_OK);
}
TEST(UpstreamPolicy, RecoveryProbeTimeoutReleasesOnlyItsLease) {
    Endpoint a(0, 0, "recover-timeout"), b(0, 0, "recover-timeout"), c(0, 0, "recover-timeout");
    ASSERT_EQ(a.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(b.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(c.Begin(), DNS_ADMIT_OK);
    _dns_policy_http_error(&a.server, 429, "0");
    usleep(150000);
    ASSERT_EQ(a.Wire(), DNS_ADMIT_OK); a.Progress();
    _dns_attempt_expire(&a.query, ULONG_MAX);
    EXPECT_EQ(atomic_read(&a.query.dns_request_sent), 0);
    ASSERT_EQ(b.Wire(), DNS_ADMIT_OK);
    EXPECT_EQ(c.Wire(), DNS_ADMIT_WAIT);
}
TEST(UpstreamPolicy, DatagramAndStreamShareRecoveryLease) {
    Endpoint udp(0, 0, "recover-mixed"), https(0, 0, "recover-mixed");
    udp.server.type = DNS_SERVER_UDP;
    ASSERT_EQ(https.Begin(), DNS_ADMIT_OK);
    _dns_policy_http_error(&https.server, 429, "0");
    usleep(150000);
    ASSERT_EQ(udp.Begin(), DNS_ADMIT_OK);
    EXPECT_EQ(https.Wire(), DNS_ADMIT_WAIT);
    ASSERT_EQ(udp.Retire(), 1);
    _dns_attempt_replied(&udp.query, &udp.server);
    EXPECT_EQ(https.Wire(), DNS_ADMIT_OK);
}
TEST(UpstreamPolicy, RecoveryPreservesExplicitRateAndRetryAfterMinimum) {
    Endpoint a(1, 1, "recover-rate"), b(1, 1, "recover-rate");
    _dns_policy_http_error(&a.server, 429, "1");
    usleep(150000);
    EXPECT_EQ(a.Begin(), DNS_ADMIT_WAIT); // server minimum is not local 100ms
    // Separate policy lets the fast recovery fixture stay bounded.
    Endpoint probe(1, 1, "recover-rate-fast"), next(1, 1, "recover-rate-fast");
    _dns_policy_http_error(&probe.server, 429, "0");
    usleep(150000);
    ASSERT_EQ(probe.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(probe.Wire(), DNS_ADMIT_OK); probe.Progress();
    ASSERT_EQ(probe.Retire(), 1);
    _dns_attempt_replied(&probe.query, &probe.server);
    EXPECT_EQ(next.Begin(), DNS_ADMIT_WAIT); // successful probe does not refill rate tokens
}
TEST(UpstreamPolicy, RecoveryGatesProductionTcpWritesAcrossSharedEndpoints) {
    Endpoint a(0, 0, "recover-wire"), b(0, 0, "recover-wire");
    int x[2], y[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, x), 0);
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, y), 0);
    a.server.type = b.server.type = DNS_SERVER_TCP;
    a.server.fd = x[0]; b.server.fd = y[0];
    a.server.status = b.server.status = DNS_SERVER_STATUS_CONNECTING;
    unsigned char dns[12] = {0x12, 0x34}, received[32];
    ASSERT_EQ(a.Begin(), DNS_ADMIT_OK); ASSERT_EQ(b.Begin(), DNS_ADMIT_OK);
    ASSERT_EQ(_dns_client_send_framed(&a.server, &a.query, dns, sizeof(dns)), 0);
    ASSERT_EQ(_dns_client_send_framed(&b.server, &b.query, dns, sizeof(dns)), 0);
    _dns_policy_http_error(&a.server, 429, "0");
    a.server.status = b.server.status = DNS_SERVER_STATUS_CONNECTED;
    EXPECT_EQ(_dns_client_process_stream_writes(&a.server), 0);
    EXPECT_EQ(_dns_client_process_stream_writes(&b.server), 0);
    EXPECT_EQ(recv(x[1], received, sizeof(received), 0), -1); EXPECT_EQ(errno, EAGAIN);
    EXPECT_EQ(recv(y[1], received, sizeof(received), 0), -1); EXPECT_EQ(errno, EAGAIN);
    usleep(150000);
    ASSERT_EQ(_dns_client_process_stream_writes(&a.server), 0);
    EXPECT_EQ(recv(x[1], received, sizeof(received), 0), 14);
    EXPECT_EQ(_dns_client_process_stream_writes(&b.server), 0);
    EXPECT_EQ(recv(y[1], received, sizeof(received), 0), -1); EXPECT_EQ(errno, EAGAIN);
    ASSERT_EQ(a.Retire(), 1); _dns_attempt_replied(&a.query, &a.server);
    ASSERT_EQ(_dns_client_process_stream_writes(&b.server), 0);
    EXPECT_EQ(recv(y[1], received, sizeof(received), 0), 14);
    EXPECT_EQ(b.Retire(), 1);
    close(x[0]); close(x[1]); close(y[0]); close(y[1]);
    a.server.fd = b.server.fd = -1;
}

// The production receive path must not infer a UDP wire generation from the
// current attempt: retries keep the query's SID on the wire.
namespace {
struct ReceiveQuery {
    Endpoint &endpoint;
    int action, calls = 0, rcode = -1;
    dns_server_group group{};
    dns_server_group_member member{};
    ReceiveQuery(Endpoint &e, int result = DNS_CLIENT_ACTION_OK) : endpoint(e), action(result) {
        pthread_mutex_init(&client.domain_map_lock, nullptr);
        pthread_mutex_init(&client.server_list_lock, nullptr);
        for (auto &bucket : client.domain_map) INIT_HLIST_HEAD(&bucket);
        for (auto &bucket : client.group) INIT_HLIST_HEAD(&bucket);
        INIT_LIST_HEAD(&client.dns_request_list);
        INIT_LIST_HEAD(&group.head); INIT_LIST_HEAD(&member.list);
        member.server = &e.server; list_add(&member.list, &group.head);
        e.query.server_group = &group;
        INIT_LIST_HEAD(&e.query.dns_request_list);
        INIT_HLIST_NODE(&e.query.domain_node);
        for (auto &bucket : e.query.replied_map) INIT_HLIST_HEAD(&bucket);
        strcpy(e.query.domain, "recovery.mock.example"); e.query.qtype = DNS_T_A;
        e.query.created_tick = get_tick_count();
        e.query.budget = dns_query_budget_new(4, DNS_QUERY_RETRY * DNS_QUERY_TIMEOUT);
        // One explicit owner plus the query-list owner; receive may retire the
        // latter, but this stack fixture must never enter heap destruction.
        atomic_set(&e.query.refcnt, 2);
        e.query.callback = Callback; e.query.user_ptr = this;
        EXPECT_EQ(_dns_client_add_hashmap(&e.query), 0);
    }
    ~ReceiveQuery() {
        if (!endpoint.query.terminal) _dns_client_query_remove(&endpoint.query);
        _dns_replied_check_remove(&endpoint.query, &endpoint.server);
        EXPECT_EQ(atomic_read(&endpoint.query.refcnt), 1);
        list_del_init(&member.list);
        pthread_mutex_destroy(&client.server_list_lock);
        pthread_mutex_destroy(&client.domain_map_lock);
    }
    static int Callback(const char *, dns_result_type type, dns_server_info *,
                        dns_packet *packet, unsigned char *, int, void *opaque) {
        auto *self = static_cast<ReceiveQuery *>(opaque);
        if (type == DNS_QUERY_RESULT) { self->calls++; self->rcode = packet->head.rcode; }
        return self->action;
    }
    std::vector<unsigned char> Reply(int rcode = DNS_RC_NOERROR) {
        unsigned char storage[DNS_PACKSIZE], wire[DNS_IN_PACKSIZE];
        auto *packet = reinterpret_cast<dns_packet *>(storage);
        dns_head head{}; head.id = endpoint.query.sid; head.qr = DNS_QR_ANSWER;
        head.rd = 1; head.ra = 1; head.rcode = rcode;
        EXPECT_EQ(dns_packet_init(packet, sizeof(storage), &head), 0);
        EXPECT_EQ(dns_add_domain(packet, endpoint.query.domain, DNS_T_A, DNS_C_IN), 0);
        int len = dns_encode(wire, sizeof(wire), packet);
        EXPECT_GT(len, 0);
        return len > 0 ? std::vector<unsigned char>(wire, wire + len) : std::vector<unsigned char>{};
    }
    int Deliver(std::vector<unsigned char> wire) {
        return _dns_client_recv(&endpoint.server, wire.data(), wire.size(),
                                &endpoint.server.addr, endpoint.server.ai_addrlen);
    }
};
struct LoopbackDatagram {
    Endpoint &endpoint;
    int peer = -1;
    sockaddr_in client_address{};
    LoopbackDatagram(Endpoint &e) : endpoint(e) {
        peer = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        e.server.fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        EXPECT_GE(peer, 0); EXPECT_GE(e.server.fd, 0);
        sockaddr_in address{}; address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        EXPECT_EQ(bind(peer, reinterpret_cast<sockaddr *>(&address), sizeof(address)), 0);
        socklen_t len = sizeof(address);
        EXPECT_EQ(getsockname(peer, reinterpret_cast<sockaddr *>(&address), &len), 0);
        EXPECT_EQ(connect(e.server.fd, reinterpret_cast<sockaddr *>(&address), len), 0);
        e.server.type = DNS_SERVER_UDP; e.server.ai_family = AF_INET;
        e.server.ai_addrlen = len; memcpy(&e.server.addr, &address, len);
        e.server.status = DNS_SERVER_STATUS_CONNECTED;
    }
    ~LoopbackDatagram() { close(peer); close(endpoint.server.fd); endpoint.server.fd = -1; }
    std::vector<unsigned char> Capture() {
        pollfd p{peer, POLLIN, 0};
        EXPECT_EQ(poll(&p, 1, 250), 1);
        unsigned char wire[DNS_IN_PACKSIZE]; socklen_t len = sizeof(client_address);
        int n = recvfrom(peer, wire, sizeof(wire), 0,
                         reinterpret_cast<sockaddr *>(&client_address), &len);
        EXPECT_GT(n, 0);
        return n > 0 ? std::vector<unsigned char>(wire, wire + n) : std::vector<unsigned char>{};
    }
    int Deliver(const std::vector<unsigned char> &wire) {
        EXPECT_EQ(sendto(peer, wire.data(), wire.size(), 0,
                         reinterpret_cast<sockaddr *>(&client_address), sizeof(client_address)),
                  static_cast<ssize_t>(wire.size()));
        pollfd p{endpoint.server.fd, POLLIN, 0}; EXPECT_EQ(poll(&p, 1, 250), 1);
        unsigned char response[DNS_IN_PACKSIZE]; sockaddr_storage from{}; socklen_t len = sizeof(from);
        int n = recvfrom(endpoint.server.fd, response, sizeof(response), 0,
                         reinterpret_cast<sockaddr *>(&from), &len);
        EXPECT_GT(n, 0);
        return n > 0 ? _dns_client_recv(&endpoint.server, response, n,
                         reinterpret_cast<sockaddr *>(&from), len) : -1;
    }
};
}

TEST(UpstreamPolicy, Pre429UdpReplyCannotProveRetriedProbeEpochThroughReceive) {
    Endpoint udp(0, 0, "udp-retry-proof"), https(0, 0, "udp-retry-proof"),
             sibling(0, 0, "udp-retry-proof");
    ReceiveQuery registered(udp); LoopbackDatagram wire(udp);
    ASSERT_EQ(_dns_client_send_query(&udp.query), 0);
    auto first = wire.Capture(); ASSERT_FALSE(first.empty());
    auto old_reply = registered.Reply();
    unsigned first_generation = _dns_attempt_generation(&udp.query, &udp.server);
    ASSERT_EQ(https.Begin(), DNS_ADMIT_OK); ASSERT_EQ(sibling.Begin(), DNS_ADMIT_OK);
    _dns_policy_http_error(&https.server, 429, "0");
    // Remain within the original two-second budget while genuinely expiring gen1.
    usleep((DNS_QUERY_TIMEOUT + 40) * 1000);
    _dns_attempt_expire(&udp.query, get_tick_count());
    ASSERT_EQ(atomic_read(&udp.query.dns_request_sent), 0);
    ASSERT_EQ(_dns_client_send_query(&udp.query), 0);
    auto second = wire.Capture();
    ASSERT_EQ(first, second); // Same domain/type/SID, no wire-generation discriminator.
    ASSERT_GT(_dns_attempt_generation(&udp.query, &udp.server), first_generation);
    ASSERT_GT(dns_query_budget_remaining_ms(udp.query.budget), 0u);
    ASSERT_EQ(wire.Deliver(old_reply), 0);
    EXPECT_EQ(registered.calls, 1); EXPECT_EQ(registered.rcode, DNS_RC_NOERROR);
    EXPECT_TRUE(udp.query.terminal); EXPECT_TRUE(udp.query.has_result);
    // Ordinary delivery succeeds, but only one sibling may now probe recovery.
    ASSERT_EQ(https.Wire(), DNS_ADMIT_OK);
    EXPECT_EQ(sibling.Wire(), DNS_ADMIT_WAIT);
}

TEST(UpstreamPolicy, FirstSendUdpQueryAfterCooldownCanStillProveRecoveryThroughReceive) {
    Endpoint udp(0, 0, "udp-first-proof"), https(0, 0, "udp-first-proof"),
             sibling(0, 0, "udp-first-proof");
    ReceiveQuery registered(udp); LoopbackDatagram wire(udp);
    ASSERT_EQ(https.Begin(), DNS_ADMIT_OK); ASSERT_EQ(sibling.Begin(), DNS_ADMIT_OK);
    _dns_policy_http_error(&https.server, 429, "0"); usleep(150000);
    ASSERT_EQ(_dns_client_send_query(&udp.query), 0); ASSERT_FALSE(wire.Capture().empty());
    ASSERT_EQ(wire.Deliver(registered.Reply()), 0);
    EXPECT_EQ(registered.calls, 1); EXPECT_TRUE(udp.query.terminal);
    EXPECT_EQ(https.Wire(), DNS_ADMIT_OK); EXPECT_EQ(sibling.Wire(), DNS_ADMIT_OK);
}

TEST(UpstreamPolicy, RecoveryExchangeCallbackContractIsSeparateFromDnsBusinessSuccess) {
    for (int action : {DNS_CLIENT_ACTION_OK, DNS_CLIENT_ACTION_MAY_RETRY,
                       DNS_CLIENT_ACTION_UNDEFINE, DNS_CLIENT_ACTION_RETRY, DNS_CLIENT_ACTION_DROP}) {
        for (int rcode : {DNS_RC_NOERROR, DNS_RC_NXDOMAIN, DNS_RC_SERVFAIL, DNS_RC_REFUSED}) {
            SCOPED_TRACE(::testing::Message() << "action=" << action << " rcode=" << rcode);
            Endpoint probe(0, 0, "callback-proof"), a(0, 0, "callback-proof"), b(0, 0, "callback-proof");
            ReceiveQuery registered(probe, action);
            ASSERT_EQ(probe.Begin(), DNS_ADMIT_OK);
            ASSERT_EQ(a.Begin(), DNS_ADMIT_OK); ASSERT_EQ(b.Begin(), DNS_ADMIT_OK);
            _dns_policy_http_error(&probe.server, 429, "0"); usleep(150000);
            ASSERT_EQ(probe.Wire(), DNS_ADMIT_OK); probe.Progress();
            ASSERT_EQ(registered.Deliver(registered.Reply(rcode)), 0);
            EXPECT_EQ(registered.calls, 1); EXPECT_EQ(registered.rcode, rcode);
            EXPECT_EQ(probe.query.has_result, action == DNS_CLIENT_ACTION_OK);
            bool accepted = action != DNS_CLIENT_ACTION_RETRY && action != DNS_CLIENT_ACTION_DROP;
            EXPECT_EQ(probe.query.terminal, accepted && action != DNS_CLIENT_ACTION_MAY_RETRY);
            ASSERT_EQ(a.Wire(), DNS_ADMIT_OK);
            EXPECT_EQ(b.Wire(), accepted ? DNS_ADMIT_OK : DNS_ADMIT_WAIT);
        }
    }
}
