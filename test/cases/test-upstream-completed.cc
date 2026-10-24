/* Completed native requests must not turn late records into provider faults. */
#include "client.h"
#include "server.h"
#include "smartdns/upstream_service.h"
#include "gtest/gtest.h"
#include <atomic>
#include <chrono>
#include <cstring>
#include <poll.h>
#include <unistd.h>

namespace {
bool wait_for(const std::atomic<bool> &flag)
{
    auto limit = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!flag.load() && std::chrono::steady_clock::now() < limit) poll(nullptr, 0, 1);
    return flag.load();
}

void completed_case(bool pooled, int qtype, int late_rcode = DNS_RC_NOERROR)
{
    std::atomic<bool> slow_received{false}, release_late{false};
    std::atomic<unsigned> late_sends{0};
    auto answer = [&](smartdns::ServerRequestContext *r) {
        dns_add_domain(r->response_packet, r->domain.c_str(), r->qtype, r->qclass);
        if (qtype == DNS_T_SRV)
            dns_add_SRV(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, 10, 0, 5260, "sip.example");
        else smartdns::MockServer::AddIP(r, r->domain.c_str(), "192.0.2.96", 60);
    };
    smartdns::MockServer fast, slow, alternate;
    // The winner waits until a late response really is in flight. Release the
    // late provider only after the client received its answer, without races
    // based on arbitrary response delays.
    ASSERT_TRUE(fast.Start("udp://127.0.0.1:63896", [&](auto *r) {
        if (!wait_for(slow_received)) return smartdns::SERVER_REQUEST_ERROR;
        answer(r); return smartdns::SERVER_REQUEST_OK;
    }));
    auto late = [&](smartdns::ServerRequestContext *r) {
        late_sends++; slow_received = true;
        if (!wait_for(release_late)) return smartdns::SERVER_REQUEST_ERROR;
        if (late_rcode == DNS_RC_NOERROR) answer(r);
        else dns_add_domain(r->response_packet, r->domain.c_str(), r->qtype, r->qclass);
        r->response_packet->head.rcode = late_rcode;
        return smartdns::SERVER_REQUEST_OK;
    };
    ASSERT_TRUE(slow.Start("udp://127.0.0.1:63897", late));
    if (pooled) ASSERT_TRUE(alternate.Start("udp://127.0.0.2:63897", late));
    smartdns::Server resolver(smartdns::Server::CREATE_MODE_THREAD);
    std::string conf = "bind 127.0.0.1:63796\nserver 127.0.0.1:63896\nserver ";
    conf += pooled ? "udp://late.example:63897 -upstream-ip-pool -host-ip 127.0.0.1,127.0.0.2\n"
                   : "127.0.0.1:63897\n";
    conf += "cache-size 0\ncache-persist no\nprefetch-domain no\nserve-expired no\n"
            "dualstack-ip-selection no\nspeed-check-mode none\nresponse-mode fastest-response\n";
    ASSERT_TRUE(resolver.Start(conf));
    smartdns::Client query;
    bool queried = query.Query(std::string(qtype == DNS_T_SRV ? "_sips._tcp.example SRV" : "late.example A") +
                               " +time=3 +tries=1", 63796, "127.0.0.1");
    release_late = true; // Release even if the client failed, so teardown cannot strand a mock.
    ASSERT_TRUE(queried);
    ASSERT_EQ(query.GetStatus(), "NOERROR"); ASSERT_EQ(query.GetAnswerNum(), 1);
    EXPECT_EQ(query.GetAnswer()[0].GetData(), qtype == DNS_T_SRV ? "10 0 5260 sip.example." : "192.0.2.96");

    dns_upstream_service_snapshot_v1 rows[4]{}, base{};
    ASSERT_EQ(dns_client_get_service_snapshot_v1(rows, 4), 2);
    const char *id = nullptr;
    for (const auto &row : rows)
        if ((pooled && row.pool_enabled) || (!pooled && row.port == 63897)) id = row.service_id;
    ASSERT_NE(id, nullptr);
    dns_upstream_service_diagnostics_v1 raw{}; dns_upstream_policy_snapshot_v1 policy{};
    auto limit = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    do {
        ASSERT_EQ(dns_client_get_service_diagnostics_v1(id, &base, &raw), 0);
        ASSERT_EQ(dns_client_get_service_policy_v1(id, &policy), 0);
        if (base.in_flight == 0 && policy.event_count + base.success_count) break;
        poll(nullptr, 0, 5);
    } while (std::chrono::steady_clock::now() < limit);
    EXPECT_EQ(base.in_flight, 0U);
    if (pooled) EXPECT_EQ(base.recv_count, late_sends.load());
    if (late_rcode == DNS_RC_NOERROR) {
        EXPECT_EQ(late_sends, 1U); EXPECT_EQ(base.attempt_count, 1U);
    }
    EXPECT_EQ(policy.reject_counts[DNS_REJECT_NO_USABLE_RECORDS], 0U);
    EXPECT_EQ(raw.events[DNS_EVENT_DNS_REJECTED], 0U);
    EXPECT_EQ(raw.events[DNS_EVENT_ATTEMPT_TIMEOUT], 0U);
    if (late_rcode != DNS_RC_NOERROR) {
        EXPECT_GE(late_sends, 1U);
        EXPECT_EQ(raw.events[DNS_EVENT_DNS_RCODE], late_sends.load());
        EXPECT_EQ(policy.kind_counts[DNS_DETAIL_DNS_RCODE], late_sends.load());
        EXPECT_EQ(policy.events[0].code, DNS_RC_SERVFAIL);
    } else if (qtype == DNS_T_SRV) {
        EXPECT_EQ(policy.reject_counts[DNS_REJECT_COMPLETED], 1U);
        EXPECT_EQ(raw.failure_end[DNS_END_OTHER_RESULT], 1U);
        EXPECT_EQ(raw.failure_last_event[0], 1U); // no invented DNS/network failure
        dns_upstream_endpoint_activity_v1 endpoints[4]{};
        int count = dns_client_get_service_endpoint_activity_v1(id, endpoints, 4);
        ASSERT_GT(count, 0);
        uint64_t failures = 0;
        for (int i = 0; i < count; i++) failures += endpoints[i].endpoint.failure_count;
        if (pooled) EXPECT_EQ(failures, 0U);
    } else {
        // Keep the native processing of late usable addresses, rather than
        // blanket-dropping every response after fastest-response notified.
        EXPECT_EQ(base.success_count, 1U);
        EXPECT_EQ(policy.reject_counts[DNS_REJECT_COMPLETED], 0U);
    }
}
} // namespace

#define COMPLETED_CASE(Name, Action) \
TEST(UpstreamCompleted, Name) { \
    ::testing::FLAGS_gtest_death_test_style = "threadsafe"; \
    ASSERT_EXIT({ Action; \
        auto *result = ::testing::UnitTest::GetInstance()->current_test_info()->result(); \
        for (int i = 0; i < result->total_part_count(); i++) \
            if (result->GetTestPartResult(i).failed()) \
                fprintf(stderr, "%s\n", result->GetTestPartResult(i).message()); \
        _exit(::testing::Test::HasFailure() ? 1 : 0); \
    }, ::testing::ExitedWithCode(0), ""); \
}
COMPLETED_CASE(LateSrvPoolKeepsCompletionWithoutRetryOrEndpointPenalty, completed_case(true, DNS_T_SRV))
COMPLETED_CASE(LateSrvOrdinaryKeepsCompletionWithoutRetry, completed_case(false, DNS_T_SRV))
COMPLETED_CASE(LateUsableAddressStillUsesNativeProcessing, completed_case(true, DNS_T_A))
COMPLETED_CASE(LateActualServfailRemainsVisible, completed_case(true, DNS_T_SRV, DNS_RC_SERVFAIL))
#undef COMPLETED_CASE
