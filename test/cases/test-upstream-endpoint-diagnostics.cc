#include "gtest/gtest.h"
#include "client.h"
#include "server.h"
extern "C" {
#include "dns_client/upstream_observer.h"
#include "dns_client/upstream_policy.h"
#include "smartdns/util.h"
}
#include <arpa/inet.h>
#include <cstring>
#include <cerrno>
#include <string>
#include <chrono>
#include <poll.h>

namespace {
struct ObservedEndpoint {
    dns_server_info ep{};
    dns_query_struct q{};
    bool finished = false;
    ObservedEndpoint() {
        pthread_mutexattr_t attr; pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&ep.lock, &attr); pthread_mutexattr_destroy(&attr);
        pthread_mutex_init(&q.lock, nullptr);
        INIT_LIST_HEAD(&ep.list); INIT_LIST_HEAD(&ep.conn_stream_list);
        INIT_LIST_HEAD(&q.conn_stream_list);
        atomic_set(&ep.refcnt, 1); ep.fd = -1;
        ep.type = DNS_SERVER_UDP; ep.port = 53; ep.status = DNS_SERVER_STATUS_CONNECTIONLESS;
        ep.ai_family = AF_INET; ep.ai_addrlen = sizeof(ep.in);
        ep.in.sin_family = AF_INET; ep.in.sin_port = htons(ep.port);
        inet_pton(AF_INET, "192.0.2.7", &ep.in.sin_addr);
        strcpy(ep.ip, "192.0.2.7"); strcpy(ep.host, "ordinary.example");
        dns_client_flags_init(&ep.flags); ep.flags.type = ep.type;
        q.created_tick = get_tick_count(); q.sid = 1234; q.qtype = DNS_T_AAAA;
        strcpy(q.domain, "dualstack.example"); q.budget = dns_query_budget_new(8, 10000);
        EXPECT_EQ(_dns_policy_attach(&ep), 0); _dns_endpoint_observer_init(&ep);
        EXPECT_NE(ep.diagnostic, nullptr);
    }
    void Observe() { _dns_endpoint_observe(&q, &ep); }
    void Send() {
        ASSERT_EQ(_dns_attempt_begin(&q, &ep), DNS_ADMIT_OK);
        _dns_attempt_mark_sent(&q, &ep, _dns_attempt_generation(&q, &ep));
    }
    void Finish() { ASSERT_FALSE(finished); finished = true; _dns_endpoint_query_finish(&q); }
    dns_upstream_service_snapshot_v1 Snapshot() {
        dns_upstream_service_snapshot_v1 base{}; _dns_endpoint_snapshot(&ep, &base, nullptr); return base;
    }
    ~ObservedEndpoint() {
        if (!finished) _dns_endpoint_query_finish(&q);
        _dns_attempt_free_all(&q); _dns_endpoint_query_free(&q); dns_query_budget_put(q.budget);
        EXPECT_EQ(atomic_read(&ep.refcnt), 1);
        _dns_endpoint_observer_destroy(&ep); _dns_policy_detach(&ep);
        pthread_mutex_destroy(&ep.lock); pthread_mutex_destroy(&q.lock);
    }
};
}

TEST(UpstreamEndpointDiagnostics, AcceptedNegativeResponseClosesExactlyOnceAndPreservesNonPoolRouting) {
    ObservedEndpoint node; node.Observe(); node.Observe(); node.Send();
    EXPECT_EQ(node.ep.service, nullptr); // instrumentation cannot enable pool routing
    auto pending = node.Snapshot(); EXPECT_EQ(pending.query_count, 1U); EXPECT_EQ(pending.in_flight, 1U);
    auto generation = _dns_attempt_generation(&node.q, &node.ep);
    _dns_attempt_mark_sent(&node.q, &node.ep, generation); // repeated positive chunks are one attempt
    _dns_attempt_response_sample(&node.q, &node.ep);
    _dns_service_query_result(&node.q, &node.ep, 1); // NOERROR/SOA and NXDOMAIN are accepted too
    // OK_WAIT must close this endpoint even while native query ownership remains.
    pending = node.Snapshot(); EXPECT_EQ(pending.success_count, 1U); EXPECT_EQ(pending.response_latency_samples, 1U);
    EXPECT_EQ(pending.in_flight, 0U); EXPECT_FALSE(node.q.terminal);
    _dns_service_query_result(&node.q, &node.ep, 1); // duplicate cannot settle twice
    node.q.has_result = 1; node.q.result_endpoint = &node.ep; node.Finish();
    auto base = node.Snapshot(); EXPECT_EQ(base.query_count, 1U); EXPECT_EQ(base.attempt_count, 1U);
    EXPECT_EQ(base.success_count, 1U); EXPECT_EQ(base.failure_count + base.skip_count + base.in_flight, 0U);
    EXPECT_EQ(base.response_latency_samples, 1U); EXPECT_EQ(base.attempt_rtt_samples, 1U);
}
TEST(UpstreamEndpointDiagnostics, SentRaceUnsentRateWaitAndLocalCancelRemainDistinct) {
    { ObservedEndpoint node; node.Observe(); node.Send(); node.q.has_result = 1; node.Finish();
      auto base = node.Snapshot(); EXPECT_EQ(base.failure_count, 1U);
      EXPECT_EQ(node.ep.diagnostic->breakdown.failure_end[DNS_END_OTHER_RESULT], 1U); }
    { ObservedEndpoint node; node.Observe();
      pthread_mutex_lock(&node.q.lock); _dns_endpoint_wait_locked(&node.q, &node.ep, DNS_WAIT_RATE);
      pthread_mutex_unlock(&node.q.lock); node.q.has_result = 1; node.Finish();
      auto base = node.Snapshot(); EXPECT_EQ(base.skip_count, 1U); EXPECT_EQ(base.attempt_count, 0U);
      EXPECT_EQ(node.ep.diagnostic->breakdown.skip_wait[DNS_WAIT_RATE], 1U);
      EXPECT_EQ(node.ep.diagnostic->breakdown.skip_end[DNS_END_OTHER_RESULT], 1U); }
    { ObservedEndpoint node; node.Observe(); node.Send(); dns_query_budget_cancel(node.q.budget); node.Finish();
      EXPECT_EQ(node.ep.diagnostic->breakdown.failure_end[DNS_END_BUDGET_OR_CANCEL], 1U); }
}
TEST(UpstreamEndpointDiagnostics, RejectedOwnResultHasProvenanceAndLastEventRatherThanAnotherWinner) {
    ObservedEndpoint node; node.Observe(); node.Send();
    _dns_service_diagnostic_event(&node.q, &node.ep, DNS_EVENT_DNS_RCODE);
    _dns_service_query_result(&node.q, &node.ep, 0);
    node.q.has_result = 1; node.q.result_endpoint = &node.ep; node.Finish();
    auto *d = node.ep.diagnostic;
    EXPECT_EQ(d->base.failure_count, 1U); EXPECT_EQ(d->breakdown.events[DNS_EVENT_DNS_RCODE], 1U);
    EXPECT_EQ(d->breakdown.failure_end[DNS_END_UNACCEPTED_RESULT], 1U);
    EXPECT_EQ(d->breakdown.failure_last_event[DNS_EVENT_DNS_RCODE + 1], 1U);
    EXPECT_EQ(d->breakdown.failure_end[DNS_END_OTHER_RESULT], 0U);
}
TEST(UpstreamEndpointDiagnostics, PositiveWriteRacingTerminalIsSentAndRetriesRemainOneLogicalQuery) {
    { ObservedEndpoint node; node.Observe(); ASSERT_EQ(_dns_attempt_begin(&node.q, &node.ep), DNS_ADMIT_OK);
      node.q.terminal = 1; node.q.has_result = 1;
      _dns_attempt_mark_sent(&node.q, &node.ep, _dns_attempt_generation(&node.q, &node.ep)); node.Finish();
      auto base = node.Snapshot(); EXPECT_EQ(base.attempt_count, 1U); EXPECT_EQ(base.failure_count, 1U);
      EXPECT_EQ(base.skip_count, 0U); }
    { ObservedEndpoint node; node.Observe(); node.Send();
      ASSERT_EQ(_dns_attempt_retire(&node.q, &node.ep, 0), 1); node.Send();
      _dns_attempt_response_sample(&node.q, &node.ep); _dns_service_query_result(&node.q, &node.ep, 1);
      node.q.has_result = 1; node.Finish(); auto base = node.Snapshot();
      EXPECT_EQ(base.query_count, 1U); EXPECT_EQ(base.attempt_count, 2U); EXPECT_EQ(base.success_count, 1U);
      EXPECT_EQ(base.attempt_rtt_samples, 0U); EXPECT_EQ(base.attempt_rtt_ambiguous_count, 1U);
      EXPECT_EQ(node.ep.service_success_count, 1U); EXPECT_EQ(node.ep.service_failure_count, 1U); }
}
TEST(UpstreamEndpointDiagnostics, HttpCountersAreIndependentOfBoundedEventWindowAndCaptureWallTime) {
    ObservedEndpoint node; node.Observe();
    _dns_policy_http_error_query(&node.q, &node.ep, 429, "3600");
    _dns_service_diagnostic_http(&node.q, &node.ep, 429); // association must not double count
    for (unsigned i = 0; i < 40; i++)
        _dns_service_detail(&node.q, &node.ep, DNS_DETAIL_RESPONSE_TIMEOUT, DNS_PHASE_RESPONSE, 0, 1000, 1000);
    dns_upstream_policy_snapshot_v1 policy{}; _dns_endpoint_policy_snapshot(&node.ep, &policy);
    EXPECT_EQ(policy.event_count, 32U); EXPECT_EQ(policy.dropped_events, 9U);
    EXPECT_EQ(policy.kind_counts[DNS_DETAIL_HTTP_429], 1U);
    dns_upstream_endpoint_activity_v1 activity{}; _dns_policy_endpoint_activity(&node.ep, &activity);
    EXPECT_EQ(activity.http_429, 1U); EXPECT_EQ(activity.http_503, 0U);
    EXPECT_GT(activity.cooldown_remaining_ms, 0U); EXPECT_LE(activity.cooldown_remaining_ms, 1000U);
    EXPECT_GT(activity.last_backpressure_unix_ms, 0U);
    dns_upstream_event_context_snapshot_v1 context{}; _dns_endpoint_context_snapshot(&node.ep, &context);
    EXPECT_EQ(context.event_count, 32U); EXPECT_EQ(context.events[0].sequence, policy.events[0].sequence);
    EXPECT_EQ(std::string(context.events[0].domain), "dualstack.example");
    EXPECT_EQ(context.events[0].qtype, DNS_T_AAAA); EXPECT_GT(context.events[0].unix_ms, 0U);
}
TEST(UpstreamEndpointDiagnostics, DeadlineAndIoFailureAreRealEvidenceWithoutGeneratingProbeTraffic) {
    ObservedEndpoint node; node.Observe(); node.Send();
    _dns_endpoint_io_error(&node.q, &node.ep, DNS_PHASE_CONNECT, EHOSTUNREACH);
    node.q.created_tick = get_tick_count() - DNS_QUERY_LIFETIME; node.Finish();
    EXPECT_EQ(node.ep.diagnostic->breakdown.failure_end[DNS_END_DEADLINE], 1U);
    EXPECT_EQ(node.ep.diagnostic->breakdown.events[DNS_EVENT_IO_OR_PROTOCOL], 1U);
    EXPECT_EQ(node.ep.diagnostic->detail.events[0].system_error, EHOSTUNREACH);
    EXPECT_EQ(node.ep.fd, -1);
}
TEST(UpstreamEndpointDiagnostics, IdentityIgnoresUnusedUnionBytesAndLoadDiscriminatorButIncludesEgress) {
    ObservedEndpoint node; std::string original = node.ep.diagnostic->base.service_id;
    _dns_endpoint_observer_destroy(&node.ep);
    node.ep.flags.service_config_id = 123;
    reinterpret_cast<unsigned char *>(&node.ep.flags.tls)[sizeof(node.ep.flags.tls) - 1] = 0xa5;
    _dns_endpoint_observer_init(&node.ep); EXPECT_EQ(std::string(node.ep.diagnostic->base.service_id), original);
    _dns_endpoint_observer_destroy(&node.ep); strcpy(node.ep.flags.ifname, "wan-example");
    _dns_endpoint_observer_init(&node.ep); EXPECT_NE(std::string(node.ep.diagnostic->base.service_id), original);
}
TEST(UpstreamEndpointDiagnostics, ExistingCopiedApisResolveOrdinaryEndpointAndKeepLegacySnapshotCounters) {
    ObservedEndpoint node;
    pthread_mutex_init(&client.server_list_lock, nullptr); INIT_LIST_HEAD(&client.dns_server_list);
    list_add_tail(&node.ep.list, &client.dns_server_list);
    node.Observe(); node.Send();
    std::string id = node.ep.diagnostic->base.service_id;
    dns_upstream_service_snapshot_v1 base{}; dns_upstream_service_diagnostics_v1 breakdown{};
    EXPECT_EQ(dns_client_get_service_diagnostics_v1(id.c_str(), &base, &breakdown), 0);
    EXPECT_EQ(base.pool_enabled, 0U); EXPECT_EQ(base.query_count, 1U); EXPECT_EQ(base.in_flight, 1U);
    dns_upstream_service_snapshot_v1 legacy{};
    EXPECT_EQ(dns_client_get_service_snapshot_v1(&legacy, 1), 1);
    EXPECT_EQ(legacy.query_count, 0U); EXPECT_EQ(std::string(legacy.service_id), id);
    dns_upstream_endpoint_activity_v1 activity{};
    EXPECT_EQ(dns_client_get_service_endpoint_activity_v1(id.c_str(), nullptr, 0), 1);
    EXPECT_EQ(dns_client_get_service_endpoint_activity_v1(id.c_str(), &activity, 1), 1);
    EXPECT_EQ(activity.endpoint.attempt_count, 1U); EXPECT_GT(activity.sends_peak_100ms, 0U);
    dns_upstream_policy_snapshot_v1 policy{}; dns_upstream_event_context_snapshot_v1 context{};
    EXPECT_EQ(dns_client_get_service_policy_v1(id.c_str(), &policy), 0);
    EXPECT_EQ(dns_client_get_service_event_context_v1(id.c_str(), &context), 0);
    EXPECT_EQ(policy.path_count, 1U); EXPECT_EQ(std::string(policy.paths[0].ip), "192.0.2.7");
    EXPECT_EQ(dns_client_get_service_endpoint_activity_v1(nullptr, &activity, 1), -1);
    EXPECT_EQ(dns_client_get_service_endpoint_activity_v1(id.c_str(), nullptr, 1), -1);
    list_del_init(&node.ep.list); pthread_mutex_destroy(&client.server_list_lock);
}

static void OrdinaryUdpObserverCase() {
    smartdns::MockServer upstream;
    ASSERT_TRUE(upstream.Start("udp://127.0.0.1:62894", [](smartdns::ServerRequestContext *r) {
        dns_add_domain(r->response_packet, r->domain.c_str(), r->qtype, r->qclass);
        if (r->domain == "positive.example") {
            smartdns::MockServer::AddIP(r, r->domain.c_str(), "192.0.2.94", 60);
        } else {
            dns_soa soa{}; strcpy(soa.mname, "ns.example"); strcpy(soa.rname, "hostmaster.example");
            soa.minimum = 60; dns_add_SOA(r->response_packet, DNS_RRS_NS, "example", 60, &soa);
            if (r->domain == "missing.example") r->response_packet->head.rcode = DNS_RC_NXDOMAIN;
        }
        return smartdns::SERVER_REQUEST_OK;
    }));
    smartdns::Server resolver(smartdns::Server::CREATE_MODE_THREAD);
    ASSERT_TRUE(resolver.Start("bind 127.0.0.1:62794\nserver 127.0.0.1:62894\n"
        "cache-size 0\ncache-persist no\nprefetch-domain no\nserve-expired no\n"
        "dualstack-ip-selection no\nspeed-check-mode none\nresponse-mode fastest-response\n"));
    smartdns::Client query;
    for (const char *name : {"positive.example A", "negative.example AAAA", "missing.example AAAA"}) {
        ASSERT_TRUE(query.Query(std::string(name) + " +time=3 +tries=1", 62794, "127.0.0.1"));
        EXPECT_EQ(query.GetStatus(), std::string(name).find("missing") == 0 ? "NXDOMAIN" : "NOERROR");
        EXPECT_EQ(query.GetAnswerNum(), std::string(name).find("positive") == 0 ? 1 : 0);
    }
    dns_upstream_service_snapshot_v1 legacy{}, base{}; dns_upstream_service_diagnostics_v1 raw{};
    ASSERT_EQ(dns_client_get_service_snapshot_v1(&legacy, 1), 1);
    ASSERT_EQ(strlen(legacy.service_id), 64U);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    do {
        ASSERT_EQ(dns_client_get_service_diagnostics_v1(legacy.service_id, &base, &raw), 0);
        if (base.success_count == 3 && base.in_flight == 0) break;
        poll(nullptr, 0, 5);
    } while (std::chrono::steady_clock::now() < deadline);
    EXPECT_EQ(base.pool_enabled, 0U); EXPECT_EQ(base.query_count, 3U);
    EXPECT_EQ(base.success_count, 3U); EXPECT_EQ(base.failure_count + base.skip_count + base.in_flight, 0U);
    EXPECT_EQ(base.attempt_count, 3U); EXPECT_EQ(raw.events[DNS_EVENT_DNS_REJECTED], 0U);
    dns_upstream_endpoint_activity_v1 node{};
    ASSERT_EQ(dns_client_get_service_endpoint_activity_v1(legacy.service_id, &node, 1), 1);
    EXPECT_EQ(node.endpoint.attempt_count, 3U); EXPECT_EQ(node.endpoint.success_count, 3U);
    EXPECT_EQ(node.http_429 + node.http_503, 0U); EXPECT_GT(node.sends_peak_100ms, 0U);
}

TEST(UpstreamEndpointDiagnostics, RealOrdinaryUdpRecordsPositiveSoaNegativeAndNxDomainThroughExistingApis) {
    // The native server has process-wide configuration globals. Isolate its
    // full lifecycle, as the other in-process server integration fixtures do.
    ASSERT_EXIT({ OrdinaryUdpObserverCase(); _exit(::testing::Test::HasFailure() ? 1 : 0); },
        ::testing::ExitedWithCode(0), "");
}
