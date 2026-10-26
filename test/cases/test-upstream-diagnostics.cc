#include "gtest/gtest.h"
#include <cstdlib>
extern "C" {
#include "dns_client/upstream_service.h"
#include "smartdns/util.h"
}

TEST(UpstreamDiagnostics, LoopSeparatesEmptyZeroWaitsReadinessWakeupsAndCpuWindow) {
    dns_client_loop_diagnostics_v1 before{}, after{};
    unsigned long now = get_tick_count();
    _dns_client_loop_diagnostic_start(now);
    ASSERT_EQ(dns_client_get_loop_diagnostics_v1(&before), 0);
    _dns_client_loop_diagnostic_poll(now, 0, 0);
    _dns_client_loop_diagnostic_poll(now, 0, 3);
    _dns_client_loop_diagnostic_poll(now, 100, 0);
    _dns_client_loop_diagnostic_wake(); _dns_client_loop_diagnostic_period();
    _dns_client_loop_diagnostic_poll(now + 1000, 100, 0);
    ASSERT_EQ(dns_client_get_loop_diagnostics_v1(&after), 0);
    EXPECT_EQ(after.version, 1U); EXPECT_EQ(after.struct_size, sizeof(after));
    EXPECT_EQ(after.iterations, 4U); EXPECT_EQ(after.zero_waits, 2U);
    EXPECT_EQ(after.zero_wait_no_events, 1U); EXPECT_EQ(after.ready_events, 3U);
    EXPECT_EQ(after.wakeups, 1U); EXPECT_EQ(after.periodic_runs, 1U);
    if (after.cpu_clock_available) {
        EXPECT_EQ(after.sample_wall_ms, 1000U); EXPECT_GE(after.cpu_total_ns, before.cpu_total_ns);
        EXPECT_EQ(after.sample_cpu_ns, after.cpu_total_ns - before.cpu_total_ns);
    }
    EXPECT_EQ(dns_client_get_loop_diagnostics_v1(nullptr), -1);
    EXPECT_EQ(dns_client_get_service_diagnostics_v1(nullptr, nullptr, nullptr), -1);
}

TEST(UpstreamDiagnostics, EvidenceRingIsBoundedOrderedAndSeparateFromQueryOutcomes) {
    dns_upstream_service service{};dns_server_info endpoint{};
    pthread_mutex_init(&service.detail_lock,nullptr);endpoint.service=&service;endpoint.port=443;
    strcpy(endpoint.ip,"::1");
    for(unsigned i=0;i<40;i++)_dns_service_detail(nullptr,&endpoint,DNS_DETAIL_RESPONSE_TIMEOUT,DNS_PHASE_RESPONSE,0,700+i,700);
    EXPECT_EQ(service.detail.event_count,32U);EXPECT_EQ(service.detail.dropped_events,8U);
    EXPECT_EQ(service.detail.kind_counts[DNS_DETAIL_RESPONSE_TIMEOUT],40U);
    EXPECT_EQ(service.detail.events[0].sequence,40U);EXPECT_EQ(service.detail.events[31].sequence,9U);
    EXPECT_EQ(service.detail.events[0].family,6U);EXPECT_EQ(service.stats.query_count,0U);
    _dns_service_response_time(&endpoint,63);_dns_service_response_time(&endpoint,701);
    EXPECT_EQ(service.detail.response_histogram[3],1U);EXPECT_EQ(service.detail.response_histogram[6],1U);
    _dns_service_detail(nullptr,&endpoint,DNS_DETAIL_DNS_REJECT,DNS_PHASE_RESPONSE,DNS_REJECT_FILTERED,0,0);
    EXPECT_EQ(service.detail.reject_counts[DNS_REJECT_FILTERED],1U);
    EXPECT_EQ(service.detail.kind_counts[DNS_DETAIL_RESPONSE_TIMEOUT],40U);
    std::free(service.failures); std::free(service.event_sources);
    pthread_mutex_destroy(&service.detail_lock);
}

TEST(UpstreamDiagnostics, OtherHttpStatusRetainsActualCodeWithoutInventingSocketFailure) {
    dns_upstream_service s{};dns_server_info ep{};ep.service=&s;
    pthread_mutex_init(&s.detail_lock,nullptr);
    _dns_service_diagnostic_http(nullptr,&ep,403);
    EXPECT_EQ(s.diagnostics.events[DNS_EVENT_HTTP_OTHER],1U);
    EXPECT_EQ(s.detail.event_count,1U);EXPECT_EQ(s.detail.events[0].code,403);
    EXPECT_EQ(s.detail.events[0].phase,DNS_PHASE_RESPONSE);EXPECT_EQ(s.detail.events[0].system_error,0);
    EXPECT_EQ(s.stats.failure_count,0U);std::free(s.failures);std::free(s.event_sources);pthread_mutex_destroy(&s.detail_lock);
}
