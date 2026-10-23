#include "gtest/gtest.h"
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
