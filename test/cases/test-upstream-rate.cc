#include "gtest/gtest.h"
extern "C" {
#include "dns_client/upstream_rate.h"
}

namespace {
void Traffic(dns_rate_controller &r, unsigned qps, unsigned seconds, uint64_t start, bool waiting) {
    for (unsigned second = 0; second < seconds; second++) {
        for (unsigned i = 0; i < qps; i++) {
            uint64_t tick = start + second * 1000 + i * 1000 / qps;
            if (waiting) _dns_rate_demand(&r, tick);
            _dns_rate_sent(&r, tick); _dns_rate_accepted(&r, tick, tick + 5);
        }
    }
}
}
TEST(UpstreamRate, ConfiguredCeilingIsNotAssumedToBeObservedCapacity) {
    dns_rate_controller r{}; _dns_rate_init(&r, 40);
    EXPECT_EQ(r.cap, 40U); EXPECT_EQ(r.current, 20U); EXPECT_EQ(r.known_good, 0U);
    Traffic(r, 4, 45, 10000, false);
    EXPECT_EQ(r.current, 20U); EXPECT_EQ(r.known_good, 0U);
}
TEST(UpstreamRate, OneLateWaveReducesOnlyOnceButNewEpochCanReduceAgain) {
    dns_rate_controller r{}; _dns_rate_init(&r, 20);
    _dns_rate_sent(&r, 10000); _dns_rate_sent(&r, 10050);
    EXPECT_EQ(_dns_rate_rejected(&r, 10000, 10080), 1); EXPECT_EQ(r.current, 10U);
    EXPECT_EQ(_dns_rate_rejected(&r, 10050, 10120), 0); EXPECT_EQ(r.current, 10U);
    EXPECT_EQ(_dns_rate_rejected(&r, 0, 10400), 0); EXPECT_EQ(r.current, 10U);
    _dns_rate_sent(&r, 10500);
    EXPECT_EQ(_dns_rate_rejected(&r, 10500, 10540), 1); EXPECT_EQ(r.current, 5U);
}
TEST(UpstreamRate, NaturalSaturatedCleanTrafficRaisesSlowlyAndUsesKnownGoodAfterProbeRejection) {
    dns_rate_controller r{}; _dns_rate_init(&r, 20);
    _dns_rate_sent(&r, 10000); _dns_rate_rejected(&r, 10000, 10020);
    EXPECT_EQ(r.current, 10U);
    Traffic(r, 10, 25, 11000, true); EXPECT_EQ(r.current, 10U);
    Traffic(r, 10, 10, 36000, true); EXPECT_EQ(r.current, 11U);
    EXPECT_EQ(r.known_good, 10U);
    _dns_rate_sent(&r, 46000); _dns_rate_rejected(&r, 46000, 46020);
    EXPECT_EQ(r.current, 10U);
    EXPECT_EQ(r.probe_cap, 10U);
    Traffic(r, 10, 40, 47000, true);
    EXPECT_EQ(r.current, 10U); // keep serving without repeating the rejected probe
}
TEST(UpstreamRate, UnreturnedResponsesAndStartupBurstDoNotProveSustainableCapacity) {
    dns_rate_controller r{}; _dns_rate_init(&r, 40);
    for (unsigned i = 0; i < 100; i++) { _dns_rate_sent(&r, 10000 + i); _dns_rate_accepted(&r, 10000 + i, 10100 + i); }
    for (unsigned second = 1; second < 45; second++) {
        for (unsigned i = 0; i < 20; i++) { uint64_t tick = 10000 + second * 1000 + i * 50; _dns_rate_demand(&r, tick); _dns_rate_sent(&r, tick); }
        // Most responses are censored/timeout: observing one real success is
        // insufficient to close those windows or invent the other outcomes.
        _dns_rate_accepted(&r, 10000 + second * 1000, 10005 + second * 1000);
    }
    EXPECT_EQ(r.current, 20U); EXPECT_EQ(r.known_good, 0U);
}
TEST(UpstreamRate, DisabledControlAndLowCeilingsRemainBounded) {
    dns_rate_controller r{}; _dns_rate_init(&r, 0);
    EXPECT_EQ(_dns_rate_rejected(&r, 100, 200), 0); EXPECT_EQ(r.current, 0U);
    _dns_rate_init(&r, 1); _dns_rate_rejected(&r, 100, 200);
    EXPECT_EQ(r.current, 1U); EXPECT_EQ(r.cap, 1U);
}
