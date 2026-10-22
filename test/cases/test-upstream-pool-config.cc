/* Bounded parser correctness only; no sockets, public DNS or performance tests. */
#include "gtest/gtest.h"
extern "C" {
#include "dns_conf/server.h"
#include "dns_conf/dns_conf_group.h"
extern struct dns_conf_group_info *dns_conf_current_group_info;
int dns_conf_pool_normalize_for_test(void);
}
#include <cstring>
#include <memory>
#include <string>
#include <vector>

class UpstreamPoolConfig : public ::testing::Test {
protected:
    std::vector<unsigned char> saved;
    dns_conf_group_info *previous = nullptr;
    struct dns_group_table saved_groups{};
    void SetUp() override {
        saved.resize(sizeof(dns_conf)); std::memcpy(saved.data(), &dns_conf, sizeof(dns_conf));
        std::memset(&dns_conf, 0, sizeof(dns_conf));
        previous = dns_conf_current_group_info; dns_conf_current_group_info = nullptr;
        saved_groups = dns_group_table; std::memset(&dns_group_table, 0, sizeof(dns_group_table));
    }
    void TearDown() override {
        dns_conf_current_group_info = previous;
        dns_group_table = saved_groups;
        std::memcpy(&dns_conf, saved.data(), sizeof(dns_conf));
    }
    int parse(std::vector<std::string> args) {
        std::vector<char *> argv;
        for (auto &arg : args) argv.push_back(&arg[0]);
        argv.push_back(nullptr);
        return _config_server_https(nullptr, args.size(), argv.data());
    }
    void reset() { std::memset(&dns_conf, 0, sizeof(dns_conf)); }
};

TEST_F(UpstreamPoolConfig, ExplicitOptInRetainsAuthorityAndActualList) {
    ASSERT_EQ(parse({"server-https", "https://resolver.example/dns-query", "-host-ip",
        "192.0.2.1,192.0.2.2,2001:db8::1", "-upstream-ip-pool"}), 0);
    const auto &s = dns_conf.servers[0];
    EXPECT_EQ(s.upstream_ip_pool, 1U); EXPECT_EQ(s.max_upstream_backends, 4U);
    EXPECT_EQ(s.max_upstream_connections, 0U); EXPECT_EQ(s.pool_ip_count, 3U);
    EXPECT_STREQ(s.server, "resolver.example"); EXPECT_STREQ(s.authority, "resolver.example");
    EXPECT_STREQ(s.hostname, "resolver.example"); EXPECT_STREQ(s.tls_host_verify, "resolver.example");
    EXPECT_STREQ(s.path, "/dns-query"); EXPECT_STREQ(s.quota_group, "");
}
TEST_F(UpstreamPoolConfig, CanonicalDedupPreservesFirstOccurrenceOrder) {
    ASSERT_EQ(parse({"server-https", "https://resolver.example/", "-upstream-ip-pool", "-host-ip",
        "192.0.2.1,::ffff:192.0.2.1,2001:0db8:0:0::1,2001:db8::1,127.0.0.1,::1"}), 0);
    auto &s = dns_conf.servers[0]; ASSERT_EQ(s.pool_ip_count, 4U);
    EXPECT_STREQ(s.pool_ips[0], "192.0.2.1"); EXPECT_STREQ(s.pool_ips[1], "2001:db8::1");
    EXPECT_STREQ(s.pool_ips[2], "127.0.0.1"); EXPECT_STREQ(s.pool_ips[3], "::1");
}
TEST_F(UpstreamPoolConfig, ConfiguredCapDoesNotDiscardStaticCandidates) {
    ASSERT_EQ(parse({"server-https", "https://resolver.example/", "-upstream-ip-pool", "-host-ip",
        "192.0.2.1,192.0.2.2,192.0.2.3", "-max-upstream-backends", "2"}), 0);
    EXPECT_EQ(dns_conf.servers[0].pool_ip_count, 3U);
    EXPECT_EQ(dns_conf.servers[0].max_upstream_backends, 2U);
    reset();
    ASSERT_EQ(parse({"server-https", "https://resolver.example/", "-upstream-ip-pool",
        "-max-upstream-backends", "64", "-max-upstream-connections", "8"}), 0);
    EXPECT_EQ(dns_conf.servers[0].max_upstream_connections, 8U);
}
TEST_F(UpstreamPoolConfig, StrictListErrorsAndForbiddenAddresses) {
    for (const char *value : {"", ",192.0.2.1", "192.0.2.1,", "192.0.2.1,,192.0.2.2", "host.example",
        "[2001:db8::1]", "fe80::1%eth0", "192.0.2.1:53", " 192.0.2.1", "0.0.0.0", "::",
        "224.0.0.1", "ff02::1", "::ffff:224.0.0.1", "255.255.255.255"}) {
        reset(); EXPECT_EQ(parse({"server-https", "https://resolver.example/", "-upstream-ip-pool", "-host-ip", value}), -1) << value;
    }
    std::string too_many;
    for (int i = 1; i <= 65; i++) { if (i > 1) too_many += ','; too_many += "192.0.2." + std::to_string(i); }
    reset(); EXPECT_EQ(parse({"server-https", "https://resolver.example/", "-upstream-ip-pool", "-host-ip", too_many}), -1);
}
TEST_F(UpstreamPoolConfig, RejectsInvalidCapsAndConflictingModes) {
    for (const char *value : {"0", "65", "-1", "+1", "1x", "", "99999999999999999999"}) {
        reset(); EXPECT_EQ(parse({"server-https", "https://resolver.example/", "-upstream-ip-pool", "-max-upstream-backends", value}), -1) << value;
    }
    reset(); EXPECT_EQ(parse({"server-https", "https://resolver.example/", "-upstream-ip-pool", "-max-upstream-connections", "5"}), -1);
    reset(); EXPECT_EQ(parse({"server-https", "https://192.0.2.1/", "-upstream-ip-pool"}), -1);
    reset(); EXPECT_EQ(parse({"server-https", "https://resolver.example/", "-upstream-ip-pool", "-bootstrap-dns"}), -1);
    reset(); EXPECT_EQ(parse({"server-https", "https://resolver.example/", "-upstream-ip-pool", "-upstream-round-robin", "-quota-group", "provider"}), -1);
    reset(); EXPECT_EQ(parse({"server-https", "https://resolver.example/", "-upstream-ip-pool", "-host-ip", "192.0.2.1", "-host-ip", "192.0.2.2"}), -1);
}
TEST_F(UpstreamPoolConfig, OffModeDoesNotEnableOrAcceptLists) {
    ASSERT_EQ(parse({"server-https", "https://resolver.example/", "-host-ip", "192.0.2.1"}), 0);
    EXPECT_EQ(dns_conf.servers[0].upstream_ip_pool, 0U);
    EXPECT_STREQ(dns_conf.servers[0].server, "192.0.2.1"); EXPECT_STREQ(dns_conf.servers[0].authority, "resolver.example");
    reset(); EXPECT_EQ(parse({"server-https", "https://resolver.example/", "-host-ip", "192.0.2.1,192.0.2.2"}), -1);
    reset(); EXPECT_EQ(parse({"server-https", "https://resolver.example/", "-max-upstream-backends", "4"}), -1);
}
TEST_F(UpstreamPoolConfig, QuotaGroupSharesRateButNotPoolPhysicalCap) {
    ASSERT_EQ(parse({"server-https", "https://one.example/", "-upstream-ip-pool", "-quota-group", "provider",
        "-max-query-rate", "10", "-max-upstream-connections", "1"}), 0);
    ASSERT_EQ(parse({"server-https", "https://two.example/", "-upstream-ip-pool", "-quota-group", "provider",
        "-max-query-rate", "10", "-max-upstream-connections", "2"}), 0);
    EXPECT_EQ(parse({"server-https", "https://three.example/", "-upstream-ip-pool", "-quota-group", "provider",
        "-max-query-rate", "11"}), -1);
}
TEST_F(UpstreamPoolConfig, MalformedNewOptionsCannotSilentlyBecomeDefaults) {
    for (const auto &tail : std::vector<std::vector<std::string>>{
        {"-upstream-ip-pool=yes"}, {"-upstream-ip-pool", "-max-upstream-backends"},
        {"-upstream-ip-pool", "-max-upstream-connections"}, {"-upstream-ip-pool", "-host-ip"}}) {
        reset(); std::vector<std::string> args{"server-https", "https://resolver.example/"};
        args.insert(args.end(), tail.begin(), tail.end()); EXPECT_EQ(parse(args), -1);
    }
}
TEST_F(UpstreamPoolConfig, ExplicitListCanReachSafeBoundWithoutFixedTwoOrFour) {
    std::string ips;
    for (int i = 1; i <= 64; i++) { if (i > 1) ips += ','; ips += "192.0.2." + std::to_string(i); }
    ASSERT_EQ(parse({"server-https", "https://resolver.example/", "-host-ip", ips,
        "-max-upstream-backends", "64", "-max-upstream-connections", "64", "-upstream-ip-pool"}), 0);
    EXPECT_EQ(dns_conf.servers[0].pool_ip_count, 64U); EXPECT_EQ(dns_conf.servers[0].max_upstream_backends, 64U);
    EXPECT_EQ(dns_conf.servers[0].max_upstream_connections, 64U);
}
TEST_F(UpstreamPoolConfig, LegacyRrNormalizesIntoExactlyOneServiceWithoutInventingRate) {
    for (const char *ip : {"192.0.2.1", "192.0.2.2", "192.0.2.1"})
        ASSERT_EQ(parse({"server-https", "https://resolver.example/dns-query", "-host-ip", ip,
            "-upstream-round-robin", "-quota-group", "provider"}), 0);
    ASSERT_EQ(dns_conf_pool_normalize_for_test(), 0);
    const auto &s = dns_conf.servers[0];
    EXPECT_EQ(s.upstream_ip_pool, 1U); EXPECT_EQ(s.upstream_round_robin, 0U);
    EXPECT_EQ(s.pool_ip_count, 2U); EXPECT_EQ(s.max_upstream_backends, 2U);
    EXPECT_EQ(s.max_upstream_connections, 2U); EXPECT_EQ(s.max_query_rate, 0U); EXPECT_EQ(s.query_burst, 0U);
    EXPECT_STREQ(s.server, "resolver.example"); EXPECT_STREQ(s.quota_group, "provider");
    EXPECT_EQ(dns_conf.servers[1].pool_compat_skip, 1U); EXPECT_EQ(dns_conf.servers[2].pool_compat_skip, 1U);
    EXPECT_EQ(dns_conf.server_num, 3); // stable original entries, but one runtime service
    EXPECT_EQ(dns_conf_pool_normalize_for_test(), 0); // normalization is idempotent
}
TEST_F(UpstreamPoolConfig, LegacyRrMismatchFailsBeforeAnyMutation) {
    ASSERT_EQ(parse({"server-https", "https://resolver.example/dns-query", "-host-ip", "192.0.2.1",
        "-upstream-round-robin", "-quota-group", "provider"}), 0);
    ASSERT_EQ(parse({"server-https", "https://resolver.example/other", "-host-ip", "192.0.2.2",
        "-upstream-round-robin", "-quota-group", "provider"}), 0);
    EXPECT_EQ(dns_conf_pool_normalize_for_test(), -1);
    EXPECT_EQ(dns_conf.servers[0].upstream_ip_pool, 0U); EXPECT_EQ(dns_conf.servers[0].upstream_round_robin, 1U);
    EXPECT_STREQ(dns_conf.servers[0].server, "192.0.2.1"); EXPECT_EQ(dns_conf.servers[1].pool_compat_skip, 0U);
}
TEST_F(UpstreamPoolConfig, LegacyEndpointConcurrencyRequiresExplicitMigration) {
    ASSERT_EQ(parse({"server-https", "https://resolver.example/", "-host-ip", "192.0.2.1",
        "-upstream-round-robin", "-quota-group", "provider", "-max-concurrent-queries", "3"}), 0);
    EXPECT_EQ(dns_conf_pool_normalize_for_test(), -1);
}
TEST_F(UpstreamPoolConfig, LegacyDifferentGroupIntersectionsCannotBeCollapsed) {
    for (const char *ip : {"192.0.2.1", "192.0.2.2"})
        ASSERT_EQ(parse({"server-https", "https://resolver.example/", "-host-ip", ip,
            "-upstream-round-robin", "-quota-group", "provider"}), 0);
    dns_server_groups group{}; std::strcpy(group.group_name, "subset");
    group.server_num = 1; group.servers[0] = &dns_conf.servers[0];
    INIT_HLIST_NODE(&group.node); hlist_add_head(&group.node, &dns_group_table.group[0]);
    EXPECT_EQ(dns_conf_pool_normalize_for_test(), -1);
    hlist_del_init(&group.node);
}
TEST_F(UpstreamPoolConfig, LegacyIdenticalGroupSetsKeepPointersAndQuotaValues) {
    for (const char *ip : {"192.0.2.1", "192.0.2.2", "192.0.2.3"})
        ASSERT_EQ(parse({"server-https", "https://resolver.example/", "-host-ip", ip,
            "-upstream-round-robin", "-quota-group", "provider", "-max-query-rate", "12",
            "-query-burst", "3", "-max-upstream-connections", "1"}), 0);
    dns_server_groups group{}; std::strcpy(group.group_name, "same"); group.server_num = 3;
    for (int i = 0; i < 3; i++) group.servers[i] = &dns_conf.servers[i];
    INIT_HLIST_NODE(&group.node); hlist_add_head(&group.node, &dns_group_table.group[0]);
    ASSERT_EQ(dns_conf_pool_normalize_for_test(), 0);
    EXPECT_EQ(dns_conf.servers[0].max_upstream_backends, 3U);
    EXPECT_EQ(dns_conf.servers[0].max_upstream_connections, 1U);
    EXPECT_EQ(dns_conf.servers[0].max_query_rate, 12U); EXPECT_EQ(dns_conf.servers[0].query_burst, 3U);
    EXPECT_EQ(group.servers[0], &dns_conf.servers[0]); EXPECT_EQ(group.servers[1], &dns_conf.servers[1]);
    hlist_del_init(&group.node);
}
