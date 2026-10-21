/* Parser-only fixtures: no sockets, DNS lookups, or server startup. */
#include "gtest/gtest.h"
#include "dns_conf/server.h"
#include "dns_conf/dns_conf_group.h"
#include <cstring>
#include <iterator>
#include <string>
#include <vector>

extern "C" { extern struct dns_conf_group_info *dns_conf_current_group_info; }

class UpstreamRoundRobinConfig : public ::testing::Test {
protected:
    std::vector<dns_servers> previous_servers;
    int previous_count = 0;
    dns_conf_group_info *previous_group = nullptr;
    void SetUp() override {
        previous_servers.assign(std::begin(dns_conf.servers), std::end(dns_conf.servers));
        previous_count = dns_conf.server_num;
        previous_group = dns_conf_current_group_info;
        dns_conf_current_group_info = nullptr;
        dns_conf.server_num = 0;
        std::memset(dns_conf.servers, 0, sizeof(dns_conf.servers));
    }
    void TearDown() override {
        std::memcpy(dns_conf.servers, previous_servers.data(), sizeof(dns_conf.servers));
        dns_conf.server_num = previous_count;
        dns_conf_current_group_info = previous_group;
    }
    int Parse(std::initializer_list<const char *> options) {
        // Failed parses do not advance server_num; discard that uncommitted slot.
        std::memset(&dns_conf.servers[dns_conf.server_num], 0, sizeof(dns_servers));
        std::vector<std::string> words{"server", "127.0.0.1"};
        for (const auto *option : options) words.emplace_back(option);
        std::vector<char *> argv;
        for (auto &word : words) argv.push_back(&word[0]);
        argv.push_back(nullptr);
        return _config_server_udp(nullptr, static_cast<int>(words.size()), argv.data());
    }
};

TEST_F(UpstreamRoundRobinConfig, LegacyAndQuotaOnlyRemainDisabled) {
    ASSERT_EQ(Parse({}), 0);
    EXPECT_EQ(dns_conf.servers[0].upstream_round_robin, 0U);
    EXPECT_EQ(dns_conf.servers[0].max_upstream_connections, 0U);
    ASSERT_EQ(Parse({"-quota-group", "legacy", "-max-query-rate", "7", "-query-burst", "3"}), 0);
    EXPECT_EQ(dns_conf.servers[1].upstream_round_robin, 0U);
    EXPECT_EQ(dns_conf.servers[1].max_upstream_connections, 0U);
}

TEST_F(UpstreamRoundRobinConfig, ExplicitOptInRequiresNamedLogicalService) {
    EXPECT_EQ(Parse({"-upstream-round-robin"}), -1);
    EXPECT_EQ(Parse({"-upstream-round-robin", "-quota-group", ""}), -1);
    EXPECT_EQ(dns_conf.server_num, 0);
    ASSERT_EQ(Parse({"-upstream-round-robin", "-quota-group", "rr"}), 0);
    EXPECT_EQ(dns_conf.servers[0].upstream_round_robin, 1U);
    EXPECT_EQ(dns_conf.servers[0].max_upstream_connections, 2U);
}

TEST_F(UpstreamRoundRobinConfig, ConnectionLimitRequiresOptInAndRejectsInvalidValues) {
    EXPECT_EQ(Parse({"-quota-group", "rr", "-max-upstream-connections", "2"}), -1);
    EXPECT_EQ(Parse({"-upstream-round-robin", "-quota-group", "rr", "-max-upstream-connections"}), -1);
    EXPECT_EQ(Parse({"-upstream-round-robin=yes", "-quota-group", "rr"}), -1);
    for (const char *value : {"", "0", "5", "-1", "+2", "2x", " 2", "999999999999999999999"}) {
        EXPECT_EQ(Parse({"-upstream-round-robin", "-quota-group", "rr",
                         "-max-upstream-connections", value}), -1) << value;
    }
    EXPECT_EQ(dns_conf.server_num, 0);
    for (const char *value : {"1", "2", "3", "4"}) {
        std::string service = std::string("rr-") + value;
        ASSERT_EQ(Parse({"-max-upstream-connections", value, "-quota-group", service.c_str(),
                         "-upstream-round-robin"}), 0);
        EXPECT_EQ(dns_conf.servers[dns_conf.server_num - 1].max_upstream_connections,
                  static_cast<unsigned>(value[0] - '0'));
    }
}

TEST_F(UpstreamRoundRobinConfig, SharedServiceMustAgreeOnModeLimitRateAndBurst) {
    ASSERT_EQ(Parse({"-upstream-round-robin", "-quota-group", "rr", "-max-query-rate", "7",
                     "-query-burst", "3"}), 0);
    ASSERT_EQ(Parse({"-upstream-round-robin", "-quota-group", "rr", "-max-query-rate", "7",
                     "-query-burst", "3", "-max-upstream-connections", "2"}), 0);
    EXPECT_EQ(Parse({"-quota-group", "rr", "-max-query-rate", "7", "-query-burst", "3"}), -1);
    EXPECT_EQ(Parse({"-upstream-round-robin", "-quota-group", "rr", "-max-query-rate", "7",
                     "-query-burst", "3", "-max-upstream-connections", "4"}), -1);
    EXPECT_EQ(Parse({"-upstream-round-robin", "-quota-group", "rr", "-max-query-rate", "8",
                     "-query-burst", "3"}), -1);
    EXPECT_EQ(Parse({"-upstream-round-robin", "-quota-group", "rr", "-max-query-rate", "7",
                     "-query-burst", "4"}), -1);
    EXPECT_EQ(dns_conf.server_num, 2);
}

TEST_F(UpstreamRoundRobinConfig, ExistingBudgetGroupCannotSilentlyBecomeRoundRobin) {
    ASSERT_EQ(Parse({"-quota-group", "legacy"}), 0);
    EXPECT_EQ(Parse({"-quota-group", "legacy", "-upstream-round-robin"}), -1);
    EXPECT_EQ(dns_conf.server_num, 1);
}
