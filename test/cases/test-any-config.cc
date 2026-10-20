/* Configuration parser fixtures, no server startup or network access. */
#include "gtest/gtest.h"
#include "dns_conf/any.h"
#include "dns_conf/dns_conf_group.h"
#include <cstddef>
#include <cstring>
#include <string>

/* Existing internal state, declared only for fixture restoration: the public
 * setter deliberately ignores nullptr, so it cannot restore an unset group. */
extern "C" { extern struct dns_conf_group_info *dns_conf_current_group_info; }

class AnyConfig : public ::testing::Test {
protected:
	dns_conf_group group{};
	dns_conf_group_info info{};
	dns_conf_group_info *previous = nullptr;
	void SetUp() override { previous = _config_current_group(); info.rule = &group; _config_set_current_group(&info); }
	void TearDown() override { dns_conf_current_group_info = previous; }
	int parse(int (*fn)(void *, int, char **), const std::string &value, size_t offset = 0) {
		char key[] = "any-option", input[256]; std::strncpy(input, value.c_str(), sizeof(input)); input[sizeof(input) - 1] = 0;
		char *argv[] = {key, input}; return fn((void *)offset, 2, argv);
	}
};
TEST_F(AnyConfig, ModeIsExplicitAndPassthroughIsZero)
{
	EXPECT_EQ(group.any.aggregate, 0); EXPECT_EQ(parse(_config_any_mode, "aggregate"), 0); EXPECT_EQ(group.any.aggregate, 1);
	EXPECT_EQ(parse(_config_any_mode, "all-records"), -1); EXPECT_EQ(parse(_config_any_mode, "passthrough"), 0);
}
TEST_F(AnyConfig, TypeListIsRequiredFiniteAndHasNoMetaTypes)
{
	EXPECT_EQ(group.any.type_count, 0); ASSERT_EQ(parse(_config_any_types, "A,AAAA,MX,TXT,NS,PTR,SRV,CAA"), 0); EXPECT_EQ(group.any.type_count, 8);
	for (const char *value : {"", "A,A", "A,a", "A,", ",A", "ANY", "AXFR", "IXFR", "OPT", "TYPE65280", "A,AAAA,MX,TXT,NS,PTR,SRV,CAA,SOA"})
		EXPECT_EQ(parse(_config_any_types, value), -1) << value;
	EXPECT_EQ(group.any.type_count, 8); /* Rejected changes are atomic. */
}
TEST_F(AnyConfig, NumericBoundsRejectRatherThanClamp)
{
	for (const char *value : {"0", "9", "-1", "1x", "999999999999999999999", ""})
		EXPECT_EQ(parse(_config_any_number, value, offsetof(dns_conf_group, any.concurrency)), -1) << value;
	EXPECT_EQ(parse(_config_any_number, "8", offsetof(dns_conf_group, any.concurrency)), 0);
	EXPECT_EQ(parse(_config_any_number, "65", offsetof(dns_conf_group, any.max_attempts)), -1);
	EXPECT_EQ(parse(_config_any_number, "64", offsetof(dns_conf_group, any.max_attempts)), 0);
	EXPECT_EQ(parse(_config_any_number, "951", offsetof(dns_conf_group, any.timeout_ms)), -1);
	EXPECT_EQ(parse(_config_any_number, "950", offsetof(dns_conf_group, any.timeout_ms)), 0);
}
TEST_F(AnyConfig, PartialRequiresYesOrNo)
{
	EXPECT_EQ(parse(_config_any_partial, "yes"), 0); EXPECT_EQ(group.any.partial, 1);
	EXPECT_EQ(parse(_config_any_partial, "perhaps"), -1); EXPECT_EQ(group.any.partial, 1);
	EXPECT_EQ(parse(_config_any_partial, "no"), 0); EXPECT_EQ(group.any.partial, 0);
}

TEST_F(AnyConfig, AggregateModeWithoutTypeListFailsFinalValidation)
{
	struct dns_conf_rule saved = dns_conf_rule;
	std::memset(&dns_conf_rule, 0, sizeof(dns_conf_rule));
	/* Use the same hlist primitives without C-only ARRAY_SIZE type checks. */
	for (auto &bucket : dns_conf_rule.group) INIT_HLIST_HEAD(&bucket);
	group.group_name = "fixture"; group.any.aggregate = 1; INIT_HLIST_NODE(&group.node);
	/* hash_add with key zero selects bucket zero. Verification scans all buckets. */
	hlist_add_head(&group.node, &dns_conf_rule.group[0]);
	EXPECT_EQ(_config_any_verify(), -1);
	group.any.type_count = 1; group.any.types[0] = DNS_T_A; EXPECT_EQ(_config_any_verify(), 0);
	dns_conf_rule = saved;
}
