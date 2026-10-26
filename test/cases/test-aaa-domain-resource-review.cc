/* Synthetic, offline reproduction against unmodified upstream production code.
 * No WAN, QPS, PTR policy, WebUI, cache history or private configuration. */
#include "gtest/gtest.h"
#include "include/utils.h"
#include <cstdio>
#include <iostream>
#include <set>
#include <string>
#include <time.h>
#include <unistd.h>
#ifdef __GLIBC__
#include <malloc.h>
#endif
#include "dns_conf/domain_rule.h"
#include "dns_conf/dns_conf_group.h"
extern "C" { extern struct dns_conf_group_info *dns_conf_current_group_info; }

namespace {
long long CpuNs()
{
	struct timespec value{};
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &value);
	return value.tv_sec * 1000000000LL + value.tv_nsec;
}
long RssKiB()
{
	long size = 0, resident = 0;
	FILE *file = fopen("/proc/self/statm", "r");
	if (!file) return -1;
	int count = fscanf(file, "%ld %ld", &size, &resident);
	fclose(file);
	return count == 2 ? resident * sysconf(_SC_PAGESIZE) / 1024 : -1;
}
size_t HeapBytes()
{
#if defined(__GLIBC__) && __GLIBC_PREREQ(2, 33)
	return mallinfo2().uordblks;
#else
	return 0;
#endif
}
void Measure()
{
	dns_conf_group group{};
	dns_conf_group_info info{};
	info.rule = &group;
	art_tree_init(&group.domain_rule.tree);
	_config_set_current_group(&info);
	char name[80];
	const long rss = RssKiB();
	const size_t heap = HeapBytes();
	const long long start = CpuNs();
	for (unsigned i = 0; i < 100000; i++) {
		snprintf(name, sizeof(name), "block%06u.example", i);
		if (_config_domain_rule_flag_set(name, DOMAIN_FLAG_ADDR_SOA, 0) != 0) _exit(2);
	}
	const long long load = CpuNs() - start;
	const long rss_after = RssKiB();
	const size_t heap_after = HeapBytes();
	std::set<const void *> unique;
	for (unsigned i = 0; i < 100000; i++) {
		snprintf(name, sizeof(name), "block%06u.example", i);
		auto flags = static_cast<dns_rule_flags *>(dns_conf_get_domain_rule(name, DOMAIN_RULE_FLAGS));
		if (!flags || flags->flags != DOMAIN_FLAG_ADDR_SOA) _exit(3);
		unique.insert(flags);
	}
	const long long lookup_start = CpuNs();
	for (unsigned i = 0; i < 1000000; i++) {
		snprintf(name, sizeof(name), "block%06u.example", i % 100000);
		if (!dns_conf_get_domain_rule(name, DOMAIN_RULE_FLAGS)) _exit(4);
	}
	std::cout << "RESOURCE_MEASURE rules=100000 unique_flags=" << unique.size()
		<< " rss_delta_kib=" << rss_after - rss << " heap_delta_bytes=" << heap_after - heap
		<< " load_cpu_ns=" << load << " lookup_cpu_ns=" << CpuNs() - lookup_start << std::endl;
}
void CheckInheritance()
{
	smartdns::TempFile file;
	if (!file.Write("bind 127.0.0.1:60053\nserver 127.0.0.1:61053\naddress /blocked.example/#\n"
		"group-begin child -inherit default\ngroup-end\n")) _exit(2);
	if (dns_server_load_conf(file.GetPath().c_str()) != 0) _exit(3);
	dns_conf_group_info parent_info{};
	parent_info.rule = dns_server_get_default_rule_group();
	if (!parent_info.rule) _exit(8);
	_config_set_current_group(&parent_info);
	auto initial = static_cast<dns_rule_flags *>(dns_conf_get_domain_rule("blocked.example", DOMAIN_RULE_FLAGS));
	if (!initial || !(initial->flags & DOMAIN_FLAG_ADDR_SOA)) _exit(9);
	dns_conf_group_info child{};
	child.rule = dns_server_get_rule_group("child");
	if (!child.rule) _exit(4);
	_config_set_current_group(&child);
	if (_config_domain_rule_flag_set("blocked.example", DOMAIN_FLAG_ADDR_SOA, 1) != 0) _exit(5);
	auto changed = static_cast<dns_rule_flags *>(dns_conf_get_domain_rule("blocked.example", DOMAIN_RULE_FLAGS));
	if (!changed || (changed->flags & DOMAIN_FLAG_ADDR_SOA)) _exit(6);
	_config_set_current_group(&parent_info);
	auto parent = static_cast<dns_rule_flags *>(dns_conf_get_domain_rule("blocked.example", DOMAIN_RULE_FLAGS));
	std::cerr << "INHERITED_PARENT_FLAGS=" << (parent ? parent->flags : 0) << std::endl;
	const bool preserved = parent && (parent->flags & DOMAIN_FLAG_ADDR_SOA);
	dns_server_load_exit();
	_exit(preserved ? 0 : 7);
}
}

TEST(DomainRuleResourceReview, AIndependentOfficialAllocationMeasurements)
{
	for (int i = 0; i < 3; i++) ASSERT_EXIT({ Measure(); _exit(0); }, ::testing::ExitedWithCode(0), "");
}
TEST(DomainRuleResourceReview, BInheritedValueChangeMustPreserveParent)
{
	ASSERT_EXIT(CheckInheritance(), ::testing::ExitedWithCode(0), "");
}
