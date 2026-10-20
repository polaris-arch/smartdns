/* Offline wire regressions. No sockets, provider queries, or external DNS. */
#include "gtest/gtest.h"
#include "smartdns/dns_any.h"
#include <cstring>
#include <string>
#include <vector>

namespace {
using Wire = std::vector<unsigned char>;
void u16(Wire &v, unsigned int n) { v.push_back(n >> 8); v.push_back(n); }
void u32(Wire &v, unsigned int n) { v.push_back(n >> 24); v.push_back(n >> 16); v.push_back(n >> 8); v.push_back(n); }
void name(Wire &v, const std::string &s)
{
	size_t begin = 0;
	while (begin < s.size()) {
		size_t end = s.find('.', begin); if (end == std::string::npos) end = s.size();
		v.push_back(end - begin); v.insert(v.end(), s.begin() + begin, s.begin() + end); begin = end + 1;
	}
	v.push_back(0);
}
Wire response(int type, int answers, int authority = 0, int additional = 0, int rcode = 0)
{
	Wire v; u16(v, 0x1234); u16(v, 0x81a0 | rcode); u16(v, 1); u16(v, answers); u16(v, authority); u16(v, additional);
	name(v, "unit.test"); u16(v, type); u16(v, DNS_C_IN); return v;
}
void rr(Wire &v, const std::string &owner, int type, unsigned int ttl, const Wire &data, int rrclass = DNS_C_IN)
{
	name(v, owner); u16(v, type); u16(v, rrclass); u32(v, ttl); u16(v, data.size()); v.insert(v.end(), data.begin(), data.end());
}
Wire domain_data(const std::string &target) { Wire v; name(v, target); return v; }
Wire soa_data(unsigned int minimum = 20)
{
	Wire v; name(v, "ns.unit.test"); name(v, "hostmaster.unit.test");
	u32(v, 7); u32(v, 60); u32(v, 60); u32(v, 600); u32(v, minimum); return v;
}
int merge(Wire a, int at, Wire b, int bt, int partial, Wire *result = nullptr)
{
	dns_any_input input[2] = {{a.empty() ? nullptr : a.data(), (int)a.size(), (unsigned short)at, 0},
		{b.empty() ? nullptr : b.data(), (int)b.size(), (unsigned short)bt, 0}};
	unsigned char out[DNS_IN_PACKSIZE];
	int len = dns_any_merge("unit.test", input, 2, partial, out, sizeof(out));
	if (len > 0 && result) result->assign(out, out + len);
	return len;
}
}

TEST(AnyBounded, NamedTypeDoesNotChangeAllSentinel)
{
	EXPECT_EQ(DNS_T_ANY, 255); EXPECT_EQ(DNS_T_ALL, 65535);
	EXPECT_EQ(dns_any_type_from_name("aaaa"), DNS_T_AAAA);
	for (const char *s : {"ANY", "AXFR", "IXFR", "OPT", "255", "TYPE65280", "", "RRSIG"})
		EXPECT_EQ(dns_any_type_from_name(s), -1);
}

TEST(AnyBounded, PlainAddressProofAcceptsOnlyCompleteDirectAnswers)
{
	unsigned char addresses[DNS_ANY_MAX_RECORDS][DNS_RR_AAAA_LEN];
	for (int type : {DNS_T_A, DNS_T_AAAA}) {
		const Wire data(type == DNS_T_A ? 4 : 16, 7);
		for (bool compressed : {false, true}) {
			Wire v = response(type, 1, 0, 1); v[3] = 0x80;
			if (compressed) {
				u16(v, 0xc00c); u16(v, type); u16(v, DNS_C_IN);
				u32(v, 60); u16(v, data.size()); v.insert(v.end(), data.begin(), data.end());
			} else rr(v, "unit.test", type, 60, data);
			rr(v, "", DNS_T_OPT, 0, {}, 1232);
			ASSERT_EQ(dns_any_plain_addresses("unit.test", type, v.data(), v.size(), addresses), 1);
			EXPECT_EQ(std::memcmp(addresses[0], data.data(), data.size()), 0);
		}
	}
	Wire capped = response(DNS_T_A, DNS_ANY_MAX_RECORDS); capped[3] = 0x80;
	for (int i = 0; i < DNS_ANY_MAX_RECORDS; i++)
		rr(capped, "unit.test", DNS_T_A, 60, {1, 2, 3, static_cast<unsigned char>(i)});
	EXPECT_EQ(dns_any_plain_addresses("unit.test", DNS_T_A, capped.data(), capped.size(), addresses),
		DNS_ANY_MAX_RECORDS);
}

TEST(AnyBounded, PlainAddressProofRejectsMalformedOrUnsupportedPackets)
{
	unsigned char addresses[DNS_ANY_MAX_RECORDS][DNS_RR_AAAA_LEN];
	auto direct = [](int answers = 1, int authority = 0, int extra = 0) {
		Wire v = response(DNS_T_A, answers, authority, extra); v[3] = 0x80; return v;
	};
	Wire good = direct(); rr(good, "unit.test", DNS_T_A, 60, {1, 2, 3, 4});
	std::vector<Wire> bad;
	for (int flag : {0x10, 0x20, 0x40, 1}) {
		Wire v = good; v[3] |= flag; bad.push_back(v);
	}
	Wire v = good; v[2] |= 2; bad.push_back(v);
	v = good; v[2] &= ~0x80; bad.push_back(v);
	v = good; v[2] |= 8; bad.push_back(v);
	v = good; v.push_back(0); bad.push_back(v);
	v = good; v.pop_back(); bad.push_back(v);
	bad.emplace_back(good.begin(), good.begin() + 10);
	v = good; v[direct().size() - 1] = 3; bad.push_back(v);
	v = direct(); rr(v, "wrong.test", DNS_T_A, 60, {1, 2, 3, 4}); bad.push_back(v);
	v = direct(); rr(v, "unit.test", DNS_T_A, 60, {1, 2, 3, 4}, 3); bad.push_back(v);
	v = direct(); rr(v, "unit.test", DNS_T_A, 60, {1, 2, 3}); bad.push_back(v);
	v = direct(); rr(v, "unit.test", DNS_T_AAAA, 60, Wire(16, 7)); bad.push_back(v);
	v = direct(); rr(v, "unit.test", DNS_T_CNAME, 60, domain_data("target.test")); bad.push_back(v);
	for (unsigned int ttl : {0U, 0x80000000U}) {
		v = direct(); rr(v, "unit.test", DNS_T_A, ttl, {1, 2, 3, 4}); bad.push_back(v);
	}
	v = direct(0, 0, 1); rr(v, "unit.test", DNS_T_A, 60, {1, 2, 3, 4}); bad.push_back(v);
	v = direct(1, 1); rr(v, "unit.test", DNS_T_A, 60, {1, 2, 3, 4});
	rr(v, "unit.test", DNS_T_SOA, 60, soa_data()); bad.push_back(v);
	v = direct(1, 0, 1); rr(v, "unit.test", DNS_T_A, 60, {1, 2, 3, 4});
	rr(v, "unit.test", DNS_T_A, 60, {1, 2, 3, 5}); bad.push_back(v);
	for (int mode = 0; mode < 4; mode++) {
		v = direct(1, 0, mode == 3 ? 2 : 1); rr(v, "unit.test", DNS_T_A, 60, {1, 2, 3, 4});
		rr(v, mode == 2 ? "not-root.test" : "", DNS_T_OPT, mode == 1 ? DNS_OPT_FLAG_DO : 0,
			mode == 0 ? Wire{0, 8, 0, 0} : Wire{}, 1232);
		if (mode == 3) rr(v, "", DNS_T_OPT, 0, {}, 1232);
		bad.push_back(v);
	}
	for (bool outside : {false, true}) {
		v = direct(); const size_t at = v.size();
		u16(v, 0xc000 | (outside ? 4095 : at)); u16(v, DNS_T_A); u16(v, DNS_C_IN);
		u32(v, 60); u16(v, 4); v.insert(v.end(), {1, 2, 3, 4}); bad.push_back(v);
	}
	v = direct(DNS_ANY_MAX_RECORDS + 1);
	for (int i = 0; i <= DNS_ANY_MAX_RECORDS; i++) rr(v, "unit.test", DNS_T_A, 60, {1, 2, 3, 4});
	bad.push_back(v);
	for (size_t i = 0; i < bad.size(); i++) {
		SCOPED_TRACE(i);
		EXPECT_EQ(dns_any_plain_addresses("unit.test", DNS_T_A, bad[i].data(), bad[i].size(), addresses), -1);
	}
	EXPECT_EQ(dns_any_plain_addresses("wrong.test", DNS_T_A, good.data(), good.size(), addresses), -1);
	EXPECT_EQ(dns_any_plain_addresses("unit.test", DNS_T_AAAA, good.data(), good.size(), addresses), -1);
	v = good; v[12] = 0xc0; v[13] = 12;
	EXPECT_EQ(dns_any_plain_addresses("unit.test", DNS_T_A, v.data(), v.size(), addresses), -1);
}

TEST(AnyBounded, FreshMixedTtlsAndUnknownDataRemainByteExact)
{
	Wire v = response(DNS_T_ANY, 3);
	rr(v, "unit.test", DNS_T_A, 12, {1, 2, 3, 4});
	rr(v, "unit.test", DNS_T_TXT, 70, {2, 'o', 'k'});
	rr(v, "unit.test", 65280, 90, {0xc0, 0x0c, 0xff, 0});
	Wire original = v; unsigned int ttl;
	ASSERT_EQ(dns_any_wire_age(v.data(), v.size(), 0, &ttl), 0);
	EXPECT_EQ(ttl, 12U); EXPECT_EQ(v, original);
	ASSERT_EQ(dns_any_wire_age(v.data(), v.size(), 10, &ttl), 0); EXPECT_EQ(ttl, 2U);
	ASSERT_EQ(dns_any_wire_age(v.data(), v.size(), 1000, &ttl), 0); EXPECT_EQ(ttl, 0U);
}

TEST(AnyBounded, OptFlagsAreNeverAged)
{
	Wire v = response(DNS_T_ANY, 1, 0, 1);
	rr(v, "unit.test", DNS_T_A, 30, {1, 2, 3, 4});
	rr(v, "", DNS_T_OPT, DNS_OPT_FLAG_DO, {}, 1232);
	Wire before = v; unsigned int ttl;
	ASSERT_EQ(dns_any_wire_age(v.data(), v.size(), 20, &ttl), 0); EXPECT_EQ(ttl, 10U);
	EXPECT_TRUE(std::equal(v.end() - 11, v.end(), before.end() - 11));
}

TEST(AnyBounded, AgeOverflowAndTtlZeroCannotExtendCache)
{
	Wire v = response(DNS_T_ANY, 1); rr(v, "unit.test", DNS_T_A, 100, {1, 2, 3, 4});
	unsigned int ttl;
	ASSERT_EQ(dns_any_wire_age(v.data(), v.size(), 0xffffffffU, &ttl), 0); EXPECT_EQ(ttl, 0U);
	ASSERT_EQ(dns_any_wire_age(v.data(), v.size(), 0, &ttl), 0); EXPECT_EQ(ttl, 0U);
}

TEST(AnyBounded, NegativeLifetimeHonorsSoaMinimum)
{
	Wire v = response(DNS_T_ANY, 0, 1, 0, DNS_RC_NXDOMAIN);
	rr(v, "unit.test", DNS_T_SOA, 200, soa_data(20)); unsigned int ttl;
	ASSERT_EQ(dns_any_wire_age(v.data(), v.size(), 5, &ttl), 0); EXPECT_EQ(ttl, 15U);
	ASSERT_EQ(dns_any_wire_age(v.data(), v.size(), 0, &ttl), 0); EXPECT_EQ(ttl, 15U);
	ASSERT_EQ(dns_any_wire_age(v.data(), v.size(), 2, &ttl), 0); EXPECT_EQ(ttl, 13U);
}

TEST(AnyBounded, MinimalHinfoRemainsAnExactAnyAnswer)
{
	Wire v = response(DNS_T_ANY, 1); rr(v, "unit.test", 13, 60, {7, 'R', 'F', 'C', '8', '4', '8', '2', 0});
	Wire original = v; unsigned int ttl;
	EXPECT_EQ(dns_any_wire_age(v.data(), v.size(), 0, &ttl), 0); EXPECT_EQ(ttl, 60U); EXPECT_EQ(v, original);
}

TEST(AnyBounded, MalformedLengthsAndCompressionLoopsFail)
{
	Wire v = response(DNS_T_ANY, 1); rr(v, "unit.test", DNS_T_A, 60, {1, 2, 3, 4});
	v.pop_back(); EXPECT_EQ(dns_any_wire_age(v.data(), v.size(), 0, nullptr), -1);
	v = response(DNS_T_ANY, 0); v[12] = 0xc0; v[13] = 12;
	EXPECT_EQ(dns_any_wire_age(v.data(), v.size(), 0, nullptr), -1);
}

TEST(AnyBounded, MergePreservesBinaryTxtChunksAndClearsAd)
{
	Wire a = response(DNS_T_A, 1); rr(a, "unit.test", DNS_T_A, 15, {1, 2, 3, 4});
	Wire t = response(DNS_T_TXT, 1); Wire chunks{3, 'a', 0, 'b', 2, 'c', 'd'};
	rr(t, "unit.test", DNS_T_TXT, 80, chunks); Wire result;
	ASSERT_GT(merge(a, DNS_T_A, t, DNS_T_TXT, 1, &result), 0);
	EXPECT_EQ(result[3] & 0x20, 0); EXPECT_EQ(result[7], 2);
	EXPECT_TRUE(std::equal(chunks.begin(), chunks.end(), result.end() - chunks.size()));
	unsigned int ttl; ASSERT_EQ(dns_any_wire_age(result.data(), result.size(), 0, &ttl), 0); EXPECT_EQ(ttl, 15U);
}

TEST(AnyBounded, PartialFailureIsExplicitAndAllFailureIsNotNoerror)
{
	Wire a = response(DNS_T_A, 1); rr(a, "unit.test", DNS_T_A, 20, {1, 2, 3, 4});
	EXPECT_GT(merge(a, DNS_T_A, {}, DNS_T_TXT, 1), 0);
	EXPECT_EQ(merge(a, DNS_T_A, {}, DNS_T_TXT, 0), -1);
	EXPECT_EQ(merge({}, DNS_T_A, {}, DNS_T_TXT, 1), -1);
}

TEST(AnyBounded, PositiveAndNxdomainConflictCannotBecomeSubset)
{
	Wire a = response(DNS_T_A, 1); rr(a, "unit.test", DNS_T_A, 20, {1, 2, 3, 4});
	Wire n = response(DNS_T_TXT, 0, 1, 0, DNS_RC_NXDOMAIN); rr(n, "unit.test", DNS_T_SOA, 20, soa_data());
	EXPECT_EQ(merge(a, DNS_T_A, n, DNS_T_TXT, 1), -1);
}

TEST(AnyBounded, ConsistentCnameChainIsRetainedOnce)
{
	Wire a = response(DNS_T_A, 2); rr(a, "unit.test", DNS_T_CNAME, 40, domain_data("target.test")); rr(a, "target.test", DNS_T_A, 20, {1, 2, 3, 4});
	Wire t = response(DNS_T_TXT, 2); rr(t, "unit.test", DNS_T_CNAME, 30, domain_data("target.test")); rr(t, "target.test", DNS_T_TXT, 80, {1, 'x'});
	Wire result; ASSERT_GT(merge(a, DNS_T_A, t, DNS_T_TXT, 1, &result), 0); EXPECT_EQ(result[7], 3);
}

TEST(AnyBounded, ConflictingCnamesAndTerminalNamesFail)
{
	Wire a = response(DNS_T_A, 2); rr(a, "unit.test", DNS_T_CNAME, 40, domain_data("one.test")); rr(a, "one.test", DNS_T_A, 20, {1, 2, 3, 4});
	Wire t = response(DNS_T_TXT, 2); rr(t, "unit.test", DNS_T_CNAME, 30, domain_data("two.test")); rr(t, "two.test", DNS_T_TXT, 80, {1, 'x'});
	EXPECT_EQ(merge(a, DNS_T_A, t, DNS_T_TXT, 1), -1);
}

TEST(AnyBounded, AliasLoopAndIllegalSameOwnerDataFail)
{
	Wire loop = response(DNS_T_A, 2); rr(loop, "unit.test", DNS_T_CNAME, 40, domain_data("unit.test")); rr(loop, "unit.test", DNS_T_A, 20, {1, 2, 3, 4});
	Wire t = response(DNS_T_TXT, 1); rr(t, "unit.test", DNS_T_TXT, 80, {1, 'x'});
	EXPECT_EQ(merge(loop, DNS_T_A, t, DNS_T_TXT, 1), -1);
}

TEST(AnyBounded, CompressedMxTargetIsRelocatedSafely)
{
	Wire m = response(DNS_T_MX, 1); rr(m, "unit.test", DNS_T_MX, 20, {0, 10, 0xc0, 0x0c});
	Wire a = response(DNS_T_A, 1); rr(a, "unit.test", DNS_T_A, 20, {1, 2, 3, 4});
	Wire result; ASSERT_GT(merge(m, DNS_T_MX, a, DNS_T_A, 1, &result), 0);
	unsigned char packet[DNS_PACKSIZE]; EXPECT_EQ(dns_decode((dns_packet *)packet, sizeof(packet), result.data(), result.size()), 0);
}

TEST(AnyBounded, BothNodataRetainSoaAndAnyQuestion)
{
	Wire a = response(DNS_T_A, 0, 1); rr(a, "unit.test", DNS_T_SOA, 200, soa_data());
	Wire t = response(DNS_T_TXT, 0, 1); rr(t, "unit.test", DNS_T_SOA, 200, soa_data());
	Wire result; ASSERT_GT(merge(a, DNS_T_A, t, DNS_T_TXT, 0, &result), 0);
	EXPECT_EQ(result[3] & 15, 0); EXPECT_EQ(result[9], 1);
	unsigned int ttl; ASSERT_EQ(dns_any_wire_age(result.data(), result.size(), 0, &ttl), 0); EXPECT_EQ(ttl, 20U);
}

TEST(AnyBounded, TruncatedChildIsNotSilentlyTreatedAsComplete)
{
	Wire a = response(DNS_T_A, 1); rr(a, "unit.test", DNS_T_A, 20, {1, 2, 3, 4}); a[2] |= 2;
	EXPECT_EQ(merge(a, DNS_T_A, {}, DNS_T_TXT, 1), -1);
}

TEST(AnyBounded, QuestionOnlyTruncationIsWellFormed)
{
	unsigned char wire[512], packet[DNS_PACKSIZE];
	int len = dns_any_empty_response("unit.test", DNS_RC_NOERROR, 1, wire, sizeof(wire));
	ASSERT_GT(len, 0); ASSERT_EQ(dns_decode((dns_packet *)packet, sizeof(packet), wire, len), 0);
	dns_packet *p = (dns_packet *)packet; EXPECT_EQ(p->head.tc, 1); EXPECT_EQ(p->head.ancount, 0); EXPECT_EQ(p->head.ad, 0);
}

TEST(AnyBounded, WrongQuestionAndEcsResponseCannotBeSynthesized)
{
	Wire a = response(DNS_T_AAAA, 1); rr(a, "unit.test", DNS_T_A, 20, {1, 2, 3, 4});
	EXPECT_EQ(merge(a, DNS_T_A, {}, DNS_T_TXT, 1), -1);
	a = response(DNS_T_A, 1, 0, 1); rr(a, "unit.test", DNS_T_A, 20, {1, 2, 3, 4});
	rr(a, "", DNS_T_OPT, 0, {0, 8, 0, 4, 0, 1, 0, 0}, 1232);
	EXPECT_EQ(merge(a, DNS_T_A, {}, DNS_T_TXT, 1), -1);
}

TEST(AnyBounded, OutputByteCapIsARealBound)
{
	Wire a = response(DNS_T_A, 1); rr(a, "unit.test", DNS_T_A, 20, {1, 2, 3, 4});
	dns_any_input input{a.data(), (int)a.size(), DNS_T_A, 0}; unsigned char output[30];
	EXPECT_EQ(dns_any_merge("unit.test", &input, 1, 0, output, sizeof(output)), -1);
}

TEST(AnyBounded, AgreeingNxdomainIsDistinctFromTransportFailure)
{
	Wire a = response(DNS_T_A, 0, 1, 0, DNS_RC_NXDOMAIN); rr(a, "unit.test", DNS_T_SOA, 200, soa_data());
	Wire t = response(DNS_T_TXT, 0, 1, 0, DNS_RC_NXDOMAIN); rr(t, "unit.test", DNS_T_SOA, 200, soa_data());
	Wire result; ASSERT_GT(merge(a, DNS_T_A, t, DNS_T_TXT, 0, &result), 0); EXPECT_EQ(result[3] & 15, DNS_RC_NXDOMAIN);
}

TEST(AnyBounded, AliasDepthIsFinite)
{
	Wire a = response(DNS_T_A, 11); std::string owner = "unit.test";
	for (int i = 0; i < 10; i++) { std::string target = std::to_string(i) + ".test"; rr(a, owner, DNS_T_CNAME, 60, domain_data(target)); owner = target; }
	rr(a, owner, DNS_T_A, 20, {1, 2, 3, 4});
	EXPECT_EQ(merge(a, DNS_T_A, {}, DNS_T_TXT, 1), -1);
}

TEST(AnyBounded, AliasCycleWithoutSameOwnerDataIsRejected)
{
	Wire a = response(DNS_T_A, 2); rr(a, "unit.test", DNS_T_CNAME, 60, domain_data("target.test")); rr(a, "target.test", DNS_T_CNAME, 60, domain_data("unit.test"));
	Wire t = response(DNS_T_TXT, 1); rr(t, "unit.test", DNS_T_TXT, 60, {1, 'x'});
	EXPECT_EQ(merge(a, DNS_T_A, t, DNS_T_TXT, 1), -1);
}

TEST(AnyBounded, UnrelatedNegativeAuthorityIsRejected)
{
	Wire a = response(DNS_T_A, 0, 1); rr(a, "different.test", DNS_T_SOA, 60, soa_data());
	Wire t = response(DNS_T_TXT, 0, 1); rr(t, "different.test", DNS_T_SOA, 60, soa_data());
	EXPECT_EQ(merge(a, DNS_T_A, t, DNS_T_TXT, 1), -1);
}
