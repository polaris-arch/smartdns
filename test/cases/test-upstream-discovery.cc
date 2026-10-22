/* Bounded, virtual-clock correctness tests. No network or performance workloads. */
#include "gtest/gtest.h"
extern "C" {
#include "dns_client/upstream_discovery.h"
}
#include <arpa/inet.h>
#include <cstring>
#include <string>
#include <vector>

namespace {
struct Packet {
    alignas(dns_packet) unsigned char data[DNS_PACKSIZE]{};
    dns_packet *p = reinterpret_cast<dns_packet *>(data);
    Packet(int qtype = DNS_T_A, const char *name = "resolver.example", int rcode = DNS_RC_NOERROR) {
        dns_head h{}; h.qr = DNS_OP_IQUERY; h.rcode = rcode;
        EXPECT_EQ(dns_packet_init(p, sizeof(data), &h), 0);
        EXPECT_EQ(dns_add_domain(p, name, qtype, 1), 0);
    }
    void address(const char *ip, int ttl = 60, const char *owner = "resolver.example", dns_rr_type section = DNS_RRS_AN) {
        unsigned char a[16]{};
        if (inet_pton(AF_INET, ip, a) == 1) EXPECT_EQ(dns_add_A(p, section, owner, ttl, a), 0);
        else { ASSERT_EQ(inet_pton(AF_INET6, ip, a), 1); EXPECT_EQ(dns_add_AAAA(p, section, owner, ttl, a), 0); }
    }
    void negative(int ttl = 300, unsigned minimum = 30, const char *zone = "example") {
        dns_soa soa{}; strcpy(soa.mname, "ns.example"); strcpy(soa.rname, "hostmaster.example"); soa.minimum = minimum;
        EXPECT_EQ(dns_add_SOA(p, DNS_RRS_NS, zone, ttl, &soa), 0);
    }
};
struct Discovery {
    dns_upstream_discovery *d;
    dns_discovery_snapshot last{};
    unsigned callbacks = 0;
    Discovery() {
        d = _dns_discovery_create("resolver.example", Receive, this); EXPECT_NE(d, nullptr); }
    ~Discovery() { if (d) _dns_discovery_destroy(d); }
    static void Receive(const dns_discovery_snapshot *s, void *u) {
        auto *self = static_cast<Discovery *>(u); self->last = *s; self->callbacks++;
    }
    void begin(unsigned long now = 1000) { ASSERT_EQ(_dns_discovery_test_begin(d, now), 0); }
    void answer(Packet &p, int type = DNS_T_A, unsigned long now = 1000) { _dns_discovery_test_answer(d, type, p.p, now); }
    void failure(int type, unsigned long now = 1000) { _dns_discovery_test_failure(d, type, now); }
    void seed() {
        begin(); Packet a; a.address("8.8.8.8", 10); answer(a); failure(DNS_T_AAAA);
        ASSERT_EQ(last.count, 1u);
    }
};
}
TEST(UpstreamDiscovery, CompleteRrsetAndCanonicalDedup) {
    Discovery d; d.begin(); Packet a; a.address("8.8.8.8"); a.address("1.1.1.1"); a.address("8.8.8.8", 30);
    Packet aaaa(DNS_T_AAAA); aaaa.address("2001:4860:4860::8888");
    d.answer(a); d.answer(aaaa, DNS_T_AAAA);
    ASSERT_EQ(d.last.count, 3u); EXPECT_EQ(d.last.discovered, 4u); EXPECT_EQ(d.last.expires, 31000u);
}
TEST(UpstreamDiscovery, IgnoreUnrelatedOwnerAndAdditionalRecords) {
    Discovery d; d.begin(); Packet a; a.address("8.8.8.8", 30, "attacker.example");
    a.address("1.1.1.1", 30, "resolver.example", DNS_RRS_NR);
    d.answer(a); d.failure(DNS_T_AAAA); EXPECT_EQ(d.last.count, 0u);
}
TEST(UpstreamDiscovery, CnameChainUsesMinimumTtl) {
    Discovery d; d.begin(); Packet a;
    ASSERT_EQ(dns_add_CNAME(a.p, DNS_RRS_AN, "resolver.example", 4, "edge.example"), 0);
    a.address("8.8.8.8", 60, "edge.example"); d.answer(a); d.failure(DNS_T_AAAA);
    ASSERT_EQ(d.last.count, 1u); EXPECT_EQ(d.last.expires, 5000u);
}
TEST(UpstreamDiscovery, CnameFollowupCarriesChainTtlAndRejectsCycles) {
    Discovery d; d.begin(); Packet a;
    dns_add_CNAME(a.p, DNS_RRS_AN, "resolver.example", 3, "edge.example"); d.answer(a);
    Packet b(DNS_T_A, "edge.example"); b.address("1.1.1.1", 60, "edge.example");
    d.answer(b); d.failure(DNS_T_AAAA); ASSERT_EQ(d.last.count, 1u); EXPECT_EQ(d.last.expires, 4000u);
    d.begin(2000); Packet cycle; dns_add_CNAME(cycle.p, DNS_RRS_AN, "resolver.example", 60, "x.example");
    dns_add_CNAME(cycle.p, DNS_RRS_AN, "x.example", 60, "resolver.example");
    d.answer(cycle, DNS_T_A, 2000); d.failure(DNS_T_AAAA, 2000);
    EXPECT_EQ(d.last.count, 1u); EXPECT_EQ(d.last.expires, 4000u); // no renewed TTL
}
TEST(UpstreamDiscovery, RejectOnlyUnusableUnicastTargets) {
    for (const char *ip : {"0.0.0.0", "255.255.255.255", "224.0.0.1", "239.255.255.255", "169.254.1.1"}) {
        unsigned char a[16]{}; ASSERT_EQ(inet_pton(AF_INET, ip, a), 1);
        EXPECT_FALSE(_dns_discovery_address_allowed(AF_INET, a)) << ip;
    }
    for (const char *ip : {"::", "fe80::1", "febf::1", "ff02::1", "::ffff:0.0.0.0", "::ffff:224.0.0.1", "::ffff:255.255.255.255"}) {
        unsigned char a[16]{}; ASSERT_EQ(inet_pton(AF_INET6, ip, a), 1);
        EXPECT_FALSE(_dns_discovery_address_allowed(AF_INET6, a)) << ip;
    }
    for (const char *ip : {"10.1.2.3", "172.16.1.1", "192.168.1.1", "100.64.0.1", "127.0.0.1", "192.0.2.1", "8.8.8.8"}) {
        unsigned char a[16]{}; ASSERT_EQ(inet_pton(AF_INET, ip, a), 1);
        EXPECT_TRUE(_dns_discovery_address_allowed(AF_INET, a)) << ip;
    }
    for (const char *ip : {"::1", "fc00::1", "fd00::1", "::ffff:10.1.2.3", "2001:db8::1", "2001:4860:4860::8888"}) {
        unsigned char a[16]{}; ASSERT_EQ(inet_pton(AF_INET6, ip, a), 1);
        EXPECT_TRUE(_dns_discovery_address_allowed(AF_INET6, a)) << ip;
    }
}
TEST(UpstreamDiscovery, MappedPublicV6DeduplicatesWithA) {
    Discovery d; d.begin(); Packet a; a.address("8.8.8.8"); Packet b(DNS_T_AAAA); b.address("::ffff:8.8.8.8");
    d.answer(a); d.answer(b, DNS_T_AAAA); ASSERT_EQ(d.last.count, 1u); EXPECT_EQ(d.last.addresses[0].family, AF_INET);
}
TEST(UpstreamDiscovery, NegativeRevokesImmediatelyNotAtNegativeTtl) {
    Discovery d; d.seed(); d.begin(2000); Packet a; a.negative(300, 30); d.answer(a, DNS_T_A, 2000);
    EXPECT_EQ(d.last.count, 0u); // AAAA still pending, negative already effective
    d.failure(DNS_T_AAAA, 2000); EXPECT_EQ(d.last.count, 0u);
}
TEST(UpstreamDiscovery, RefusedAndUnprovedEmptyAreTransientNotNegative) {
    Discovery d; d.seed(); d.begin(2000); Packet a(DNS_T_A, "resolver.example", DNS_RC_REFUSED); a.negative();
    d.answer(a, DNS_T_A, 2000); d.failure(DNS_T_AAAA, 2000); EXPECT_EQ(d.last.count, 1u);
    _dns_discovery_test_expire(d.d, 12000); ASSERT_EQ(d.last.count, 1u); EXPECT_EQ(d.last.stale, 1u);
    EXPECT_EQ(d.last.expires, 71000u);
    _dns_discovery_test_expire(d.d, 71000); EXPECT_EQ(d.last.count, 0u);
}
TEST(UpstreamDiscovery, NoTransientFailureMeansNoStaleGrace) {
    Discovery d; d.begin(); Packet a; a.address("8.8.8.8", 1); Packet b(DNS_T_AAAA); b.negative();
    d.answer(a); d.answer(b, DNS_T_AAAA); ASSERT_EQ(d.last.count, 1u);
    _dns_discovery_test_expire(d.d, 2000); EXPECT_EQ(d.last.count, 0u);
}
TEST(UpstreamDiscovery, ZeroTtlNeverAdmitsAndRevokesPrevious) {
    Discovery d; d.seed(); d.begin(2000); Packet a; a.address("8.8.8.8", 0); d.answer(a, DNS_T_A, 2000);
    EXPECT_EQ(d.last.count, 0u); EXPECT_EQ(d.last.zero_ttl, 1u); d.failure(DNS_T_AAAA, 2000);
    d.begin(3000); Packet mix; mix.address("1.1.1.1", 0); mix.address("8.8.4.4", 60);
    d.answer(mix, DNS_T_A, 3000); d.failure(DNS_T_AAAA, 3000); EXPECT_EQ(d.last.count, 1u); EXPECT_EQ(d.last.zero_ttl, 1u);
}
TEST(UpstreamDiscovery, UnusableTargetDoesNotObtainGrace) {
    Discovery d; d.seed(); d.begin(2000); Packet a; a.address("0.0.0.0", 60); d.answer(a, DNS_T_A, 2000);
    EXPECT_EQ(d.last.count, 0u); EXPECT_EQ(d.last.rejected, 1u); d.failure(DNS_T_AAAA, 2000);
}
TEST(UpstreamDiscovery, RrsetOverflowRejectsWholeFamilyNotFirst64) {
    Discovery d; d.begin(); Packet a;
    for (unsigned i = 1; i <= 65; i++) a.address(("8.8.8." + std::to_string(i)).c_str(), 60);
    d.answer(a); d.failure(DNS_T_AAAA); EXPECT_EQ(d.last.count, 0u); EXPECT_EQ(d.last.discovered, 65u);
}
TEST(UpstreamDiscovery, NxdomainAndPositiveContradictionDoesNotRefresh) {
    Discovery d; d.seed(); d.begin(2000); Packet a(DNS_T_A, "resolver.example", DNS_RC_NXDOMAIN); a.negative();
    d.answer(a, DNS_T_A, 2000); Packet b(DNS_T_AAAA); b.address("2001:4860:4860::8888");
    d.answer(b, DNS_T_AAAA, 2000); EXPECT_EQ(d.last.status, DNS_DISCOVERY_INCONSISTENT); EXPECT_EQ(d.last.count, 0u);
}
TEST(UpstreamDiscovery, WrongQuestionAndUnrelatedSoaCannotRevoke) {
    Discovery d; d.seed(); d.begin(2000); Packet wrong(DNS_T_A, "else.example"); wrong.negative();
    d.answer(wrong, DNS_T_A, 2000); d.failure(DNS_T_AAAA, 2000); EXPECT_EQ(d.last.count, 1u);
    d.begin(3000); Packet bad; bad.negative(30, 30, "not-the-owner.invalid");
    d.answer(bad, DNS_T_A, 3000); d.failure(DNS_T_AAAA, 3000); EXPECT_EQ(d.last.count, 1u);
}
TEST(UpstreamDiscovery, CallbackMayDestroyDiscovery) {
    struct Owner { dns_upstream_discovery *d; unsigned calls; } owner{};
    owner.d = _dns_discovery_create("resolver.example", [](const dns_discovery_snapshot *, void *p) {
        auto *o = static_cast<Owner *>(p); o->calls++; _dns_discovery_destroy(o->d); o->d = nullptr;
    }, &owner);
    ASSERT_NE(owner.d, nullptr); ASSERT_EQ(_dns_discovery_test_begin(owner.d, 1000), 0);
    Packet a; a.negative(); _dns_discovery_test_answer(owner.d, DNS_T_A, a.p, 1000);
    EXPECT_EQ(owner.calls, 1u); EXPECT_EQ(owner.d, nullptr);
}
TEST(UpstreamDiscovery, CnameTtlDoesNotRestartAtFollowupResponse) {
    Discovery d; d.begin(1000); Packet a;
    dns_add_CNAME(a.p, DNS_RRS_AN, "resolver.example", 3, "edge.example"); d.answer(a, DNS_T_A, 1000);
    Packet b(DNS_T_A, "edge.example"); b.address("1.1.1.1", 60, "edge.example");
    d.answer(b, DNS_T_A, 3000); d.failure(DNS_T_AAAA, 3000);
    ASSERT_EQ(d.last.count, 1u); EXPECT_EQ(d.last.expires, 4000u);
}
TEST(UpstreamDiscovery, LocalAddressesRemainCandidatesForServicePortRecursionCheck) {
    Discovery d; d.begin(); Packet a; a.address("127.0.0.1"); a.address("192.168.1.1");
    Packet b(DNS_T_AAAA); b.address("::1"); b.address("fd12:3456::1");
    d.answer(a); d.answer(b, DNS_T_AAAA);
    EXPECT_EQ(d.last.count, 4u); EXPECT_EQ(d.last.rejected, 0u);
}
TEST(UpstreamDiscovery, EightCnameLinksAllowedNinthRejected) {
    for (unsigned links : {8u, 9u}) {
        Discovery d; d.begin(); Packet p; std::string from = "resolver.example";
        for (unsigned i = 0; i < links; i++) {
            std::string target = "hop" + std::to_string(i) + ".example";
            ASSERT_EQ(dns_add_CNAME(p.p, DNS_RRS_AN, from.c_str(), 60, target.c_str()), 0); from = target;
        }
        p.address("8.8.8.8", 60, from.c_str()); d.answer(p); d.failure(DNS_T_AAAA);
        EXPECT_EQ(d.last.count, links == 8 ? 1u : 0u);
    }
}
TEST(UpstreamDiscovery, TimerFailureBackoffAndDestroyRemovePendingWake) {
    // No client is running: dispatch fails synchronously, exercising error refs.
    Discovery d; ASSERT_EQ(_dns_discovery_start(d.d), 0);
    auto due = _dns_discovery_next_deadline(); ASSERT_NE(due, ULONG_MAX);
    _dns_discovery_run_due(due);
    EXPECT_EQ(d.last.status, DNS_DISCOVERY_FAILED);
    EXPECT_GE(_dns_discovery_next_deadline(), due + 1000);
    _dns_discovery_destroy(d.d); d.d = nullptr;
    EXPECT_EQ(_dns_discovery_next_deadline(), ULONG_MAX);
}
TEST(UpstreamDiscovery, CancelledDiscoveryIgnoresLateResultsAndEndReleasesReference) {
    Discovery d; d.begin();
    void *request = _dns_discovery_test_hold_request(d.d, DNS_T_A); ASSERT_NE(request, nullptr);
    _dns_discovery_destroy(d.d); d.d = nullptr;
    Packet a; a.address("8.8.8.8");
    EXPECT_EQ(_dns_discovery_test_deliver(request, 1 /* DNS_QUERY_RESULT */, a.p), -2 /* DROP */);
    EXPECT_EQ(d.callbacks, 0u);
    EXPECT_EQ(_dns_discovery_test_deliver(request, 2 /* DNS_QUERY_END */, nullptr), 0);
    EXPECT_EQ(d.callbacks, 0u);
}
TEST(UpstreamDiscovery, ExpiredCnameCannotBeRenewedBySlowerTerminalAnswer) {
    Discovery d; d.begin(); Packet a;
    dns_add_CNAME(a.p, DNS_RRS_AN, "resolver.example", 1, "edge.example"); d.answer(a);
    Packet b(DNS_T_A, "edge.example"); b.address("8.8.8.8", 60, "edge.example");
    d.answer(b, DNS_T_A, 3000); d.failure(DNS_T_AAAA, 3000);
    EXPECT_EQ(d.last.count, 0u); EXPECT_EQ(d.last.zero_ttl, 1u);
}
TEST(UpstreamDiscovery, KnownFamilyFailureGrantsGraceWhileOtherFamilyStillPending) {
    Discovery d; d.seed(); d.begin(10000); d.failure(DNS_T_A, 10000);
    _dns_discovery_test_expire(d.d, 12000);
    ASSERT_EQ(d.last.count, 1u); EXPECT_EQ(d.last.stale, 1u); EXPECT_EQ(d.last.expires, 71000u);
    d.failure(DNS_T_AAAA, 12000);
}

TEST(UpstreamDiscovery, PrivateAndUlaMembershipRefreshIsNotScopeLocked) {
    Discovery d; d.begin(); Packet a; a.address("10.0.0.1"); Packet b(DNS_T_AAAA); b.address("fd12::1");
    d.answer(a); d.answer(b, DNS_T_AAAA); ASSERT_EQ(d.last.count, 2u); EXPECT_EQ(d.last.rejected, 0u);
    d.begin(2000); Packet next; next.address("192.168.10.53"); Packet next6(DNS_T_AAAA); next6.address("fd34::53");
    d.answer(next, DNS_T_A, 2000); d.answer(next6, DNS_T_AAAA, 2000);
    ASSERT_EQ(d.last.count, 2u); EXPECT_EQ(d.last.rejected, 0u);
    EXPECT_STREQ(d.last.addresses[0].text, "192.168.10.53"); EXPECT_STREQ(d.last.addresses[1].text, "fd34::53");
}
TEST(UpstreamDiscovery, PublicPrivateTransitionsRemainValidAcrossVpnChanges) {
    Discovery d; d.seed();
    for (auto target : {"192.168.10.53", "8.8.4.4", "127.0.0.1", "1.1.1.1"}) {
        d.begin(2000); Packet a; a.address(target); Packet b(DNS_T_AAAA); b.negative();
        d.answer(a, DNS_T_A, 2000); d.answer(b, DNS_T_AAAA, 2000);
        ASSERT_EQ(d.last.count, 1u); EXPECT_EQ(d.last.rejected, 0u); EXPECT_STREQ(d.last.addresses[0].text, target);
    }
}
