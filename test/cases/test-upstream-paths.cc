#include "gtest/gtest.h"
#include <net/if.h>
#include <cstdlib>
#include <cstring>
extern "C" {
#include "dns_client/upstream_service.h"
#include "dns_client/upstream_discovery.h"
#include "smartdns/util.h"
}
namespace {
struct Routes {
    dns_upstream_service service{}; dns_discovery_snapshot desired{};
    Routes() {
        pthread_mutex_init(&service.detail_lock,nullptr); service.flags.set_mark=-1;
        service.desired=&desired; service.port=443; service.type=DNS_SERVER_HTTPS;
        desired.count=2; std::strcpy(desired.addresses[0].text,"127.0.0.2");
        std::strcpy(desired.addresses[1].text,"::1");
    }
    ~Routes(){_dns_paths_close();std::free(service.failures);std::free(service.event_sources);pthread_mutex_destroy(&service.detail_lock);}
    void refresh(){service.path_refresh_due=0;_dns_paths_refresh(&service,get_tick_count());}
};
void route_changes() {
    // The suite already runs in a loopback-only network namespace. Mutate only
    // this unique ULA fixture, requiring NET_ADMIN rather than SYS_ADMIN/unshare.
    struct if_nameindex *names=if_nameindex();ASSERT_NE(names,nullptr);
    unsigned interfaces=0;for(auto *p=names;p->if_index;p++){interfaces++;EXPECT_STREQ(p->if_name,"lo");}
    if_freenameindex(names);ASSERT_EQ(interfaces,1U);
    Routes r;std::strcpy(r.desired.addresses[1].text,"fd42:7a5e::53");r.refresh();
    EXPECT_EQ(r.service.detail.paths[0].state,DNS_PATH_ELIGIBLE);
    EXPECT_EQ(r.service.detail.paths[1].state,DNS_PATH_NO_ROUTE);
    EXPECT_TRUE(_dns_path_allowed(&r.service,"127.0.0.2"));
    EXPECT_FALSE(_dns_path_allowed(&r.service,"fd42:7a5e::53"));
    ASSERT_EQ(std::system("ip -6 addr add fd42:7a5e::1/64 dev lo"),0);
    _dns_paths_network_tick();_dns_paths_refresh(&r.service,get_tick_count());
    EXPECT_EQ(r.service.detail.paths[1].state,DNS_PATH_ELIGIBLE);
    EXPECT_STREQ(r.service.detail.paths[1].interface,"lo");
    ASSERT_EQ(std::system("ip -6 addr del fd42:7a5e::1/64 dev lo"),0);
    _dns_paths_network_tick();_dns_paths_refresh(&r.service,get_tick_count());
    EXPECT_EQ(r.service.detail.paths[1].state,DNS_PATH_NO_ROUTE);
}
}
TEST(UpstreamPaths, ForcedFamilyFiltersTransportWithoutChangingDiscovery) {
    Routes r;r.service.config.family=4;r.refresh();
    EXPECT_TRUE(_dns_path_allowed(&r.service,"127.0.0.2"));
    EXPECT_FALSE(_dns_path_allowed(&r.service,"::1"));
    EXPECT_EQ(r.service.detail.paths[1].state,DNS_PATH_FAMILY_DISABLED);
    EXPECT_EQ(r.desired.count,2U);
    r.service.config.family=6;r.refresh();
    EXPECT_EQ(r.service.detail.paths[0].state,DNS_PATH_FAMILY_DISABLED);
    EXPECT_EQ(r.service.detail.paths[1].state,DNS_PATH_ELIGIBLE);
    EXPECT_TRUE(_dns_path_allowed(&r.service,"::1"));
    r.service.config.family=0;r.refresh();
    EXPECT_TRUE(_dns_path_allowed(&r.service,"127.0.0.2"));EXPECT_TRUE(_dns_path_allowed(&r.service,"::1"));
}
TEST(UpstreamPaths, MissingBoundInterfaceDoesNotBecomeReachable) {
    Routes r;std::strcpy(r.service.flags.ifname,"no-pool-device");r.refresh();
    EXPECT_EQ(r.service.detail.paths[0].state,DNS_PATH_BINDING_ERROR);
    EXPECT_FALSE(_dns_path_allowed(&r.service,"127.0.0.2"));
}
TEST(UpstreamPaths, EventContextRingKeepsExactSequenceTimestampAndDnsEvidence) {
    Routes r;
    dns_server_info endpoint{}; endpoint.service = &r.service;
    std::strcpy(endpoint.ip, "127.0.0.2"); endpoint.port = 443;
    dns_query_struct query{}; query.qtype = DNS_T_AAAA; query.sid = 0; // zero is a valid DNS ID
    std::strcpy(query.domain, "empty.example");
    alignas(dns_packet) unsigned char storage[DNS_PACKSIZE], wire[DNS_IN_PACKSIZE];
    auto *packet = reinterpret_cast<dns_packet *>(storage);
    dns_head head{}; head.qr = DNS_QR_ANSWER;
    ASSERT_EQ(dns_packet_init(packet, sizeof(storage), &head), 0);
    ASSERT_EQ(dns_add_domain(packet, query.domain, query.qtype, DNS_C_IN), 0);
    dns_soa soa{}; std::strcpy(soa.mname,"ns.example"); std::strcpy(soa.rname,"hostmaster.example");
    ASSERT_EQ(dns_add_SOA(packet, DNS_RRS_NS, "example", 60, &soa), 0);
    int length = dns_encode(wire, sizeof(wire), packet); ASSERT_GT(length, 0);
    ASSERT_EQ(dns_decode(packet, sizeof(storage), wire, length), 0);
    for (unsigned i = 0; i < DNS_UPSTREAM_DETAIL_EVENTS + 2; i++)
        _dns_service_detail_dns(&query, &endpoint, DNS_DETAIL_DNS_REJECT, DNS_PHASE_RESPONSE,
            DNS_REJECT_NO_USABLE_RECORDS, packet);
    EXPECT_EQ(r.service.detail.event_count, DNS_UPSTREAM_DETAIL_EVENTS);
    EXPECT_EQ(r.service.detail.dropped_events, 2U);
    for (unsigned i = 0; i < DNS_UPSTREAM_DETAIL_EVENTS; i++) {
        const auto &context = r.service.event_context[i];
        EXPECT_EQ(context.sequence, r.service.detail.events[i].sequence);
        EXPECT_GT(context.unix_ms, 0U); EXPECT_STREQ(context.domain, query.domain);
        EXPECT_EQ(context.qtype, DNS_T_AAAA); EXPECT_EQ(context.dns_summary_valid, 1U);
        EXPECT_EQ(context.answers, 0U); EXPECT_EQ(context.authority, 1U); EXPECT_EQ(context.soa_records, 1U);
    }
    auto sequence = r.service.event_context[0].sequence;
    _dns_service_detail(nullptr,&endpoint,DNS_DETAIL_KEEPALIVE_ACK,DNS_PHASE_HTTP2,0,0,0);
    EXPECT_EQ(r.service.event_context[0].sequence,sequence); // healthy probes never evict failures
}
TEST(UpstreamPaths, SingleStackRecoversAndWithdrawsOnActualRouteEvents) {
    ::testing::FLAGS_gtest_death_test_style="threadsafe";
    ASSERT_EXIT({route_changes();std::exit(::testing::Test::HasFailure()?1:0);},::testing::ExitedWithCode(0),"");
}
