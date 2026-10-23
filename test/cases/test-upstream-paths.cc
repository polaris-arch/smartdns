#include "gtest/gtest.h"
#include <sched.h>
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
    ~Routes(){_dns_paths_close();pthread_mutex_destroy(&service.detail_lock);}
    void refresh(){service.path_refresh_due=0;_dns_paths_refresh(&service,get_tick_count());}
};
void route_changes() {
    ASSERT_EQ(unshare(CLONE_NEWNET),0); ASSERT_EQ(std::system("ip link set lo up"),0);
    Routes r;std::strcpy(r.desired.addresses[1].text,"2001:db8::53");r.refresh();
    EXPECT_EQ(r.service.detail.paths[0].state,DNS_PATH_ELIGIBLE);
    EXPECT_EQ(r.service.detail.paths[1].state,DNS_PATH_NO_ROUTE);
    EXPECT_TRUE(_dns_path_allowed(&r.service,"127.0.0.2"));
    EXPECT_FALSE(_dns_path_allowed(&r.service,"2001:db8::53"));
    ASSERT_EQ(std::system("ip -6 addr add 2001:db8::1/64 dev lo"),0);
    _dns_paths_network_tick();_dns_paths_refresh(&r.service,get_tick_count());
    EXPECT_EQ(r.service.detail.paths[1].state,DNS_PATH_ELIGIBLE);
    EXPECT_STREQ(r.service.detail.paths[1].interface,"lo");
    ASSERT_EQ(std::system("ip -6 addr del 2001:db8::1/64 dev lo"),0);
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
TEST(UpstreamPaths, SingleStackRecoversAndWithdrawsOnActualRouteEvents) {
    ::testing::FLAGS_gtest_death_test_style="threadsafe";
    ASSERT_EXIT({route_changes();std::exit(::testing::Test::HasFailure()?1:0);},::testing::ExitedWithCode(0),"");
}
