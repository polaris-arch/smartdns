#include "gtest/gtest.h"
extern "C" {
#include "dns_client/upstream_network.h"
}
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>
#include <cstring>
#include <vector>

namespace {
struct Message {
    alignas(nlmsghdr) unsigned char bytes[512]{};
    nlmsghdr *header = reinterpret_cast<nlmsghdr *>(bytes);
    explicit Message(bool link = false) {
        header->nlmsg_type = link ? RTM_NEWLINK : RTM_NEWROUTE;
        header->nlmsg_len = NLMSG_LENGTH(link ? sizeof(ifinfomsg) : sizeof(rtmsg));
        if (!link) {
            auto *r = static_cast<rtmsg *>(NLMSG_DATA(header));
            r->rtm_family = AF_INET; r->rtm_type = RTN_UNICAST;
            r->rtm_table = RT_TABLE_UNSPEC;
        }
    }
    void Attr(unsigned tag, const void *value, size_t length) {
        size_t offset = NLMSG_ALIGN(header->nlmsg_len);
        ASSERT_LE(offset + RTA_SPACE(length), sizeof(bytes));
        auto *a = reinterpret_cast<rtattr *>(bytes + offset);
        a->rta_type = tag; a->rta_len = RTA_LENGTH(length);
        memcpy(RTA_DATA(a), value, length);
        header->nlmsg_len = offset + RTA_SPACE(length);
    }
    int Parse(dns_network_interface_v1 *items, unsigned count) {
        return _dns_network_message(items, count, bytes, header->nlmsg_len);
    }
};
}

TEST(UpstreamNetwork, NamesAreHintsAndPrivateAddressesDoNotExcludeRealExits) {
    dns_network_interface_v1 items[5]{};
    strcpy(items[0].name, "enp2s0"); strcpy(items[0].address4, "100.91.184.137"); items[0].default_route4 = 1;
    strcpy(items[1].name, "dial-custom"); items[1].link_type = ARPHRD_PPP;
    strcpy(items[2].name, "pppoe-wan");
    strcpy(items[3].name, "wan1");
    strcpy(items[4].name, "wanted");
    _dns_network_classify(items, 5);
    EXPECT_EQ(items[0].role, DNS_INTERFACE_DEFAULT_EXIT); EXPECT_TRUE(items[0].recommended);
    EXPECT_EQ(items[1].role, DNS_INTERFACE_PPP); EXPECT_TRUE(items[1].recommended);
    EXPECT_EQ(items[2].role, DNS_INTERFACE_NAMED_WAN); EXPECT_TRUE(items[2].recommended);
    EXPECT_EQ(items[3].role, DNS_INTERFACE_NAMED_WAN); EXPECT_TRUE(items[3].recommended);
    EXPECT_FALSE(items[4].recommended);
}
TEST(UpstreamNetwork, LanAndOverlayAreNotRecommendedAndBridgeCanBeAnActualExit) {
    dns_network_interface_v1 items[6]{};
    items[0].loopback = 1; strcpy(items[0].name, "lo");
    strcpy(items[1].name, "br-lan"); strcpy(items[1].kind, "bridge");
    strcpy(items[2].name, "tailscale0"); items[2].default_route4 = 1;
    strcpy(items[3].name, "ztabc");
    strcpy(items[4].name, "custom-vpn"); strcpy(items[4].kind, "wireguard"); items[4].default_route6 = 1;
    strcpy(items[5].name, "br-wan"); strcpy(items[5].kind, "bridge"); items[5].default_route4 = 1;
    _dns_network_classify(items, 6);
    for (unsigned i = 0; i < 5; i++) EXPECT_FALSE(items[i].recommended);
    EXPECT_EQ(items[0].role, DNS_INTERFACE_INTERNAL); EXPECT_EQ(items[1].role, DNS_INTERFACE_INTERNAL);
    EXPECT_EQ(items[2].role, DNS_INTERFACE_TUNNEL); EXPECT_EQ(items[4].role, DNS_INTERFACE_TUNNEL);
    EXPECT_EQ(items[5].role, DNS_INTERFACE_DEFAULT_EXIT); EXPECT_TRUE(items[5].recommended);
}
TEST(UpstreamNetwork, DefaultRoutesFromPolicyTablesAndBothFamiliesAreRecognized) {
    dns_network_interface_v1 item{}; item.index = 31; strcpy(item.name, "eth2");
    Message m; unsigned table = 1001, iface = 31;
    m.Attr(RTA_TABLE, &table, sizeof(table)); m.Attr(RTA_OIF, &iface, sizeof(iface));
    EXPECT_EQ(m.Parse(&item, 1), 0); EXPECT_EQ(item.default_route4, 1U);
    auto *r = static_cast<rtmsg *>(NLMSG_DATA(m.header)); r->rtm_family = AF_INET6;
    EXPECT_EQ(m.Parse(&item, 1), 0); EXPECT_EQ(item.default_route6, 1U);
    item.default_route4 = item.default_route6 = 0; r->rtm_dst_len = 64;
    EXPECT_EQ(m.Parse(&item, 1), 0); EXPECT_EQ(item.default_route4 + item.default_route6, 0U);
}
TEST(UpstreamNetwork, CaseInsensitiveHintsCannotTurnAnInternalSlaveIntoAnExit) {
    dns_network_interface_v1 items[4]{};
    strcpy(items[0].name, "WAN1"); strcpy(items[0].kind, "veth"); items[0].default_route4 = 1;
    strcpy(items[1].name, "pppoe-internal"); items[1].master_index = 7;
    strcpy(items[2].name, "PPPoE-WAN");
    strcpy(items[3].name, "dial-custom"); items[3].master_index = 8; items[3].link_type = ARPHRD_PPP;
    _dns_network_classify(items, 4);
    EXPECT_EQ(items[0].role, DNS_INTERFACE_INTERNAL); EXPECT_FALSE(items[0].recommended);
    EXPECT_EQ(items[1].role, DNS_INTERFACE_INTERNAL); EXPECT_FALSE(items[1].recommended);
    EXPECT_EQ(items[2].role, DNS_INTERFACE_NAMED_WAN); EXPECT_TRUE(items[2].recommended);
    EXPECT_EQ(items[3].role, DNS_INTERFACE_PPP); EXPECT_TRUE(items[3].recommended);
}
TEST(UpstreamNetwork, EcmpDefaultsIncludeLiveNexthopsAndIgnoreDeadOnes) {
    dns_network_interface_v1 items[3]{};
    for (unsigned i = 0; i < 3; i++) items[i].index = i + 1;
    rtnexthop hops[3]{};
    for (unsigned i = 0; i < 3; i++) { hops[i].rtnh_len = sizeof(rtnexthop); hops[i].rtnh_ifindex = i + 1; }
    hops[2].rtnh_flags = RTNH_F_DEAD;
    Message m; m.Attr(RTA_MULTIPATH, hops, sizeof(hops));
    EXPECT_EQ(m.Parse(items, 3), 0);
    EXPECT_EQ(items[0].default_route4, 1U); EXPECT_EQ(items[1].default_route4, 1U); EXPECT_EQ(items[2].default_route4, 0U);
}
TEST(UpstreamNetwork, LinkKindAndMasterAreParsedWithoutShellOrVendorApi) {
    dns_network_interface_v1 item{}; item.index = 7;
    Message m(true); auto *link = static_cast<ifinfomsg *>(NLMSG_DATA(m.header));
    link->ifi_index = 7; link->ifi_type = ARPHRD_ETHER;
    unsigned master = 9; m.Attr(IFLA_MASTER, &master, sizeof(master));
    unsigned char nested[RTA_SPACE(7)]{}; auto *a = reinterpret_cast<rtattr *>(nested);
    a->rta_type = IFLA_INFO_KIND; a->rta_len = RTA_LENGTH(7); memcpy(RTA_DATA(a), "bridge", 7);
    m.Attr(IFLA_LINKINFO | NLA_F_NESTED, nested, sizeof(nested));
    EXPECT_EQ(m.Parse(&item, 1), 0); EXPECT_EQ(item.master_index, 9U); EXPECT_STREQ(item.kind, "bridge");
    EXPECT_EQ(_dns_network_message(&item, 1, m.bytes, sizeof(nlmsghdr) - 1), -1);
    m.header->nlmsg_len += 16;
    EXPECT_EQ(_dns_network_message(&item, 1, m.bytes, m.header->nlmsg_len - 1), -1);
}
