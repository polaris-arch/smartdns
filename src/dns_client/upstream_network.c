/* Copied interface inventory and best-effort WAN recommendations. GPL-3.0-or-later. */
#define _GNU_SOURCE
#include "upstream_network.h"
#include "smartdns/util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

static void network_describe(struct dns_network_interface_v1 *out, unsigned count);

int dns_client_get_network_interfaces_v1(struct dns_network_interface_v1 *out, unsigned capacity)
{
    if (capacity && !out) return -1;
    struct ifaddrs *addresses = NULL;
    if (getifaddrs(&addresses)) return -1;
    struct dns_network_interface_v1 snapshot[DNS_NETWORK_INTERFACES_MAX] = {0};
    unsigned count = 0;
    for (struct ifaddrs *it = addresses; it; it = it->ifa_next) {
        if (!it->ifa_name || !*it->ifa_name || strlen(it->ifa_name) >= DNS_SERVER_IFNAME_LEN) continue;
        unsigned index = if_nametoindex(it->ifa_name);
        if (!index) continue; /* disappeared during the copied inventory */
        unsigned slot = 0;
        while (slot < count && snapshot[slot].index != index) slot++;
        if (slot == count) {
            if (count == DNS_NETWORK_INTERFACES_MAX) { freeifaddrs(addresses); errno = EOVERFLOW; return -1; }
            count++;
            snapshot[slot].struct_size = sizeof(snapshot[slot]); snapshot[slot].version = 1;
            snapshot[slot].index = index;
            safe_strncpy(snapshot[slot].name, it->ifa_name, sizeof(snapshot[slot].name));
        }
        struct dns_network_interface_v1 *item = &snapshot[slot];
        item->up = !!(it->ifa_flags & IFF_UP); item->running = !!(it->ifa_flags & IFF_RUNNING);
        item->loopback = !!(it->ifa_flags & IFF_LOOPBACK); item->point_to_point = !!(it->ifa_flags & IFF_POINTOPOINT);
        if (!it->ifa_addr) continue;
        int family = it->ifa_addr->sa_family;
        if (family == AF_PACKET) item->link_type = ((struct sockaddr_ll *)it->ifa_addr)->sll_hatype;
        char address[DNS_UPSTREAM_IP_TEXT_MAX] = {0};
        if (family == AF_INET) {
            const struct in_addr *ip = &((struct sockaddr_in *)it->ifa_addr)->sin_addr;
            if (!ip->s_addr || !inet_ntop(family, ip, address, sizeof(address))) continue;
            item->ipv4_count++;
            if (!item->address4[0] || strcmp(address, item->address4) < 0)
                safe_strncpy(item->address4, address, sizeof(item->address4));
        } else if (family == AF_INET6) {
            const struct in6_addr *ip = &((struct sockaddr_in6 *)it->ifa_addr)->sin6_addr;
            if (IN6_IS_ADDR_UNSPECIFIED(ip) || !inet_ntop(family, ip, address, sizeof(address))) continue;
            item->ipv6_count++;
            /* Prefer an address usable beyond a single link for the UI summary.
             * Actual transport source selection remains a destination route lookup. */
            struct in6_addr previous;
            int old_link_local = inet_pton(AF_INET6, item->address6, &previous) == 1 && IN6_IS_ADDR_LINKLOCAL(&previous);
            if (!item->address6[0] || (old_link_local && !IN6_IS_ADDR_LINKLOCAL(ip)) ||
                (old_link_local == !!IN6_IS_ADDR_LINKLOCAL(ip) && strcmp(address, item->address6) < 0))
                safe_strncpy(item->address6, address, sizeof(item->address6));
        }
    }
    freeifaddrs(addresses);
    network_describe(snapshot, count);
    _dns_network_classify(snapshot, count);
    /* Stable ordering keeps checkbox lists from jumping across refreshes. */
    for (unsigned i = 1; i < count; i++) {
        struct dns_network_interface_v1 value = snapshot[i]; unsigned j = i;
        while (j && strcmp(snapshot[j - 1].name, value.name) > 0) { snapshot[j] = snapshot[j - 1]; j--; }
        snapshot[j] = value;
    }
    if (out && capacity) memcpy(out, snapshot, (capacity < count ? capacity : count) * sizeof(*out));
    return count;
}

static struct dns_network_interface_v1 *network_find(struct dns_network_interface_v1 *out, unsigned count, unsigned index)
{
    for (unsigned i = 0; i < count; i++) if (out[i].index == index) return out + i;
    return NULL;
}

static void network_default(struct dns_network_interface_v1 *out, unsigned count, int family, unsigned index)
{
    struct dns_network_interface_v1 *item = network_find(out, count, index);
    if (!item) return;
    if (family == AF_INET) item->default_route4 = 1;
    if (family == AF_INET6) item->default_route6 = 1;
}

int _dns_network_message(struct dns_network_interface_v1 *out, unsigned count, const void *data, size_t size)
{
    if (!data || size < sizeof(struct nlmsghdr)) return -1;
    const struct nlmsghdr *message = data;
    if (message->nlmsg_len < NLMSG_HDRLEN || message->nlmsg_len > size) return -1;
    if (message->nlmsg_type == RTM_NEWLINK) {
        if (message->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg))) return -1;
        const struct ifinfomsg *info = NLMSG_DATA(message);
        struct dns_network_interface_v1 *item = network_find(out, count, info->ifi_index);
        if (!item) return 0;
        item->link_type = info->ifi_type;
        int left = IFLA_PAYLOAD(message);
        for (const struct rtattr *a = IFLA_RTA(info); RTA_OK(a, left); a = RTA_NEXT(a, left)) {
            unsigned tag = a->rta_type & NLA_TYPE_MASK;
            if (tag == IFLA_MASTER && RTA_PAYLOAD(a) >= sizeof(item->master_index))
                memcpy(&item->master_index, RTA_DATA(a), sizeof(item->master_index));
            if (tag == IFLA_LINKINFO) {
                int nested = RTA_PAYLOAD(a);
                for (const struct rtattr *v = RTA_DATA(a); RTA_OK(v, nested); v = RTA_NEXT(v, nested)) {
                    if ((v->rta_type & NLA_TYPE_MASK) != IFLA_INFO_KIND) continue;
                    size_t n = strnlen(RTA_DATA(v), RTA_PAYLOAD(v));
                    if (n == RTA_PAYLOAD(v) || n >= sizeof(item->kind)) return -1;
                    memcpy(item->kind, RTA_DATA(v), n + 1);
                }
                if (nested > 0) return -1;
            }
        }
        return left > 0 ? -1 : 0;
    }
    if (message->nlmsg_type != RTM_NEWROUTE) return 0;
    if (message->nlmsg_len < NLMSG_LENGTH(sizeof(struct rtmsg))) return -1;
    const struct rtmsg *route = NLMSG_DATA(message);
    if ((route->rtm_family != AF_INET && route->rtm_family != AF_INET6) || route->rtm_dst_len || route->rtm_type != RTN_UNICAST) return 0;
    /* No main-table restriction: policy tables and ECMP are common on multi-WAN.
     * A default route recommends an exit; actual per-destination policy still
     * gates transport admission separately. */
    unsigned index = 0;
    int left = RTM_PAYLOAD(message);
    for (const struct rtattr *a = RTM_RTA(route); RTA_OK(a, left); a = RTA_NEXT(a, left)) {
        unsigned tag = a->rta_type & NLA_TYPE_MASK;
        if (tag == RTA_DST) {
            unsigned bytes = route->rtm_family == AF_INET ? 4 : 16;
            if (RTA_PAYLOAD(a) < bytes) return -1;
            const unsigned char *address = RTA_DATA(a);
            for (unsigned i = 0; i < bytes; i++) if (address[i]) return 0;
        }
        if (tag == RTA_OIF && RTA_PAYLOAD(a) >= sizeof(index)) memcpy(&index, RTA_DATA(a), sizeof(index));
        if (tag == RTA_MULTIPATH) {
            int remaining = RTA_PAYLOAD(a);
            for (const struct rtnexthop *hop = RTA_DATA(a); RTNH_OK(hop, remaining); hop = RTNH_NEXT(hop)) {
                if (hop->rtnh_ifindex > 0 && !(hop->rtnh_flags & (RTNH_F_DEAD | RTNH_F_LINKDOWN)))
                    network_default(out, count, route->rtm_family, hop->rtnh_ifindex);
                remaining -= RTNH_ALIGN(hop->rtnh_len);
            }
            if (remaining > 0) return -1;
        }
    }
    if (left > 0) return -1;
    if (index) network_default(out, count, route->rtm_family, index);
    return 0;
}

/* Only the control-plane inventory calls this bounded local kernel dump. The
 * DNS dispatch thread never waits here and no probe packet leaves the host. */
static int network_dump(struct dns_network_interface_v1 *out, unsigned count, unsigned type)
{
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    struct { struct nlmsghdr header; union { struct ifinfomsg link; struct rtmsg route; } data; } request = {0};
    request.header.nlmsg_type = type; request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = 1;
    request.header.nlmsg_len = NLMSG_LENGTH(type == RTM_GETLINK ? sizeof(request.data.link) : sizeof(request.data.route));
    if (sendto(fd, &request, request.header.nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof(kernel)) < 0) { close(fd); return -1; }
    unsigned long deadline = get_tick_count() + 100;
    unsigned bytes = 0; int result = -1;
    for (;;) {
        unsigned long now = get_tick_count();
        if (now >= deadline || bytes >= 1024 * 1024) break;
        struct pollfd wait = {.fd = fd, .events = POLLIN};
        int ready = poll(&wait, 1, deadline - now);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) break;
        char buffer[16384]; struct sockaddr_nl sender = {0};
        struct iovec io = {.iov_base = buffer, .iov_len = sizeof(buffer)};
        struct msghdr packet = {.msg_name = &sender, .msg_namelen = sizeof(sender), .msg_iov = &io, .msg_iovlen = 1};
        ssize_t n = recvmsg(fd, &packet, MSG_DONTWAIT);
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (n <= 0 || (packet.msg_flags & MSG_TRUNC)) break;
        if (sender.nl_pid) continue;
        bytes += n;
        for (struct nlmsghdr *message = (struct nlmsghdr *)buffer; NLMSG_OK(message, n); message = NLMSG_NEXT(message, n)) {
            if (message->nlmsg_seq != 1) continue;
            if (message->nlmsg_flags & NLM_F_DUMP_INTR) goto done;
            if (message->nlmsg_type == NLMSG_DONE) { result = 0; goto done; }
            if (message->nlmsg_type == NLMSG_ERROR ||
                _dns_network_message(out, count, message, message->nlmsg_len)) goto done;
        }
        if (n > 0) break;
    }
done:
    close(fd); return result;
}

static void network_describe(struct dns_network_interface_v1 *out, unsigned count)
{
    int links = network_dump(out, count, RTM_GETLINK) == 0;
    int routes = network_dump(out, count, RTM_GETROUTE) == 0;
    for (unsigned i = 0; i < count; i++) {
        out[i].link_inventory_complete = links; out[i].route_inventory_complete = routes;
    }
}

static int interface_prefix(const char *name, const char *prefix)
{ return !strncasecmp(name, prefix, strlen(prefix)); }

void _dns_network_classify(struct dns_network_interface_v1 *out, unsigned count)
{
    static const char *tunnels[] = {"wireguard", "tun", "gre", "gretap", "ipip", "ip6tnl", "sit", "vti", "vti6", "vxlan", "geneve", "erspan"};
    for (unsigned i = 0; i < count; i++) {
        struct dns_network_interface_v1 *item = out + i;
        int tunnel = interface_prefix(item->name, "tailscale") || interface_prefix(item->name, "zt") ||
            interface_prefix(item->name, "wg") || interface_prefix(item->name, "tun") || interface_prefix(item->name, "tap");
        for (unsigned j = 0; j < sizeof(tunnels) / sizeof(tunnels[0]); j++) tunnel |= !strcmp(item->kind, tunnels[j]);
        int ppp_name = interface_prefix(item->name, "ppp");
        int wan_name = interface_prefix(item->name, "wan") &&
            (!item->name[3] || (item->name[3] >= '0' && item->name[3] <= '9') || strchr("-_.", item->name[3]));
        int virtual_internal = !strcmp(item->kind, "veth") || !strcmp(item->kind, "dummy") || !strcmp(item->kind, "ifb") ||
            interface_prefix(item->name, "docker") || interface_prefix(item->name, "virbr") ||
            interface_prefix(item->name, "cni") || interface_prefix(item->name, "veth");
        if (item->loopback) item->role = DNS_INTERFACE_INTERNAL;
        else if (tunnel) item->role = DNS_INTERFACE_TUNNEL;
        else if (virtual_internal) item->role = DNS_INTERFACE_INTERNAL;
        else if (item->default_route4 || item->default_route6) item->role = DNS_INTERFACE_DEFAULT_EXIT;
        else if (item->link_type == ARPHRD_PPP || !strcmp(item->kind, "ppp")) item->role = DNS_INTERFACE_PPP;
        else if (item->master_index || !strcmp(item->kind, "bridge"))
            item->role = DNS_INTERFACE_INTERNAL;
        else if (ppp_name || wan_name) item->role = DNS_INTERFACE_NAMED_WAN;
        else item->role = DNS_INTERFACE_OTHER;
        item->recommended = item->role == DNS_INTERFACE_DEFAULT_EXIT || item->role == DNS_INTERFACE_PPP || item->role == DNS_INTERFACE_NAMED_WAN;
    }
}
