/* Transport-family policy, cached kernel routes and bounded diagnostic evidence. */
#define _GNU_SOURCE
#include "upstream_service.h"
#include "upstream_discovery.h"
#include "smartdns/util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/err.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

static int route_events = -1;
static uint64_t route_epoch = 1;
static unsigned route_sequence;

static void route_monitor(void)
{
    if (route_events >= 0) return;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return;
    struct sockaddr_nl address = {.nl_family = AF_NETLINK, .nl_groups = RTMGRP_LINK |
        RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE};
    if (bind(fd, (struct sockaddr *)&address, sizeof(address))) { close(fd); return; }
    route_events = fd;
}
void _dns_paths_network_tick(void)
{
    if (route_events < 0) return;
    char data[16384];
    for (unsigned i = 0; i < 64; i++) {
        ssize_t n = recv(route_events, data, sizeof(data), MSG_DONTWAIT);
        if (n < 0) { if (errno == ENOBUFS) route_epoch++; break; }
        if (!n) break;
        route_epoch++;
    }
}
void _dns_paths_close(void)
{
    if (route_events >= 0) close(route_events);
    route_events = -1; route_epoch++;
}
static int route_attribute(struct nlmsghdr *header, size_t cap, unsigned type, const void *data, size_t size)
{
    size_t offset = NLMSG_ALIGN(header->nlmsg_len), bytes = RTA_LENGTH(size);
    if (offset + RTA_ALIGN(bytes) > cap) return -1;
    struct rtattr *attribute = (struct rtattr *)((char *)header + offset);
    attribute->rta_type = type; attribute->rta_len = bytes;
    memcpy(RTA_DATA(attribute), data, size);
    header->nlmsg_len = offset + RTA_ALIGN(bytes); return 0;
}
static void path_route(struct dns_upstream_service *service, struct dns_upstream_path_v1 *out)
{
    int family = out->family == 4 ? AF_INET : AF_INET6;
    if (service->config.family && service->config.family != out->family) {
        out->state = DNS_PATH_FAMILY_DISABLED; return;
    }
    struct { struct nlmsghdr header; struct rtmsg route; unsigned char attrs[256]; } request = {0};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.route));
    request.header.nlmsg_type = RTM_GETROUTE; request.header.nlmsg_flags = NLM_F_REQUEST;
    request.header.nlmsg_seq = ++route_sequence;
    request.route.rtm_family = family; request.route.rtm_dst_len = family == AF_INET ? 32 : 128;
    unsigned char destination[16];
    if (inet_pton(family, out->ip, destination) != 1) { out->state = DNS_PATH_NO_ROUTE; return; }
    route_attribute(&request.header, sizeof(request), RTA_DST, destination, family == AF_INET ? 4 : 16);
    unsigned mark = (unsigned)service->flags.set_mark, uid = geteuid();
    if (service->flags.set_mark >= 0) route_attribute(&request.header, sizeof(request), RTA_MARK, &mark, sizeof(mark));
    route_attribute(&request.header, sizeof(request), RTA_UID, &uid, sizeof(uid));
    unsigned char protocol = service->type == DNS_SERVER_UDP || service->type == DNS_SERVER_QUIC ||
        service->type == DNS_SERVER_HTTP3 ? IPPROTO_UDP : IPPROTO_TCP;
    unsigned short port = htons(service->port);
    route_attribute(&request.header, sizeof(request), RTA_IP_PROTO, &protocol, sizeof(protocol));
    route_attribute(&request.header, sizeof(request), RTA_DPORT, &port, sizeof(port));
    if (service->flags.ifname[0]) {
        unsigned index = if_nametoindex(service->flags.ifname);
        if (!index) { out->state = DNS_PATH_BINDING_ERROR; out->system_error = ENODEV; return; }
        route_attribute(&request.header, sizeof(request), RTA_OIF, &index, sizeof(index));
    }
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) { out->state = DNS_PATH_UNKNOWN; out->system_error = errno; return; }
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    char buffer[8192];
    if (sendto(fd, &request, request.header.nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof(kernel)) < 0) {
        out->state = DNS_PATH_UNKNOWN; out->system_error = errno; close(fd); return;
    }
    /* RTM_GETROUTE is a local kernel lookup, not an external reachability probe.
     * Never block DNS IO waiting for netlink. Unknown results retain candidates;
     * the actual transport still verifies reachability and observes failures. */
    ssize_t size = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT); int saved = errno; close(fd);
    if (size < 0) { out->state = DNS_PATH_UNKNOWN; out->system_error = saved; return; }
    out->state = DNS_PATH_UNKNOWN;
    for (struct nlmsghdr *message = (struct nlmsghdr *)buffer; NLMSG_OK(message, size); message = NLMSG_NEXT(message, size)) {
        if (message->nlmsg_seq != request.header.nlmsg_seq) continue;
        if (message->nlmsg_type == NLMSG_ERROR && message->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
            int error = -((struct nlmsgerr *)NLMSG_DATA(message))->error;
            out->system_error = error;
            out->state = error == EADDRNOTAVAIL ? DNS_PATH_NO_SOURCE :
                error == ENETUNREACH || error == EHOSTUNREACH || error == EACCES ? DNS_PATH_NO_ROUTE : DNS_PATH_UNKNOWN;
            continue;
        }
        if (message->nlmsg_type != RTM_NEWROUTE || message->nlmsg_len < NLMSG_LENGTH(sizeof(struct rtmsg))) continue;
        struct rtmsg *route = NLMSG_DATA(message);
        if (route->rtm_type != RTN_UNICAST && route->rtm_type != RTN_LOCAL) { out->state = DNS_PATH_NO_ROUTE; continue; }
        int length = RTM_PAYLOAD(message); unsigned index = 0;
        for (struct rtattr *a = RTM_RTA(route); RTA_OK(a, length); a = RTA_NEXT(a, length)) {
            if (a->rta_type == RTA_OIF && RTA_PAYLOAD(a) >= sizeof(index)) memcpy(&index, RTA_DATA(a), sizeof(index));
            if (a->rta_type == RTA_PREFSRC && RTA_PAYLOAD(a) >= (family == AF_INET ? 4U : 16U))
                inet_ntop(family, RTA_DATA(a), out->source, sizeof(out->source));
        }
        if (index) if_indextoname(index, out->interface);
        out->state = DNS_PATH_ELIGIBLE;
    }
}
void _dns_paths_refresh(struct dns_upstream_service *service, unsigned long now)
{
    route_monitor();
    if (!service->desired || (service->path_epoch == route_epoch && now < service->path_refresh_due)) return;
    struct dns_upstream_path_v1 paths[DNS_UPSTREAM_DETAIL_PATHS] = {0};
    unsigned count = service->desired->count;
    if (count > DNS_UPSTREAM_DETAIL_PATHS) count = DNS_UPSTREAM_DETAIL_PATHS;
    for (unsigned i = 0; i < count; i++) {
        safe_strncpy(paths[i].ip, service->desired->addresses[i].text, sizeof(paths[i].ip));
        paths[i].family = strchr(paths[i].ip, ':') ? 6 : 4;
        path_route(service, &paths[i]);
    }
    pthread_mutex_lock(&service->detail_lock);
    memcpy(service->detail.paths, paths, sizeof(paths)); service->detail.path_count = count;
    pthread_mutex_unlock(&service->detail_lock);
    service->path_epoch = route_epoch; service->path_refresh_due = now + 5000;
}
int _dns_path_allowed(struct dns_upstream_service *service, const char *ip)
{
    int result = 0;
    pthread_mutex_lock(&service->detail_lock);
    for (unsigned i = 0; i < service->detail.path_count; i++) if (!strcmp(ip, service->detail.paths[i].ip)) {
        unsigned state = service->detail.paths[i].state;
        result = state == DNS_PATH_ELIGIBLE || state == DNS_PATH_UNKNOWN; break;
    }
    pthread_mutex_unlock(&service->detail_lock); return result;
}
void _dns_service_detail(struct dns_query_struct *query, struct dns_server_info *endpoint,
    unsigned kind, unsigned phase, int code, unsigned elapsed, unsigned limit)
{
    if (!endpoint || !endpoint->service || kind >= DNS_DETAIL_COUNT) return;
    struct dns_upstream_service *service = endpoint->service;
    struct dns_upstream_event_v1 event = {0};
    event.tick_ms = get_tick_count(); event.kind = kind; event.phase = phase; event.code = code;
    event.query_id = query ? query->sid : 0;
    event.tls_error = endpoint->service_tls_error;
    if (event.tls_error) ERR_error_string_n(event.tls_error, event.message, sizeof(event.message));
    else if (endpoint->service_system_error) safe_strncpy(event.message, strerror(endpoint->service_system_error), sizeof(event.message));
    event.system_error = endpoint->service_system_error; event.elapsed_ms = elapsed; event.limit_ms = limit;
    event.port = endpoint->port; event.family = strchr(endpoint->ip, ':') ? 6 : 4;
    safe_strncpy(event.ip, endpoint->ip, sizeof(event.ip));
    pthread_mutex_lock(&service->detail_lock);
    struct dns_upstream_policy_snapshot_v1 *detail = &service->detail;
    event.sequence = ++detail->sequence; detail->kind_counts[kind]++;
    if (kind == DNS_DETAIL_DNS_REJECT) detail->reject_counts[code >= 0 && code < DNS_REJECT_COUNT ? code : 0]++;
    /* Healthy idle probes stay in counters, preserving the bounded ring for failures and lifecycle events. */
    if (kind == DNS_DETAIL_KEEPALIVE_SENT || kind == DNS_DETAIL_KEEPALIVE_ACK) {
        pthread_mutex_unlock(&service->detail_lock); return;
    }
    if (detail->event_count == DNS_UPSTREAM_DETAIL_EVENTS) detail->dropped_events++;
    else detail->event_count++;
    memmove(&detail->events[1], &detail->events[0], (detail->event_count - 1) * sizeof(event));
    detail->events[0] = event;
    pthread_mutex_unlock(&service->detail_lock);
    (void)query;
}
void _dns_service_response_time(struct dns_server_info *endpoint, unsigned elapsed)
{
    if (!endpoint->service) return;
    static const unsigned upper[] = {10, 25, 50, 100, 250, 500, 1000, 2000};
    unsigned bin = 0; while (bin < 8 && elapsed > upper[bin]) bin++;
    pthread_mutex_lock(&endpoint->service->detail_lock);
    endpoint->service->detail.response_histogram[bin]++;
    pthread_mutex_unlock(&endpoint->service->detail_lock);
}
