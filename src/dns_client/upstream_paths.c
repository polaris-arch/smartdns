/* Transport-family policy, cached kernel routes and bounded diagnostic evidence. */
#define _GNU_SOURCE
#include "upstream_observer.h"
#include "upstream_policy.h"
#include "upstream_service.h"
#include "upstream_discovery.h"
#include "smartdns/util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/err.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

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
static void path_route(struct dns_upstream_service *service, struct dns_upstream_path_v1 *out, const char *interface)
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
    if (interface[0]) {
        unsigned index = if_nametoindex(interface);
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
static void paths_refresh_wans(struct dns_upstream_service *s)
{
    unsigned long now = get_tick_count();
    struct dns_service_wan next[DNS_UPSTREAM_WANS_MAX] = {0};
    char preferred[DNS_UPSTREAM_WANS_MAX][DNS_UPSTREAM_IP_TEXT_MAX] = {{0}};
    pthread_mutex_lock(&s->lock);
    for (unsigned i = 0; i < s->wan_count; i++) {
        memcpy(next[i].interface, s->wans[i].interface, sizeof(next[i].interface));
        next[i].address_cursor = __atomic_load_n(&s->wans[i].address_cursor, __ATOMIC_RELAXED);
        memcpy(next[i].source4, s->wans[i].source4, sizeof(next[i].source4));
        memcpy(next[i].source6, s->wans[i].source6, sizeof(next[i].source6));
        next[i].index = s->wans[i].index;
    }
    for (unsigned i = 0; i < s->member_count; i++) {
        struct dns_server_info *ep = s->members[i];
        if (ep->service_wan < s->wan_count && ep->service_member_id ==
            __atomic_load_n(&s->wans[ep->service_wan].winner, __ATOMIC_ACQUIRE) &&
            !__atomic_load_n(&ep->service_revoked, __ATOMIC_ACQUIRE))
            safe_strncpy(preferred[ep->service_wan], ep->ip, sizeof(preferred[0]));
    }
    pthread_mutex_unlock(&s->lock);
    struct ifaddrs *addresses = NULL;
    if (getifaddrs(&addresses)) return; /* preserve prior snapshot; retry on next timer */
    struct dns_upstream_path_v1 paths[DNS_UPSTREAM_WANS_MAX * 2] = {0}; unsigned path_count = 0;
    for (unsigned lane = 0; lane < s->wan_count; lane++) {
        struct dns_service_wan *w = next + lane;
        if (w->interface[0]) {
            unsigned index = if_nametoindex(w->interface);
            if (index != w->index) w->source4[0] = w->source6[0] = 0;
            w->index = index;
        }
        char local_source[2][DNS_UPSTREAM_IP_TEXT_MAX] = {{0}};
        memset(w->candidates, 0, sizeof(w->candidates));
        int up = !w->interface[0];
        for (struct ifaddrs *it = addresses; it; it = it->ifa_next) {
            if (!it->ifa_name || strcmp(it->ifa_name, w->interface)) continue;
            up |= !!(it->ifa_flags & IFF_UP);
            if (!it->ifa_addr) continue;
            int family = it->ifa_addr->sa_family; char text[DNS_UPSTREAM_IP_TEXT_MAX] = {0};
            if (family == AF_INET) inet_ntop(family, &((struct sockaddr_in *)it->ifa_addr)->sin_addr, text, sizeof(text));
            else if (family == AF_INET6 && !IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6 *)it->ifa_addr)->sin6_addr))
                inet_ntop(family, &((struct sockaddr_in6 *)it->ifa_addr)->sin6_addr, text, sizeof(text));
            else continue;
            char *source = local_source[family == AF_INET6];
            if (text[0] && (!source[0] || strcmp(text, source) < 0)) safe_strncpy(source, text, DNS_UPSTREAM_IP_TEXT_MAX);
        }
        if (local_source[0][0]) safe_strncpy(w->source4, local_source[0], sizeof(w->source4));
        if (local_source[1][0]) safe_strncpy(w->source6, local_source[1], sizeof(w->source6));
        if (!up || (w->interface[0] && !w->index)) w->source4[0] = w->source6[0] = 0;
        for (unsigned family = 0; family < 2; family++) {
            struct dns_upstream_path_v1 path = {0};
            path.family = family ? 6 : 4;
            safe_strncpy(path.interface, w->interface, sizeof(path.interface));
            unsigned tried = 0;
            for (unsigned pass = 0; pass < 2 && !w->candidates[family].ip[0]; pass++) {
                for (unsigned n = 0; n < s->desired->count && tried < 4; n++) {
                    unsigned at = (n + (pass ? w->address_cursor : 0)) % s->desired->count;
                    const struct dns_discovery_address *a = s->desired->addresses + at;
                    if ((!!strchr(a->text, ':')) != family || (pass == 0 && strcmp(a->text, preferred[lane]))) continue;
                    tried++; safe_strncpy(path.ip, a->text, sizeof(path.ip));
                    if (s->config.family && s->config.family != path.family) path.state = DNS_PATH_FAMILY_DISABLED;
                    else if (w->interface[0] && !w->index) { path.state = DNS_PATH_BINDING_ERROR; path.system_error = ENODEV; }
                    else if (!up) { path.state = DNS_PATH_NO_ROUTE; path.system_error = ENETDOWN; }
                    else if (s->flags.proxyname[0]) path.state = DNS_PATH_UNKNOWN; /* proxy chooses the real transport family and exit */
                    /* A PPP uplink may borrow a delegated-prefix address from
                     * another local interface (Linux use_oif_addrs_only=0).
                     * Local address enumeration must not veto a kernel route. */
                    else path_route(s, &path, w->interface);
                    if (path.state != DNS_PATH_ELIGIBLE && path.state != DNS_PATH_UNKNOWN) continue;
                    safe_strncpy(w->candidates[family].ip, a->text, sizeof(w->candidates[family].ip));
                    if (path.state == DNS_PATH_ELIGIBLE && path.source[0]) {
                        safe_strncpy(family ? w->source6 : w->source4, path.source, DNS_UPSTREAM_IP_TEXT_MAX);
                        if (!w->interface[0] && (!family || !w->index)) w->index = if_nametoindex(path.interface);
                    }
                    w->candidates[family].valid_until = a->valid_until; break;
                }
            }
            if (!path.ip[0]) path.state = s->config.family && s->config.family != path.family ? DNS_PATH_FAMILY_DISABLED : DNS_PATH_NO_SOURCE;
            if (!w->candidates[family].ip[0] && !s->flags.proxyname[0]) (family ? w->source6 : w->source4)[0] = 0;
            paths[path_count++] = path;
        }
    }
    freeifaddrs(addresses);
    pthread_mutex_lock(&s->lock);
    for (unsigned i = 0; i < s->wan_count; i++) {
        struct dns_service_wan *old = s->wans + i, *fresh = next + i;
        if (!old->generation || old->index != fresh->index || strcmp(old->source4, fresh->source4) || strcmp(old->source6, fresh->source6)) {
            __atomic_add_fetch(&old->generation, 1, __ATOMIC_ACQ_REL); __atomic_store_n(&old->winner, 0, __ATOMIC_RELEASE);
            _dns_policy_wan_network_changed(old->policy, now);
            old->race_due = 0;
            __atomic_store_n(&old->family_retry_at[0], 0, __ATOMIC_RELEASE);
            __atomic_store_n(&old->family_retry_at[1], 0, __ATOMIC_RELEASE);
        }
        old->index = fresh->index;
        memcpy(old->source4, fresh->source4, sizeof(old->source4)); memcpy(old->source6, fresh->source6, sizeof(old->source6));
        memcpy(old->candidates, fresh->candidates, sizeof(old->candidates));
    }
    pthread_mutex_unlock(&s->lock);
    pthread_mutex_lock(&s->detail_lock);
    memcpy(s->detail.paths, paths, sizeof(paths)); s->detail.path_count = path_count;
    pthread_mutex_unlock(&s->detail_lock);
}

void _dns_paths_refresh(struct dns_upstream_service *service, unsigned long now)
{
    route_monitor();
    if (!service->desired) return;
    int dirty = __atomic_exchange_n(&service->paths_dirty, 0, __ATOMIC_ACQ_REL);
    if (!dirty && service->path_epoch == route_epoch && now < service->path_refresh_due) return;
    if (service->wan_count) {
        paths_refresh_wans(service);
        service->path_epoch = route_epoch; service->path_refresh_due = now + 5000;
        return;
    }
    struct dns_upstream_path_v1 paths[DNS_UPSTREAM_DETAIL_PATHS] = {0};
    unsigned count = service->desired->count;
    if (count > DNS_UPSTREAM_DETAIL_PATHS) count = DNS_UPSTREAM_DETAIL_PATHS;
    for (unsigned i = 0; i < count; i++) {
        safe_strncpy(paths[i].ip, service->desired->addresses[i].text, sizeof(paths[i].ip));
        paths[i].family = strchr(paths[i].ip, ':') ? 6 : 4;
        path_route(service, &paths[i], service->flags.ifname);
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
static void service_detail(struct dns_query_struct *query, struct dns_server_info *endpoint,
    unsigned kind, unsigned phase, int code, unsigned elapsed, unsigned limit, struct dns_packet *packet)
{
    if (!endpoint || (!endpoint->service && !endpoint->diagnostic) || kind >= DNS_DETAIL_COUNT) return;
    pthread_mutex_t *lock = endpoint->service ? &endpoint->service->detail_lock : &endpoint->diagnostic->lock;
    struct dns_upstream_policy_snapshot_v1 *detail = endpoint->service ? &endpoint->service->detail : &endpoint->diagnostic->detail;
    struct dns_upstream_event_context_v1 *contexts = endpoint->service ? endpoint->service->event_context : endpoint->diagnostic->context;
    struct dns_upstream_event_v1 event = {0};
    event.tick_ms = get_tick_count(); event.kind = kind; event.phase = phase; event.code = code;
    event.query_id = query ? query->sid : 0;
    pthread_mutex_lock(&endpoint->lock);
    event.tls_error = endpoint->service_tls_error;
    if (event.tls_error) ERR_error_string_n(event.tls_error, event.message, sizeof(event.message));
    else if (endpoint->service_system_error) safe_strncpy(event.message, strerror(endpoint->service_system_error), sizeof(event.message));
    event.system_error = endpoint->service_system_error; event.elapsed_ms = elapsed; event.limit_ms = limit;
    event.port = endpoint->port; event.family = strchr(endpoint->ip, ':') ? 6 : 4;
    safe_strncpy(event.ip, endpoint->ip, sizeof(event.ip));
    int http2 = endpoint->type == DNS_SERVER_HTTPS && !strcmp(endpoint->alpn_selected, "h2");
    pthread_mutex_unlock(&endpoint->lock);
    struct dns_upstream_event_context_v1 context = {0};
    struct timespec wall;
    if (clock_gettime(CLOCK_REALTIME, &wall) == 0 && wall.tv_sec >= 0)
        context.unix_ms = (uint64_t)wall.tv_sec * 1000 + wall.tv_nsec / 1000000;
    if (query) {
        safe_strncpy(context.domain, query->domain, sizeof(context.domain));
        context.qtype = query->qtype;
    }
    if (packet) {
        context.dns_summary_valid = 1; context.rcode = packet->head.rcode;
        context.truncated = packet->head.tc; context.answers = packet->head.ancount;
        context.authority = packet->head.nscount; context.additional = packet->head.nrcount;
        for (int section = DNS_RRS_AN; section < DNS_RRS_OPT; section++) {
            int count = 0;
            struct dns_rrs *rr = dns_get_rrs_start(packet, section, &count);
            for (int i = 0; i < count && rr; i++, rr = dns_get_rrs_next(packet, rr)) {
                context.a_records += rr->type == DNS_T_A;
                context.aaaa_records += rr->type == DNS_T_AAAA;
                context.cname_records += rr->type == DNS_T_CNAME;
                context.soa_records += rr->type == DNS_T_SOA;
            }
        }
    }
    struct dns_upstream_failure_event_v1 failure = {0};
    failure.origin_flags = query ? query->origin_flags : 0;
    failure.queue_wait_ms = query ? query->background_queue_wait_ms : 0;
    safe_strncpy(failure.interface, endpoint->flags.ifname, sizeof(failure.interface));
    failure.wan_generation = endpoint->service_wan_generation;
    int retained = kind == DNS_DETAIL_DNS_RCODE || kind == DNS_DETAIL_RESPONSE_TIMEOUT ||
        kind == DNS_DETAIL_QUERY_TIMEOUT || kind == DNS_DETAIL_CONNECT_TIMEOUT || kind == DNS_DETAIL_TRANSPORT_ERROR;
    if (retained) {
        _dns_attempt_get_progress(query, endpoint, &failure.progress);
        pthread_mutex_lock(&endpoint->lock);
        failure.connection_generation = kind == DNS_DETAIL_TRANSPORT_ERROR ?
            endpoint->service_error_connection_generation : endpoint->diagnostic_connection_generation;
        failure.active_attempts = kind == DNS_DETAIL_TRANSPORT_ERROR ?
            endpoint->service_error_active_attempts : endpoint->active_attempts;
        failure.tls_operation = endpoint->service_tls_operation;
        failure.tls_error_count = endpoint->service_tls_error_count;
        failure.tls_error_overflow = endpoint->service_tls_error_overflow;
        memcpy(failure.tls_errors, endpoint->service_tls_errors, sizeof(failure.tls_errors));
        failure.quic_close_valid = endpoint->service_quic_close_valid;
        failure.quic_close_local = endpoint->service_quic_close_local;
        failure.quic_close_transport = endpoint->service_quic_close_transport;
        failure.quic_close_code = endpoint->service_quic_close_code;
        failure.quic_close_frame = endpoint->service_quic_close_frame;
        pthread_mutex_unlock(&endpoint->lock);
        if (kind == DNS_DETAIL_RESPONSE_TIMEOUT) {
            if (!failure.progress.wire_started) failure.timeout_stage = DNS_TIMEOUT_NOT_SENT;
            else if (endpoint->type == DNS_SERVER_UDP) failure.timeout_stage = DNS_TIMEOUT_WAIT_RESPONSE;
            else if (http2)
                failure.timeout_stage = !failure.progress.request_complete ? DNS_TIMEOUT_SENDING :
                    !failure.progress.headers_received ? DNS_TIMEOUT_WAIT_HEADERS : DNS_TIMEOUT_READ_BODY;
            else if (endpoint->type == DNS_SERVER_TCP || endpoint->type == DNS_SERVER_TLS)
                failure.timeout_stage = failure.progress.request_complete ? DNS_TIMEOUT_WAIT_RESPONSE : DNS_TIMEOUT_SENDING;
        }
    }
    pthread_mutex_lock(lock);
    event.sequence = ++detail->sequence; detail->kind_counts[kind]++;
    context.sequence = event.sequence;
    if (retained) {
        struct dns_upstream_failure_snapshot_v1 **slot = endpoint->service ? &endpoint->service->failures : &endpoint->diagnostic->failures;
        if (!*slot) *slot = calloc(1, sizeof(**slot));
        struct dns_upstream_failure_snapshot_v1 *f = *slot;
        failure.event = event; failure.context = context;
        if (f && kind == DNS_DETAIL_DNS_RCODE) {
            unsigned rcode_slot = code >= 0 && code < 16 ? code : 16;
            f->rcode_counts[rcode_slot]++; f->last_rcode[rcode_slot] = failure;
        } else if (f) {
            int timeout = kind != DNS_DETAIL_TRANSPORT_ERROR;
            unsigned *count = timeout ? &f->timeout_count : &f->io_count;
            struct dns_upstream_failure_event_v1 *history = timeout ? f->timeouts : f->io_errors;
            if (*count < DNS_UPSTREAM_FAILURE_RECENT) (*count)++;
            memmove(history + 1, history, (*count - 1) * sizeof(*history));
            history[0] = failure;
            if (kind == DNS_DETAIL_RESPONSE_TIMEOUT) f->timeout_stages[failure.timeout_stage]++;
        }
    }
    if (kind == DNS_DETAIL_DNS_REJECT) detail->reject_counts[code >= 0 && code < DNS_REJECT_COUNT ? code : 0]++;
    /* Healthy idle probes stay in counters, preserving the bounded ring for failures and lifecycle events. */
    if (kind == DNS_DETAIL_KEEPALIVE_SENT || kind == DNS_DETAIL_KEEPALIVE_ACK) {
        pthread_mutex_unlock(lock); return;
    }
    if (detail->event_count == DNS_UPSTREAM_DETAIL_EVENTS) detail->dropped_events++;
    else detail->event_count++;
    memmove(&detail->events[1], &detail->events[0], (detail->event_count - 1) * sizeof(event));
    memmove(&contexts[1], &contexts[0],
        (detail->event_count - 1) * sizeof(context));
    detail->events[0] = event;
    contexts[0] = context;
    struct dns_upstream_event_source_v1 **sources = endpoint->service ?
        &endpoint->service->event_sources : &endpoint->diagnostic->event_sources;
    if (!*sources) *sources = calloc(DNS_UPSTREAM_DETAIL_EVENTS, sizeof(**sources));
    if (*sources) {
        memmove(*sources + 1, *sources, (detail->event_count - 1) * sizeof(**sources));
        (*sources)[0] = (struct dns_upstream_event_source_v1){.sequence = event.sequence,
            .origin_flags = query ? query->origin_flags : 0,
            .queue_wait_ms = query ? query->background_queue_wait_ms : 0,
            .priority = query ? query->priority : 0, .wan_generation = endpoint->service_wan_generation};
        safe_strncpy((*sources)[0].interface, endpoint->flags.ifname, sizeof((*sources)[0].interface));
    }
    pthread_mutex_unlock(lock);
}
void _dns_service_detail(struct dns_query_struct *query, struct dns_server_info *endpoint,
    unsigned kind, unsigned phase, int code, unsigned elapsed, unsigned limit)
{ service_detail(query, endpoint, kind, phase, code, elapsed, limit, NULL); }
void _dns_service_detail_dns(struct dns_query_struct *query, struct dns_server_info *endpoint,
    unsigned kind, unsigned phase, int code, struct dns_packet *packet)
{ service_detail(query, endpoint, kind, phase, code, 0, 0, packet); }
void _dns_service_response_time(struct dns_server_info *endpoint, unsigned elapsed)
{
    if (!endpoint->service && !endpoint->diagnostic) return;
    static const unsigned upper[] = {10, 25, 50, 100, 250, 500, 1000, 2000};
    unsigned bin = 0; while (bin < 8 && elapsed > upper[bin]) bin++;
    pthread_mutex_t *lock = endpoint->service ? &endpoint->service->detail_lock : &endpoint->diagnostic->lock;
    struct dns_upstream_policy_snapshot_v1 *detail = endpoint->service ? &endpoint->service->detail : &endpoint->diagnostic->detail;
    pthread_mutex_lock(lock); detail->response_histogram[bin]++; pthread_mutex_unlock(lock);
}
