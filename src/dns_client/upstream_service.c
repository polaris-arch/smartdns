/* Bounded logical upstream services. GPL-3.0-or-later. */
#include "upstream_observer.h"
#include "upstream_service.h"
#include "upstream_discovery.h"
#include "upstream_policy.h"
#include "server_info.h"
#include "group.h"
#include "query.h"
#include "client_socket.h"
#include "wake_event.h"
#include "smartdns/util.h"
#include "smartdns/dns_server.h"
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <ifaddrs.h>
#include <unistd.h>

static LIST_HEAD(services);
static LIST_HEAD(service_timers); /* client IO thread only */
static pthread_mutex_t registry_lock = PTHREAD_MUTEX_INITIALIZER;
static struct dns_upstream_service *pending_services;
static struct dns_service_turn *service_turn(struct dns_upstream_service *s, unsigned lane)
{ return lane ? &s->extra_turns[lane - 1] : &s->turn; }
static unsigned service_lanes(struct dns_upstream_service *s)
{ return s->wan_count ? s->wan_count : 1; }
static void service_release_eligibility(struct dns_upstream_service *s, struct dns_server_info *ep)
{
    /* Datagram pressure has no buffered writer. Keep its short retry deadline
     * for a single exit; other exits must remain independently eligible. */
    unsigned long retry = ep->type == DNS_SERVER_UDP && service_lanes(s) == 1 ?
        __atomic_load_n(&ep->service_retry_at, __ATOMIC_ACQUIRE) : 0;
    __atomic_store_n(&s->next_eligible, retry > get_tick_count() ? retry : 0, __ATOMIC_RELEASE);
}
int _dns_service_wan_turn_available(struct dns_upstream_service *s, unsigned lane)
{
    return lane < service_lanes(s) &&
        __atomic_load_n(&service_turn(s, lane)->turn_state, __ATOMIC_ACQUIRE) == DNS_SERVICE_TURN_IDLE;
}
static int service_turn_available(struct dns_upstream_service *s)
{
    for (unsigned i = 0; i < service_lanes(s); i++)
        if (__atomic_load_n(&service_turn(s, i)->turn_state, __ATOMIC_ACQUIRE) == DNS_SERVICE_TURN_IDLE) return 1;
    return 0;
}

void _dns_service_get(struct dns_upstream_service *s)
{ if (s) atomic_inc(&s->refs); }
void _dns_service_put(struct dns_upstream_service *s)
{
    if (!s || atomic_dec_return(&s->refs)) return;
    _dns_policy_service_release(s);
    free(s->failures);
    free(s->event_sources);
    free(s->desired);
    free(s->extra_turns);
    pthread_mutex_destroy(&s->detail_lock);
    pthread_mutex_destroy(&s->turn_lock);
    pthread_mutex_destroy(&s->lock);
    free(s);
}
static void service_queue(struct dns_upstream_service *s)
{
    if (!s || __atomic_load_n(&s->stopping, __ATOMIC_ACQUIRE)) return;
    if (__atomic_exchange_n(&s->wake_pending, 1, __ATOMIC_ACQ_REL)) return;
    _dns_service_get(s);
    struct dns_upstream_service *head;
    do {
        head = __atomic_load_n(&pending_services, __ATOMIC_ACQUIRE);
        s->pending_next = head;
    } while (!__atomic_compare_exchange_n(&pending_services, &head, s, 0, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE));
    _dns_client_do_wakeup_event();
}
void _dns_service_transport_changed(struct dns_server_info *endpoint)
{
    if (endpoint && endpoint->service && endpoint->service->wan_count &&
        __atomic_load_n(&endpoint->service_draining, __ATOMIC_ACQUIRE))
        __atomic_store_n(&endpoint->service->membership_dirty, 1, __ATOMIC_RELEASE);
    if (endpoint) { service_queue(endpoint->service); dns_server_refresh_notify(); }
}
/* A coalesced intrusive state-change hint, with its own query pin. Transport
 * code can publish while holding q->lock without taking the membership lock. */
static void observation_hint(struct dns_service_observation *o, int wake)
{
    if (!__atomic_load_n(&o->registered, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&o->settled, __ATOMIC_ACQUIRE)) return;
    _dns_client_query_get(o->query);
    if (__atomic_exchange_n(&o->hint_queued, 1, __ATOMIC_ACQ_REL)) {
        _dns_client_query_release(o->query); return;
    }
    struct dns_service_observation *head;
    do {
        head = __atomic_load_n(&o->service->hints, __ATOMIC_ACQUIRE);
        o->hint_next = head;
    } while (!__atomic_compare_exchange_n(&o->service->hints, &head, o, 0,
        __ATOMIC_RELEASE, __ATOMIC_ACQUIRE));
    if (wake) service_queue(o->service);
}
static void service_timer(struct dns_upstream_service *s, unsigned long due)
{
    list_del_init(&s->timer);
    s->timer_due = due;
    if (due == ULONG_MAX || s->stopping) return;
    struct dns_upstream_service *other;
    list_for_each_entry(other, &service_timers, timer) {
        if (other->timer_due > due) { list_add_tail(&s->timer, &other->timer); return; }
    }
    list_add_tail(&s->timer, &service_timers);
}
static void normalize_host(char *out, const char *host, size_t size)
{
    safe_strncpy(out, host, size);
    size_t n = strlen(out);
    if (n && out[n - 1] == '.') out[--n] = 0;
    for (size_t i = 0; i < n; i++) out[i] = tolower((unsigned char)out[i]);
}
static struct dns_upstream_service *service_find(const char *host, int port,
    dns_server_type_t type, const struct client_dns_server_flags *flags)
{
    char canonical[DNS_MAX_HOSTNAME]; normalize_host(canonical, host, sizeof(canonical));
    struct dns_upstream_service *s;
    list_for_each_entry(s, &services, list)
        if (s->port == port && s->type == type && !strcmp(s->host, canonical) &&
            !memcmp(&s->flags, flags, sizeof(*flags))) return s;
    return NULL;
}
static int address_is_local(int family, const unsigned char *address)
{
    if (family == AF_INET && address[0] == 127) return 1;
    if (family == AF_INET6 && IN6_IS_ADDR_LOOPBACK((const struct in6_addr *)address)) return 1;
    struct ifaddrs *interfaces = NULL;
    if (!getifaddrs(&interfaces)) {
        int found = 0;
        for (struct ifaddrs *it = interfaces; it; it = it->ifa_next) {
            if (!it->ifa_addr || it->ifa_addr->sa_family != family) continue;
            const void *candidate = family == AF_INET ?
                (void *)&((struct sockaddr_in *)it->ifa_addr)->sin_addr :
                (void *)&((struct sockaddr_in6 *)it->ifa_addr)->sin6_addr;
            if (!memcmp(candidate, address, family == AF_INET ? 4 : 16)) { found = 1; break; }
        }
        freeifaddrs(interfaces); return found;
    }
    /* A UDP connect without send performs only a kernel route lookup: no DNS,
     * handshake, or probe packet. It also works in netlink-restricted sandboxes. */
    int fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_storage remote = {0}, local = {0};
    socklen_t length;
    if (family == AF_INET) {
        struct sockaddr_in *a = (void *)&remote; a->sin_family = family; a->sin_port = htons(9);
        memcpy(&a->sin_addr, address, 4); length = sizeof(*a);
    } else {
        struct sockaddr_in6 *a = (void *)&remote; a->sin6_family = family; a->sin6_port = htons(9);
        memcpy(&a->sin6_addr, address, 16); length = sizeof(*a);
    }
    int result = connect(fd, (struct sockaddr *)&remote, length);
    socklen_t local_length = sizeof(local);
    if (!result) result = getsockname(fd, (struct sockaddr *)&local, &local_length);
    close(fd);
    if (result) return -1;
    const void *candidate = family == AF_INET ? (void *)&((struct sockaddr_in *)&local)->sin_addr :
        (void *)&((struct sockaddr_in6 *)&local)->sin6_addr;
    return !memcmp(candidate, address, family == AF_INET ? 4 : 16);
}
static int service_self_listener(const char *ip, int port, dns_server_type_t transport)
{
    unsigned char address[16];
    int family = inet_pton(AF_INET, ip, address) == 1 ? AF_INET :
        inet_pton(AF_INET6, ip, address) == 1 ? AF_INET6 : 0;
    if (!family) return 1;
    if (family == AF_INET6 && IN6_IS_ADDR_V4MAPPED((struct in6_addr *)address)) {
        memmove(address, address + 12, 4); family = AF_INET;
    }
    int datagram = transport == DNS_SERVER_UDP || transport == DNS_SERVER_QUIC || transport == DNS_SERVER_HTTP3;
    int match = dns_server_listener_match(family, address, port, datagram);
    if (match == 1) return 1;
    if (match == 2) return address_is_local(family, address) != 0;

    return 0;
}
/* Only the IO thread publishes membership. Revocation always precedes addition;
 * network teardown runs outside the service lock. Existing endpoint identities
 * survive RRset reorder and unchanged refreshes. */
static void service_reconcile(struct dns_upstream_service *s, unsigned long now)
{
    struct dns_server_info *retire[DNS_UPSTREAM_BACKENDS_MAX * 2];
    unsigned retire_count = 0;
    if (!s->desired) return;
    _dns_paths_refresh(s, now);
    pthread_mutex_lock(&s->lock);
    struct dns_discovery_snapshot eligible_set = *s->desired;
    eligible_set.count = 0;
    unsigned target_wan[DNS_DISCOVERY_ADDRESS_LIMIT] = {0};
    uint64_t target_generation[DNS_DISCOVERY_ADDRESS_LIMIT] = {0};
    if (s->wan_count) {
        for (unsigned lane = 0; lane < s->wan_count; lane++) for (unsigned family = 0; family < 2; family++) {
            struct dns_service_wan *w = s->wans + lane;
            if (!w->candidates[family].ip[0]) continue;
            unsigned at = eligible_set.count++;
            safe_strncpy(eligible_set.addresses[at].text, w->candidates[family].ip, sizeof(eligible_set.addresses[at].text));
            eligible_set.addresses[at].valid_until = w->candidates[family].valid_until;
            target_wan[at] = lane; target_generation[at] = w->generation;
        }
    } else for (unsigned i = 0; i < s->desired->count; i++)
        if (_dns_path_allowed(s, s->desired->addresses[i].text))
            eligible_set.addresses[eligible_set.count++] = s->desired->addresses[i];
    const struct dns_discovery_snapshot *set = &eligible_set;
    if (!set) { pthread_mutex_unlock(&s->lock); return; }
    for (unsigned i = 0; i < s->member_count; i++) {
        struct dns_server_info *ep = s->members[i];
        int wanted = -1;
        for (unsigned j = 0; j < set->count; j++)
            if (!strcmp(ep->ip, set->addresses[j].text) && (!s->wan_count ||
                (ep->service_wan == target_wan[j] && ep->service_wan_generation == target_generation[j]))) { wanted = j; break; }
        if (!ep->service_revoked && (wanted < 0 || (s->wan_count && ep->service_draining))) {
            __atomic_store_n(&ep->service_revoked, 1, __ATOMIC_RELEASE);
            ep->service_drain_until = now + 5000;
            if (s->wan_count) {
                uint64_t expected = ep->service_member_id;
                __atomic_compare_exchange_n(&s->wans[ep->service_wan].winner, &expected, 0, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
            }
        }
        if (!ep->service_revoked && wanted >= 0)
            __atomic_store_n(&ep->service_valid_until, set->addresses[wanted].valid_until, __ATOMIC_RELEASE);
        if (ep->service_revoked) {
            dns_client_server_info_get(ep);
            retire[retire_count++] = ep;
        }
    }
    pthread_mutex_unlock(&s->lock);
    for (unsigned i = 0; i < retire_count; i++) {
        struct dns_server_info *ep = retire[i];
        pthread_mutex_lock(&ep->lock);
        int done = !ep->active_attempts || now >= ep->service_drain_until;
        if (done) _dns_client_close_socket(ep);
        done = done && ep->fd < 0 && !ep->process_depth;
        pthread_mutex_unlock(&ep->lock);
        if (done) {
            pthread_mutex_lock(&s->lock);
            for (unsigned j = 0; j < s->member_count; j++) if (s->members[j] == ep) {
                memmove(&s->members[j], &s->members[j + 1], (s->member_count - j - 1) * sizeof(ep));
                s->member_count--;
                break;
            }
            pthread_mutex_unlock(&s->lock);
            _dns_client_server_info_remove(ep); /* registry ownership */
            dns_client_server_info_release(ep); /* membership ownership */
        }
        dns_client_server_info_release(ep); /* temporary pin */
    }
    pthread_mutex_lock(&s->lock);
    unsigned selected = 0;
    for (unsigned i = 0; i < s->member_count; i++) if (!s->members[i]->service_revoked) selected++;
    pthread_mutex_unlock(&s->lock);
    /* Discovery provides a canonical family-interleaved order. Static inputs
     * retain their explicit order. Retained members always have precedence. */
    for (unsigned i = 0; i < set->count && selected < s->config.max_backends; i++) {
        int exists = 0;
        pthread_mutex_lock(&s->lock);
        for (unsigned j = 0; j < s->member_count; j++)
            if (!s->members[j]->service_revoked && !strcmp(s->members[j]->ip, set->addresses[i].text) &&
                (!s->wan_count || (s->members[j]->service_wan == target_wan[i] &&
                    s->members[j]->service_wan_generation == target_generation[i]))) exists = 1;
        int full = s->member_count >= s->config.max_backends * 2;
        pthread_mutex_unlock(&s->lock);
        if (exists || full) continue;
        struct dns_server_info *ep = NULL;
        int added = s->wan_count ? _dns_client_service_endpoint_add_on_interface(s, set->addresses[i].text,
            s->wans[target_wan[i]].interface, &ep) : _dns_client_service_endpoint_add(s, set->addresses[i].text, &ep);
        if (added) continue;
        ep->service_wan = target_wan[i]; ep->service_wan_generation = target_generation[i];
        if (s->wan_count) __atomic_store_n(&ep->service_retry_at,
            __atomic_load_n(&s->wans[ep->service_wan].family_retry_at[!!strchr(ep->ip, ':')], __ATOMIC_ACQUIRE), __ATOMIC_RELEASE);
        pthread_mutex_lock(&s->lock);
        ep->service_member_id = ++s->member_sequence;
        __atomic_store_n(&ep->service_valid_until, set->addresses[i].valid_until, __ATOMIC_RELEASE);
        s->members[s->member_count++] = ep;
        selected++;
        pthread_mutex_unlock(&s->lock);
    }
    pthread_mutex_lock(&s->lock);
    __atomic_store_n(&s->selected_count, selected, __ATOMIC_RELEASE);
    s->discovered_count = set->discovered;
    s->rejected_count = set->rejected;
    s->stale = set->stale;
    s->freshness_until = set->expires;
    s->freshness_known = set->count != 0;
    unsigned long due = s->path_refresh_due;
    for (unsigned i = 0; i < s->member_count; i++) {
        struct dns_server_info *ep = s->members[i];
        if (ep->service_revoked && ep->service_drain_until < due) due = ep->service_drain_until;
        if (ep->service_retry_at > now && ep->service_retry_at < due) due = ep->service_retry_at;
    }
    pthread_mutex_unlock(&s->lock);
    service_timer(s, due);
}
static int discovery_address_compare(const void *left, const void *right)
{
    const struct dns_discovery_address *a = left, *b = right;
    if (a->family != b->family) return a->family < b->family ? -1 : 1;
    return memcmp(a->addr, b->addr, a->family == AF_INET ? 4 : 16);
}
static void service_discovered(const struct dns_discovery_snapshot *snapshot, void *user)
{
    struct dns_upstream_service *s = user;
    if (s->stopping) return;
    struct dns_discovery_snapshot ordered = *snapshot;
    qsort(ordered.addresses, ordered.count, sizeof(ordered.addresses[0]), discovery_address_compare);
    snapshot = &ordered;
    *s->desired = *snapshot;
    s->path_refresh_due = 0;
    unsigned v4[DNS_DISCOVERY_ADDRESS_LIMIT], v6[DNS_DISCOVERY_ADDRESS_LIMIT];
    unsigned n4 = 0, n6 = 0, kept = 0;
    for (unsigned i = 0; i < snapshot->count; i++) {
        if (service_self_listener(snapshot->addresses[i].text, s->port, s->type)) {
            s->desired->rejected++; continue;
        }
        if (snapshot->addresses[i].family == AF_INET) v4[n4++] = i;
        else v6[n6++] = i;
    }
    /* Canonical ordering within each family, alternating families when filling
     * new slots. Reconcile keeps retained identities ahead of all new members. */
    for (unsigned i = 0; i < n4 || i < n6; i++) {
        if (i < n4) s->desired->addresses[kept++] = snapshot->addresses[v4[i]];
        if (i < n6) s->desired->addresses[kept++] = snapshot->addresses[v6[i]];
    }
    s->desired->count = kept;
    service_reconcile(s, get_tick_count());
    service_queue(s);
}
int dns_client_add_service(const char *host, int port, dns_server_type_t type,
    const struct client_dns_server_flags *flags, const struct dns_upstream_pool_config *pool)
{
    if (!host || !flags || !pool || !pool->max_backends || pool->max_backends > DNS_UPSTREAM_BACKENDS_MAX ||
        pool->ip_count > DNS_UPSTREAM_BACKENDS_MAX ||
        (pool->family && pool->family != 4 && pool->family != 6) ||
        pool->response_timeout_ms > 10000 || pool->query_timeout_ms > 60000 ||
        pool->connect_timeout_ms > 10000 || pool->connect_delay_ms > 2000 || pool->keepalive_ms > 600000 ||
        (pool->query_timeout_ms && (pool->response_timeout_ms > pool->query_timeout_ms ||
            pool->connect_timeout_ms > pool->query_timeout_ms)) ||
        (flags->proxyname[0] && flags->upstream_wan_count) || flags->upstream_round_robin ||
        (int)type < 0 || type == DNS_SERVER_MDNS || type >= DNS_SERVER_TYPE_END ||
        flags->upstream_wan_count > DNS_UPSTREAM_WANS_MAX ||
        flags->max_upstream_connections > pool->max_backends) return -1;
    for (unsigned i = 0; i < flags->upstream_wan_count; i++) {
        const char *name = flags->upstream_wan_interfaces[i];
        size_t length = strnlen(name, sizeof(flags->upstream_wan_interfaces[i]));
        if (!length || length == sizeof(flags->upstream_wan_interfaces[i])) return -1;
        for (size_t j = 0; j < length; j++) if (!isalnum((unsigned char)name[j]) && !strchr("_.:-", name[j])) return -1;
        for (unsigned j = 0; j < i; j++) if (!strcmp(name, flags->upstream_wan_interfaces[j])) return -1;
    }
    pthread_mutex_lock(&registry_lock);
    if (service_find(host, port, type, flags)) { pthread_mutex_unlock(&registry_lock); return -1; }
    struct dns_upstream_service *s = calloc(1, sizeof(*s));
    if (!s) { pthread_mutex_unlock(&registry_lock); return -1; }
    s->desired = calloc(1, sizeof(*s->desired));
    if (!s->desired) { free(s); pthread_mutex_unlock(&registry_lock); return -1; }
    atomic_set(&s->refs, 1); pthread_mutex_init(&s->lock, NULL); pthread_mutex_init(&s->turn_lock, NULL); pthread_mutex_init(&s->detail_lock, NULL);
    INIT_LIST_HEAD(&s->list); INIT_LIST_HEAD(&s->timer); INIT_LIST_HEAD(&s->waiters);
    normalize_host(s->host, host, sizeof(s->host));
    s->port = port; s->type = type; s->flags = *flags; s->config = *pool;
    s->wan_count = flags->upstream_wan_count ? flags->upstream_wan_count : 1;
    if (s->wan_count > 1) {
        s->extra_turns = calloc(s->wan_count - 1, sizeof(*s->extra_turns));
        if (!s->extra_turns) { _dns_service_put(s); pthread_mutex_unlock(&registry_lock); return -1; }
    }
    s->config.max_backends = s->wan_count * 2;
    for (unsigned i = 0; i < s->wan_count; i++)
        safe_strncpy(s->wans[i].interface, flags->upstream_wan_count ? flags->upstream_wan_interfaces[i] : flags->ifname,
            sizeof(s->wans[i].interface));
    if (!s->config.response_timeout_ms) s->config.response_timeout_ms = 5000;
    if (!s->config.query_timeout_ms) s->config.query_timeout_ms = 8000;
    if (!s->config.connect_timeout_ms) s->config.connect_timeout_ms = 3000;
    if (!s->config.connect_delay_ms && !s->config.connect_delay_set) s->config.connect_delay_ms = 250;
    if (!s->config.keepalive_ms && !s->config.keepalive_disabled) s->config.keepalive_ms = 30000;
    s->timer_due = ULONG_MAX;
    if (_dns_policy_service_init(s)) { _dns_service_put(s); pthread_mutex_unlock(&registry_lock); return -1; }
    list_add_tail(&s->list, &services);
    pthread_mutex_unlock(&registry_lock);
    if (!(flags->server_flag & SERVER_FLAG_EXCLUDE_DEFAULT) &&
        _dns_client_add_service_group(DNS_SERVER_GROUP_DEFAULT, s)) return -1;
    return 0;
}
int dns_client_add_service_to_group(const char *group, const char *host, int port,
    dns_server_type_t type, const struct client_dns_server_flags *flags)
{
    pthread_mutex_lock(&registry_lock);
    struct dns_upstream_service *s = service_find(host, port, type, flags);
    if (s) _dns_service_get(s);
    pthread_mutex_unlock(&registry_lock);
    if (!s) return -1;
    int ret = _dns_client_add_service_group(group, s);
    _dns_service_put(s);
    return ret;
}
static int group_compare(const void *a, const void *b) { return strcmp(a, b); }
static int service_identity(struct dns_upstream_service *s)
{
    struct dns_upstream_service_snapshot_v1 *v = &s->stats;
    struct dns_server_group *group;
    unsigned long bucket;
    struct hlist_node *tmp;
    hash_for_each_safe(client.group, bucket, tmp, group, node) {
        struct dns_server_group_member *member;
        list_for_each_entry(member, &group->head, list) if (member->service == s) {
            if (v->group_count >= 64 || strlen(group->group_name) >= sizeof(v->groups[0])) return -1;
            safe_strncpy(v->groups[v->group_count++], group->group_name, sizeof(v->groups[0]));
        }
    }
    qsort(v->groups, v->group_count, sizeof(v->groups[0]), group_compare);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx || !EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) { EVP_MD_CTX_free(ctx); return -1; }
    /* Canonical byte encoding: no padding/union tail/host-endian bytes and no
     * resource knobs or address membership in the restart-stable identity. */
#define ID_STR(value) EVP_DigestUpdate(ctx, (value), strlen(value) + 1)
#define ID_NUM(value) do { uint64_t n_ = (uint64_t)(value); unsigned char b_[8]; \
    for (unsigned j_ = 0; j_ < 8; j_++) b_[7-j_] = (unsigned char)(n_ >> (j_*8)); \
    EVP_DigestUpdate(ctx, b_, sizeof(b_)); } while (0)
    ID_STR(s->host); ID_NUM(s->port); ID_NUM(s->type);
    ID_NUM(s->flags.server_flag); ID_NUM(s->flags.result_flag); ID_NUM(s->flags.set_mark);
    ID_NUM(s->flags.tcp_keepalive); ID_NUM(s->flags.drop_packet_latency_ms); ID_NUM(s->flags.fallback);
    ID_STR(s->flags.quota_group); ID_STR(s->flags.proxyname); ID_STR(s->flags.ifname);
    ID_NUM(s->flags.subnet_all_query_types);
    ID_NUM(s->flags.ipv4_ecs.enable); ID_STR(s->flags.ipv4_ecs.ip); ID_NUM(s->flags.ipv4_ecs.subnet);
    ID_NUM(s->flags.ipv6_ecs.enable); ID_STR(s->flags.ipv6_ecs.ip); ID_NUM(s->flags.ipv6_ecs.subnet);
    if (s->type == DNS_SERVER_HTTPS || s->type == DNS_SERVER_HTTP3) {
        const struct client_dns_server_flag_https *f = &s->flags.https;
        ID_NUM(f->spi_len); EVP_DigestUpdate(ctx, f->spki, f->spi_len);
        ID_STR(f->hostname); ID_STR(f->httphost); ID_STR(f->proxyname); ID_STR(f->path);
        ID_STR(f->tls_host_verify); ID_STR(f->alpn); ID_NUM(f->skip_check_cert);
    } else if (s->type == DNS_SERVER_TLS || s->type == DNS_SERVER_QUIC) {
        const struct client_dns_server_flag_tls *f = &s->flags.tls;
        ID_NUM(f->spi_len); EVP_DigestUpdate(ctx, f->spki, f->spi_len);
        ID_STR(f->hostname); ID_STR(f->tls_host_verify); ID_STR(f->alpn); ID_NUM(f->skip_check_cert);
    } else if (s->type == DNS_SERVER_UDP) ID_NUM(s->flags.udp.ttl);
    ID_NUM(v->group_count);
    for (unsigned i = 0; i < v->group_count; i++) ID_STR(v->groups[i]);
#undef ID_STR
#undef ID_NUM
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned length = 0;
    int ok = EVP_DigestFinal_ex(ctx, digest, &length); EVP_MD_CTX_free(ctx);
    if (!ok || length != 32) return -1;
    for (unsigned i = 0; i < length; i++) snprintf(s->id + i * 2, 3, "%02x", digest[i]);
    v->struct_size = sizeof(*v); v->version = 1;
    safe_strncpy(v->service_id, s->id, sizeof(v->service_id));
    safe_strncpy(v->authority, s->host, sizeof(v->authority));
    if (s->type == DNS_SERVER_HTTPS || s->type == DNS_SERVER_HTTP3)
        safe_strncpy(v->path, s->flags.https.path, sizeof(v->path));
    v->port = s->port; v->transport = s->type; v->pool_enabled = 1;
    v->backend_cap = s->config.max_backends;
    return 0;
}
int dns_client_services_start(void)
{
    struct dns_upstream_service *s;
    pthread_mutex_lock(&registry_lock);
    list_for_each_entry(s, &services, list) {
        if (service_identity(s)) { pthread_mutex_unlock(&registry_lock); return -1; }
        struct dns_upstream_service *prior;
        list_for_each_entry(prior, &services, list) {
            if (prior == s) break;
            if (!strcmp(prior->id, s->id)) {
                tlog(TLOG_ERROR, "duplicate logical upstream identity for %s; use one declaration", s->host);
                pthread_mutex_unlock(&registry_lock); return -1;
            }
        }
        for (unsigned i = 0; i < s->config.ip_count; i++) {
            if (service_self_listener(s->config.ips[i], s->port, s->type)) {
                tlog(TLOG_ERROR, "pool %s endpoint %s:%d targets this SmartDNS listener", s->host, s->config.ips[i], s->port);
                pthread_mutex_unlock(&registry_lock); return -1;
            }
        }
        if (!s->config.ip_count) {
            struct dns_server_group *bootstrap = _dns_client_get_group("bootstrap-dns");
            if (!bootstrap || list_empty(&bootstrap->head) || bootstrap->service_members) {
                pthread_mutex_unlock(&registry_lock); return -1;
            }
            struct dns_server_group_member *member;
            list_for_each_entry(member, &bootstrap->head, list) {
                if (!member->server || member->server->proxy_name[0] ||
                    member->server->type == DNS_SERVER_MDNS || check_is_ipaddr(member->server->ip) ||
                    service_self_listener(member->server->ip, member->server->port, member->server->type)) {
                    pthread_mutex_unlock(&registry_lock); return -1;
                }
            }
        }
    }
    /* All configurations have passed before any pool discovery/socket creation. */
    list_for_each_entry(s, &services, list) service_queue(s);
    pthread_mutex_unlock(&registry_lock);
    return 0;
}

#ifdef TEST
void (*_dns_service_observe_published_test_hook)(struct dns_service_observation *);
#endif
static void waiter_remove(struct dns_upstream_service *s, struct dns_service_observation *o)
{
    if (!o->waiting) return;
    o->waiting = 0; list_del_init(&o->waiter);
    if (s->waiting_count) s->waiting_count--;
}
static void waiter_add(struct dns_upstream_service *s, struct dns_service_observation *o)
{
    if (o->waiting) return;
    if (s->waiting_count >= 256) {
        s->queue_rejected++;
        __atomic_store_n(&o->end_reason, DNS_END_BUDGET_OR_CANCEL, __ATOMIC_RELAXED);
        __atomic_store_n(&o->last_wait, DNS_WAIT_CONCURRENCY, __ATOMIC_RELAXED);
        __atomic_store_n(&o->terminal, 1, __ATOMIC_RELEASE);
        return;
    }
    list_add_tail(&o->waiter, &s->waiters); o->waiting = 1;
    if (++s->waiting_count > s->waiting_peak) s->waiting_peak = s->waiting_count;
}
static struct dns_service_observation *service_observe(struct dns_upstream_service *s, struct dns_query_struct *q)
{
    struct dns_service_observation *o;
    pthread_mutex_lock(&q->lock);
    for (o = q->service_observations; o; o = o->next) if (o->service == s) break;
    if (o || q->terminal) { pthread_mutex_unlock(&q->lock); return o; }
    pthread_mutex_unlock(&q->lock);
    struct dns_service_observation *fresh = calloc(1, sizeof(*fresh));
    if (!fresh) return NULL;
    pthread_mutex_lock(&q->lock);
    for (o = q->service_observations; o; o = o->next) if (o->service == s) break;
    if (o || q->terminal) { pthread_mutex_unlock(&q->lock); free(fresh); return o; }
    o = fresh; o->service = s; o->query = q; o->end_reason = DNS_END_OTHER;
    INIT_LIST_HEAD(&o->waiter);
    _dns_service_get(s); _dns_client_query_get(q);
    o->next = q->service_observations; q->service_observations = o;
    pthread_mutex_unlock(&q->lock);
#ifdef TEST
    if (_dns_service_observe_published_test_hook) _dns_service_observe_published_test_hook(o);
#endif
    pthread_mutex_lock(&s->lock);
    stats_inc(&s->stats.query_count); stats_inc(&s->stats.in_flight);
    waiter_add(s, o);
    /* Publication in the query list precedes service registration without
     * nesting query -> service locks. Readers may mark terminal, but cannot
     * select or enqueue a settlement hint until this release. The publisher
     * reconciles any terminal mark made during the registration window. */
    __atomic_store_n(&o->registered, 1, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&s->lock);
    if (__atomic_load_n(&o->terminal, __ATOMIC_ACQUIRE)) observation_hint(o, 1);
    return o;
}
unsigned dns_client_background_wait(const char *name, unsigned priority)
{
    unsigned long now = get_tick_count(); int ready = 0; unsigned wait = 1000;
    pthread_mutex_lock(&client.server_list_lock);
    struct dns_server_group *groups[] = {_dns_client_get_dnsserver_group(name && *name ? name : NULL), _dns_client_get_group("fallback")};
    for (unsigned pass = 0; pass < 2 && !ready; pass++) {
        if (!groups[pass] || (pass && groups[pass] == groups[0])) continue;
        struct dns_server_group_member *member;
        list_for_each_entry(member, &groups[pass]->head, list) {
            struct dns_upstream_service *s = member->service;
            if (!s) {
                struct dns_server_info *ep = member->server;
                if (ep && !ep->prohibit && (!ep->flags.max_concurrent_queries ||
                    __atomic_load_n(&ep->active_attempts, __ATOMIC_ACQUIRE) < ep->flags.max_concurrent_queries)) {
                    unsigned long due = _dns_policy_background_wait(ep, now);
                    if (!due) { ready = 1; break; }
                    if (due < wait) wait = due;
                }
                continue;
            }
            __atomic_store_n(&s->background_demand_until, now + 250, __ATOMIC_RELEASE);
            service_queue(s); /* warm a cold connection without a full DNS request */
            pthread_mutex_lock(&s->lock);
            int higher = 0; struct dns_service_observation *o;
            list_for_each_entry(o, &s->waiters, waiter) if (o->query->priority < priority &&
                !__atomic_load_n(&o->terminal, __ATOMIC_ACQUIRE) && !__atomic_load_n(&o->settled, __ATOMIC_ACQUIRE)) { higher = 1; break; }
            if (!higher && !s->stopping && (!s->flags.max_concurrent_queries ||
                __atomic_load_n(&s->active_attempts, __ATOMIC_ACQUIRE) < s->flags.max_concurrent_queries)) for (unsigned i = 0; i < s->member_count; i++) {
                struct dns_server_info *ep = s->members[i];
                if (ep->service_revoked || ep->service_draining || ep->service_rotation || ep->service_valid_until <= now ||
                    !_dns_service_wan_turn_available(s, ep->service_wan)) continue;
                if (s->wan_count) {
                    struct dns_service_wan *wan = &s->wans[ep->service_wan];
                    uint64_t winner = __atomic_load_n(&wan->winner, __ATOMIC_ACQUIRE);
                    if ((winner && winner != ep->service_member_id) || ep->service_wan_generation != wan->generation) continue;
                }
                if (ep->type != DNS_SERVER_UDP && !__atomic_load_n(&ep->service_protocol_ready, __ATOMIC_ACQUIRE)) continue;
                unsigned long due = _dns_policy_background_wait(ep, now);
                unsigned long retry = __atomic_load_n(&ep->service_retry_at, __ATOMIC_ACQUIRE);
                if (retry > now && retry - now > due) due = retry - now;
                if (!due) { ready = 1; break; }
                if (due < wait) wait = due;
            }
            pthread_mutex_unlock(&s->lock);
            if (ready) break;
        }
    }
    pthread_mutex_unlock(&client.server_list_lock); return ready ? 0 : wait;
}
int dns_client_background_ready(const char *name, unsigned priority)
{ return dns_client_background_wait(name, priority) == 0; }
int _dns_service_endpoint_eligible(struct dns_server_info *ep, unsigned long now)
{
    if (ep->service && ep->service->wan_count) {
        struct dns_service_wan *w = ep->service->wans + ep->service_wan;
        uint64_t winner = __atomic_load_n(&w->winner, __ATOMIC_ACQUIRE);
        if ((winner && winner != ep->service_member_id) ||
            ep->service_wan_generation != __atomic_load_n(&w->generation, __ATOMIC_ACQUIRE)) return 0;
    }
    return !__atomic_load_n(&ep->service_draining, __ATOMIC_ACQUIRE) && !__atomic_load_n(&ep->service_revoked, __ATOMIC_ACQUIRE) &&
        now >= __atomic_load_n(&ep->service_retry_at, __ATOMIC_ACQUIRE) &&
        (!ep->service || now < __atomic_load_n(&ep->service_valid_until, __ATOMIC_ACQUIRE)) &&
        !_dns_policy_endpoint_cooldown(ep, now);
}
struct dns_server_info *_dns_service_select(struct dns_upstream_service *s, struct dns_query_struct *q,
    int (*eligible)(struct dns_server_info *, void *), void *context)
{
    struct dns_service_observation *o = service_observe(s, q);
    if (!o || !__atomic_load_n(&o->registered, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&o->terminal, __ATOMIC_ACQUIRE) || __atomic_load_n(&o->settled, __ATOMIC_ACQUIRE)) return NULL;
    unsigned long now = get_tick_count();
    if (q->created_tick && s->config.query_timeout_ms && now >= q->created_tick && now - q->created_tick >= s->config.query_timeout_ms) {
        _dns_service_query_expired(q, s); return NULL;
    }
    if (__atomic_load_n(&o->active_attempts, __ATOMIC_ACQUIRE)) return NULL;
    if (!__atomic_load_n(&s->selected_count, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&o->last_wait, DNS_WAIT_NO_BACKEND, __ATOMIC_RELAXED); return NULL;
    }
    if (now < __atomic_load_n(&s->next_eligible, __ATOMIC_ACQUIRE)) {
        unsigned why = __atomic_load_n(&s->next_wait, __ATOMIC_RELAXED);
        __atomic_store_n(&o->last_wait, why ? why : DNS_WAIT_SCHEDULER, __ATOMIC_RELAXED); return NULL;
    }
    unsigned why = DNS_WAIT_NONE;
    unsigned long wait = _dns_policy_service_wait_reason(s, now, &why);
    if (wait) {
        __atomic_store_n(&o->last_wait, why, __ATOMIC_RELAXED);
        __atomic_store_n(&s->next_wait, why, __ATOMIC_RELAXED);
        __atomic_store_n(&s->next_eligible, now + wait, __ATOMIC_RELEASE); service_queue(s); return NULL;
    }
    struct dns_server_info *candidates[DNS_UPSTREAM_BACKENDS_MAX];
    unsigned count = 0;
    pthread_mutex_lock(&s->lock);
    unsigned active = __atomic_load_n(&s->active_attempts, __ATOMIC_ACQUIRE);
    if (s->stopping || !service_turn_available(s) ||
        (s->flags.max_concurrent_queries && active >= s->flags.max_concurrent_queries)) {
        __atomic_store_n(&o->last_wait, s->flags.max_concurrent_queries &&
            active >= s->flags.max_concurrent_queries ?
            DNS_WAIT_CONCURRENCY : DNS_WAIT_TURN, __ATOMIC_RELAXED);
        pthread_mutex_unlock(&s->lock); return NULL;
    }
    if (q->priority) {
        struct dns_service_observation *other;
        list_for_each_entry(other, &s->waiters, waiter) {
            if (!other->terminal && !other->settled && !other->writer_pending &&
                other->query->priority < q->priority && !__atomic_load_n(&other->active_attempts, __ATOMIC_ACQUIRE)) {
                __atomic_store_n(&o->last_wait, DNS_WAIT_TURN, __ATOMIC_RELAXED);
                pthread_mutex_unlock(&s->lock); service_queue(s); return NULL;
            }
        }
    }
    /* A query has at most one live attempt in this service, independent of IP. */
    if (__atomic_load_n(&o->writer_pending, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&o->last_wait, DNS_WAIT_WRITE, __ATOMIC_RELAXED);
        pthread_mutex_unlock(&s->lock); return NULL;
    }
    for (unsigned pass = 0; pass < 2; pass++) {
        for (unsigned i = 0; i < s->member_count; i++) {
            struct dns_server_info *ep = s->members[i];
            if (ep->service_rotation || !_dns_service_endpoint_eligible(ep, now) ||
                __atomic_load_n(&service_turn(s, ep->service_wan)->turn_state, __ATOMIC_ACQUIRE) != DNS_SERVICE_TURN_IDLE ||
                (pass == 0 ? ep->service_member_id <= s->cursor : ep->service_member_id > s->cursor)) continue;
            if (count < DNS_UPSTREAM_BACKENDS_MAX) { candidates[count++] = ep; dns_client_server_info_get(ep); }
        }
    }
    if (!count) { __atomic_store_n(&o->last_wait, DNS_WAIT_NO_BACKEND, __ATOMIC_RELAXED); pthread_mutex_unlock(&s->lock); return NULL; }
    pthread_mutex_lock(&s->turn_lock);
    waiter_remove(s, o);
    __atomic_store_n(&o->last_wait, DNS_WAIT_WRITE, __ATOMIC_RELAXED);
    __atomic_store_n(&o->writer_pending, 1, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&s->turn_lock);
    pthread_mutex_unlock(&s->lock);
    struct dns_server_info *chosen = NULL;
    struct dns_service_turn *leased = NULL;
    int cancelled = 0;
    for (unsigned i = 0; i < count; i++) {
        struct dns_server_info *ep = candidates[i];
        if (eligible && !eligible(ep, context)) continue;
        if (ep->type != DNS_SERVER_UDP && (ep->status != DNS_SERVER_STATUS_CONNECTED ||
            !__atomic_load_n(&ep->service_protocol_ready, __ATOMIC_ACQUIRE))) {
            unsigned cap = s->flags.max_upstream_connections ? s->flags.max_upstream_connections : s->selected_count;
            if (ep->fd < 0 && cap && __atomic_load_n(&s->connections, __ATOMIC_ACQUIRE) >= cap) continue;
            /* Warmup is asynchronous. An unready candidate must never hold up
             * a different WAN that already has a healthy connection. */
            continue;
        }
        struct dns_service_turn *turn = service_turn(s, ep->service_wan);
        pthread_mutex_lock(&s->turn_lock);
        if (__atomic_load_n(&o->terminal, __ATOMIC_ACQUIRE) || __atomic_load_n(&s->stopping, __ATOMIC_ACQUIRE)) {
            pthread_mutex_unlock(&s->turn_lock); break;
        }
        if (turn->turn_state != DNS_SERVICE_TURN_IDLE) { pthread_mutex_unlock(&s->turn_lock); continue; }
        turn->turn_observation = o; turn->turn_endpoint = NULL; turn->turn_sequence++;
        turn->cancel_requested = 0;
        __atomic_store_n(&turn->turn_state, DNS_SERVICE_TURN_SELECTING, __ATOMIC_RELEASE);
        pthread_mutex_unlock(&s->turn_lock);
        if (_dns_attempt_begin(q, ep) != DNS_ADMIT_OK) {
            pthread_mutex_lock(&s->turn_lock);
            turn->turn_observation = NULL;
            __atomic_store_n(&turn->turn_state, DNS_SERVICE_TURN_IDLE, __ATOMIC_RELEASE);
            pthread_mutex_unlock(&s->turn_lock); continue;
        }
        unsigned gen = _dns_attempt_generation(q, ep);
        pthread_mutex_lock(&s->turn_lock);
        turn->turn_endpoint = ep; dns_client_server_info_get(ep); /* lease pin */
        turn->turn_attempt_generation = gen;
        cancelled = turn->cancel_requested || __atomic_load_n(&o->terminal, __ATOMIC_ACQUIRE) ||
            __atomic_load_n(&s->stopping, __ATOMIC_ACQUIRE);
        __atomic_store_n(&turn->turn_state, cancelled ? DNS_SERVICE_TURN_ABORT_PENDING : DNS_SERVICE_TURN_RESERVED,
            __ATOMIC_RELEASE);
        leased = turn;
        pthread_mutex_unlock(&s->turn_lock);
        chosen = ep; dns_client_server_info_get(chosen); break;
    }
    for (unsigned i = 0; i < count; i++) dns_client_server_info_release(candidates[i]);
    pthread_mutex_lock(&s->turn_lock);
    if (!leased) __atomic_store_n(&o->writer_pending, 0, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&s->turn_lock);
    if (cancelled && chosen) {
        _dns_attempt_retire(q, chosen, 0);
        dns_client_server_info_release(chosen); chosen = NULL;
    }
    if (!chosen) {
        if (!leased) observation_hint(o, 0);
        if (dns_query_budget_exhausted(q->budget) || !dns_query_budget_remaining_ms(q->budget))
            __atomic_store_n(&o->terminal, 1, __ATOMIC_RELEASE);
        else if (!__atomic_load_n(&o->terminal, __ATOMIC_ACQUIRE)) {
            /* No actual progress: releasing our reservation is not an eligibility
             * event. Back off once per service rather than self-feeding eventfd. */
            __atomic_store_n(&s->next_wait, DNS_WAIT_SCHEDULER, __ATOMIC_RELAXED);
            __atomic_store_n(&s->next_eligible, now + 100, __ATOMIC_RELEASE);
        }
        service_queue(s);
    }
    return chosen; /* caller owns the endpoint pin */
}
/* Leaf arbitration lock protects owner identity together with state. A SELECTING
 * owner cannot be finalized by cancellation until it publishes its attempt. */
static int turn_matches(struct dns_service_turn *turn, struct dns_query_struct *q,
    struct dns_server_info *ep, unsigned generation)
{
    return turn->turn_endpoint == ep && turn->turn_observation && turn->turn_observation->query == q &&
        (!generation || generation == turn->turn_attempt_generation);
}
int _dns_service_write_begin(struct dns_query_struct *q, struct dns_server_info *ep, unsigned generation)
{
    struct dns_upstream_service *s = ep->service;
    if (!s) return DNS_ADMIT_OK;
    int ret = DNS_ADMIT_DONE;
    struct dns_service_turn *turn = service_turn(s, ep->service_wan);
    pthread_mutex_lock(&s->turn_lock);
    if (turn_matches(turn, q, ep, generation) && !turn->cancel_requested && !__atomic_load_n(&s->stopping, __ATOMIC_ACQUIRE) &&
        _dns_service_endpoint_eligible(ep, get_tick_count())) {
        unsigned state = __atomic_load_n(&turn->turn_state, __ATOMIC_ACQUIRE);
        if (state == DNS_SERVICE_TURN_RESERVED || state == DNS_SERVICE_TURN_WRITE_WAIT) {
            __atomic_store_n(&turn->turn_state, DNS_SERVICE_TURN_WRITING, __ATOMIC_RELEASE);
            ret = DNS_ADMIT_OK;
        } else if (state == DNS_SERVICE_TURN_WRITING) ret = DNS_ADMIT_WAIT;
    }
    pthread_mutex_unlock(&s->turn_lock);
    return ret;
}
void _dns_service_write_result(struct dns_query_struct *q, struct dns_server_info *ep,
    unsigned generation, int accepted, int retryable)
{
    struct dns_upstream_service *s = ep->service;
    if (!s) return;
    int wake = 0;
    struct dns_service_turn *turn = service_turn(s, ep->service_wan);
    pthread_mutex_lock(&s->turn_lock);
    if (turn_matches(turn, q, ep, generation) && turn->turn_state == DNS_SERVICE_TURN_WRITING) {
        unsigned next;
        if (accepted > 0) {
            turn->turn_accepted_tick = get_tick_count(); next = DNS_SERVICE_TURN_COMMIT_PENDING;
        } else next = retryable && !turn->cancel_requested ? DNS_SERVICE_TURN_WRITE_WAIT :
            DNS_SERVICE_TURN_ABORT_PENDING;
        __atomic_store_n(&turn->turn_state, next, __ATOMIC_RELEASE);
        if (next == DNS_SERVICE_TURN_WRITE_WAIT)
            __atomic_store_n(&turn->turn_observation->last_wait, DNS_WAIT_WRITE, __ATOMIC_RELAXED);
        wake = next != DNS_SERVICE_TURN_WRITE_WAIT;
    }
    pthread_mutex_unlock(&s->turn_lock);
    if (wake) {
        service_release_eligibility(s, ep);
        service_queue(s); dns_server_refresh_notify();
    }
}
static void turn_cancel_locked(struct dns_service_turn *turn)
{
    turn->cancel_requested = 1;
    if (turn->turn_state == DNS_SERVICE_TURN_RESERVED || turn->turn_state == DNS_SERVICE_TURN_WRITE_WAIT)
        __atomic_store_n(&turn->turn_state, DNS_SERVICE_TURN_ABORT_PENDING, __ATOMIC_RELEASE);
}
int _dns_service_write_pending(struct dns_query_struct *q, struct dns_server_info *ep, unsigned generation)
{
    struct dns_upstream_service *s = ep->service;
    if (!s) return 0;
    struct dns_service_turn *turn = service_turn(s, ep->service_wan);
    pthread_mutex_lock(&s->turn_lock);
    int pending = turn_matches(turn, q, ep, generation) &&
        (turn->turn_state == DNS_SERVICE_TURN_WRITING || turn->turn_state == DNS_SERVICE_TURN_COMMIT_PENDING);
    pthread_mutex_unlock(&s->turn_lock);
    return pending;
}
void _dns_service_unsent_retire(struct dns_query_struct *q, struct dns_server_info *ep, unsigned generation)
{
    struct dns_upstream_service *s = ep->service;
    if (!s) return;
    struct dns_service_turn *turn = service_turn(s, ep->service_wan);
    pthread_mutex_lock(&s->turn_lock);
    if (turn_matches(turn, q, ep, generation)) {
        turn_cancel_locked(turn);
        service_release_eligibility(s, ep);
    }
    pthread_mutex_unlock(&s->turn_lock);
    service_queue(s);
}
static void diagnostic_last_event(struct dns_query_struct *q, struct dns_server_info *ep, unsigned event)
{
    if (!ep->service) { _dns_endpoint_event(q, ep, event, 0); return; }
    if (!q) return;
    pthread_mutex_lock(&q->lock);
    for (struct dns_service_observation *o = q->service_observations; o; o = o->next)
        if (o->service == ep->service) { __atomic_store_n(&o->last_event, event + 1, __ATOMIC_RELAXED); break; }
    pthread_mutex_unlock(&q->lock);
}
void _dns_service_diagnostic_event(struct dns_query_struct *q, struct dns_server_info *ep, unsigned event)
{
    if (!ep || event >= DNS_EVENT_COUNT) return;
    if (!ep->service) { _dns_endpoint_event(q, ep, event, 1); return; }
    stats_inc(&ep->service->diagnostics.events[event]);
    diagnostic_last_event(q, ep, event);
}
void _dns_service_diagnostic_http(struct dns_query_struct *q, struct dns_server_info *ep, int status)
{
    unsigned event = status == 429 ? DNS_EVENT_HTTP_429 : status == 503 ? DNS_EVENT_HTTP_503 : DNS_EVENT_HTTP_OTHER;
    /* Backpressure events are counted once in the shared policy hook, including
     * canceled HTTP/1 FIFO owners. Here only associate that evidence with q. */
    if (status == 429 || status == 503) diagnostic_last_event(q, ep, event);
    else {
        _dns_service_diagnostic_event(q, ep, event);
        _dns_service_detail(q, ep, DNS_DETAIL_TRANSPORT_ERROR, DNS_PHASE_RESPONSE, status, 0, 0);
    }
}
void _dns_service_query_result(struct dns_query_struct *q, struct dns_server_info *ep, int accepted)
{
    _dns_attempt_reply_outcome(q, ep, accepted);
    if (!ep->service) { _dns_endpoint_result(q, ep, accepted); return; }
    pthread_mutex_lock(&q->lock);
    for (struct dns_service_observation *o = q->service_observations; o; o = o->next) {
        if (o->service != ep->service) continue;
        stats_inc(&ep->service->stats.recv_count);
        if (accepted) {
            o->accepted_tick = get_tick_count();
            __atomic_store_n(&o->success, 1, __ATOMIC_RELEASE);
            __atomic_store_n(&o->terminal, 1, __ATOMIC_RELEASE);
            __atomic_store_n(&ep->service_failures, 0, __ATOMIC_RELEASE);
            __atomic_store_n(&ep->service_retry_at, 0, __ATOMIC_RELEASE);
        }
        observation_hint(o, 1); break;
    }
    pthread_mutex_unlock(&q->lock);
}
void _dns_service_query_expired(struct dns_query_struct *q, struct dns_upstream_service *s)
{
    pthread_mutex_lock(&q->lock);
    for (struct dns_service_observation *o = q->service_observations; o; o = o->next) {
        if (o->service != s || o->terminal) continue;
        __atomic_store_n(&o->end_reason, DNS_END_DEADLINE, __ATOMIC_RELAXED);
        __atomic_store_n(&o->terminal, 1, __ATOMIC_RELEASE);
        pthread_mutex_lock(&s->turn_lock);
        for (unsigned i = 0; i < service_lanes(s); i++)
            if (service_turn(s, i)->turn_observation == o) turn_cancel_locked(service_turn(s, i));
        pthread_mutex_unlock(&s->turn_lock); observation_hint(o, 1);
    }
    pthread_mutex_unlock(&q->lock);
}
void _dns_service_query_terminal(struct dns_query_struct *q)
{
    pthread_mutex_lock(&q->lock);
    unsigned reason = _dns_query_end_reason(q);
    for (struct dns_service_observation *o = q->service_observations; o; o = o->next) {
        if (__atomic_load_n(&o->terminal, __ATOMIC_ACQUIRE)) continue;
        __atomic_store_n(&o->end_reason, reason == DNS_END_OTHER_RESULT && q->result_service == o->service ?
            DNS_END_UNACCEPTED_RESULT : reason, __ATOMIC_RELAXED);
        __atomic_store_n(&o->terminal, 1, __ATOMIC_RELEASE);
        struct dns_upstream_service *s = o->service;
        pthread_mutex_lock(&s->turn_lock);
        for (unsigned i = 0; i < service_lanes(s); i++)
            if (service_turn(s, i)->turn_observation == o) turn_cancel_locked(service_turn(s, i));
        pthread_mutex_unlock(&s->turn_lock);
        observation_hint(o, 1);
    }
    pthread_mutex_unlock(&q->lock);
}
void _dns_service_query_free(struct dns_query_struct *q)
{
    struct dns_service_observation *o = q->service_observations;
    while (o) {
        struct dns_service_observation *next = o->next;
        _dns_service_put(o->service); free(o); o = next;
    }
    q->service_observations = NULL;
}
/* Called without endpoint locks. Only fully idle sockets may surrender a slot;
 * connection establishment and partially emitted frames are never evicted. */
void _dns_service_prepare_connection(struct dns_server_info *target)
{
    struct dns_upstream_service *s = target->service;
    if (!s) return;
    pthread_mutex_lock(&target->lock);
    int needs = target->fd < 0 && !target->service_connection_held;
    pthread_mutex_unlock(&target->lock);
    unsigned cap = s->flags.max_upstream_connections ? s->flags.max_upstream_connections :
        __atomic_load_n(&s->selected_count, __ATOMIC_ACQUIRE);
    if (!needs || __atomic_load_n(&s->connections, __ATOMIC_ACQUIRE) < cap) return;
    struct dns_server_info *candidates[DNS_UPSTREAM_BACKENDS_MAX * 2];
    unsigned count = 0;
    pthread_mutex_lock(&s->lock);
    for (unsigned i = 0; i < s->member_count; i++) if (s->members[i] != target) {
        candidates[count++] = s->members[i]; dns_client_server_info_get(s->members[i]);
    }
    pthread_mutex_unlock(&s->lock);
    unsigned long now = get_tick_count();
    int rotating = 0;
    for (unsigned i = 0; i < count; i++) if (candidates[i]->service_rotation) rotating = 1;
    /* Reuse healthy connections for at least a second when the IP set exceeds
     * the physical cap. Rotate one slot at a time, never one TLS handshake per query. */
    for (unsigned i = 0; i < count && __atomic_load_n(&s->connections, __ATOMIC_ACQUIRE) >= cap; i++) {
        struct dns_server_info *ep = candidates[i]; pthread_mutex_lock(&ep->lock);
        if ((!ep->service_connect_tick || now - ep->service_connect_tick >= 1000) &&
            ep->service_connection_held && !ep->active_attempts && !ep->process_depth &&
            ep->status != DNS_SERVER_STATUS_CONNECTING && !ep->send_buff.len &&
            !ep->http2_write_owner && !ep->ssl_want_write && list_empty(&ep->conn_stream_list))
            _dns_client_close_socket(ep);
        pthread_mutex_unlock(&ep->lock);
    }
    if (!rotating && __atomic_load_n(&s->connections, __ATOMIC_ACQUIRE) >= cap) {
        for (unsigned i = 0; i < count; i++) {
            struct dns_server_info *ep = candidates[i]; pthread_mutex_lock(&ep->lock);
            int drain = ep->status == DNS_SERVER_STATUS_CONNECTED && ep->active_attempts &&
                (!ep->service_connect_tick || now - ep->service_connect_tick >= 1000);
            if (drain) __atomic_store_n(&ep->service_rotation, 1, __ATOMIC_RELEASE);
            pthread_mutex_unlock(&ep->lock); if (drain) break;
        }
    }
    for (unsigned i = 0; i < count; i++) dns_client_server_info_release(candidates[i]);
}
int _dns_service_connection_acquire(struct dns_server_info *ep)
{
    struct dns_upstream_service *s = ep->service;
    if (!s || ep->service_connection_held) return 0;
    unsigned cap = s->flags.max_upstream_connections ? s->flags.max_upstream_connections :
        __atomic_load_n(&s->selected_count, __ATOMIC_ACQUIRE);
    unsigned count = __atomic_load_n(&s->connections, __ATOMIC_ACQUIRE);
    while (count < cap) {
        if (__atomic_compare_exchange_n(&s->connections, &count, count + 1, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) { ep->service_connection_held = 1; return 0; }
    }
    __atomic_store_n(&s->next_wait, DNS_WAIT_SCHEDULER, __ATOMIC_RELAXED);
    __atomic_store_n(&s->next_eligible, get_tick_count() + 100, __ATOMIC_RELEASE);
    service_queue(s);
    return -1;
}
void _dns_service_connection_release(struct dns_server_info *ep)
{
    if (!ep->service || !ep->service_connection_held) return;
    ep->service_connection_held = 0;
    if (ep->service->wan_count) {
        uint64_t expected = ep->service_member_id;
        __atomic_compare_exchange_n(&ep->service->wans[ep->service_wan].winner, &expected, 0, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    }
    __atomic_sub_fetch(&ep->service->connections, 1, __ATOMIC_ACQ_REL);
    __atomic_store_n(&ep->service->next_eligible, 0, __ATOMIC_RELEASE);
    service_queue(ep->service);
}
void _dns_service_endpoint_failure(struct dns_server_info *ep)
{
    if (!ep->service) return;
    if (ep->service->wan_count) {
        struct dns_service_wan *w = ep->service->wans + ep->service_wan;
        uint64_t expected = ep->service_member_id;
        __atomic_compare_exchange_n(&w->winner, &expected, 0, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    }
    unsigned long now = get_tick_count();
    if (__atomic_load_n(&ep->service_retry_at, __ATOMIC_ACQUIRE) > now) return;
    __atomic_add_fetch(&ep->service_failures, 1, __ATOMIC_ACQ_REL);
    unsigned delay = ep->service->flags.upstream_retry_cooldown_ms ? ep->service->flags.upstream_retry_cooldown_ms : 1000;
    unsigned long until = delay > ULONG_MAX - now ? ULONG_MAX : now + delay;
    __atomic_store_n(&ep->service_retry_at, until, __ATOMIC_RELEASE);
    if (ep->service->wan_count) {
        struct dns_service_wan *w = ep->service->wans + ep->service_wan;
        if (ep->service_wan_generation == __atomic_load_n(&w->generation, __ATOMIC_ACQUIRE)) {
            __atomic_store_n(&w->family_retry_at[!!strchr(ep->ip, ':')], until, __ATOMIC_RELEASE);
            __atomic_add_fetch(&w->address_cursor, 1, __ATOMIC_RELAXED);
            __atomic_store_n(&ep->service->paths_dirty, 1, __ATOMIC_RELEASE);
            __atomic_store_n(&ep->service->membership_dirty, 1, __ATOMIC_RELEASE);
        }
    }
    service_queue(ep->service);
}
void _dns_service_endpoint_ready(struct dns_server_info *ep)
{
    if (!ep->service) return;
    if (ep->service->wan_count && !ep->service_revoked) {
        struct dns_service_wan *w = ep->service->wans + ep->service_wan;
        uint64_t expected = 0;
        if (ep->service_wan_generation == __atomic_load_n(&w->generation, __ATOMIC_ACQUIRE) &&
            !__atomic_compare_exchange_n(&w->winner, &expected, ep->service_member_id, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) &&
            expected != ep->service_member_id)
            __atomic_store_n(&ep->service_rotation, 1, __ATOMIC_RELEASE);
    }
    __atomic_store_n(&ep->service->next_eligible, 0, __ATOMIC_RELEASE);
    service_queue(ep->service); dns_server_refresh_notify();
}
int _dns_service_has_ecs(struct dns_upstream_service *s)
{ return s->flags.ipv4_ecs.enable || s->flags.ipv6_ecs.enable; }

static void service_flush(struct dns_upstream_service *s, unsigned long now)
{
    if (s->started && __atomic_exchange_n(&s->membership_dirty, 0, __ATOMIC_ACQ_REL)) service_reconcile(s, now);
    if (!s->started && !s->stopping) {
        s->started = 1;
        if (s->config.ip_count) {
            s->desired->count = s->desired->discovered = s->config.ip_count;
            s->desired->status = DNS_DISCOVERY_READY;
            s->desired->expires = ULONG_MAX;
            for (unsigned i = 0; i < s->config.ip_count; i++) {
                safe_strncpy(s->desired->addresses[i].text, s->config.ips[i], sizeof(s->desired->addresses[i].text));
                s->desired->addresses[i].valid_until = ULONG_MAX;
            }
            service_reconcile(s, now);
        } else {
            s->discovery = _dns_discovery_create(s->host, service_discovered, s);
            if (s->discovery) _dns_discovery_start(s->discovery);
        }
    }
    _dns_service_connection_tick(s, now);
    struct dns_query_struct *release[DNS_MAX_SERVERS * 2];
    unsigned release_count = 0;
    pthread_mutex_lock(&s->lock);
    pthread_mutex_lock(&s->turn_lock);
    struct dns_server_info *lease_endpoints[DNS_UPSTREAM_WANS_MAX] = {0};
    struct dns_query_struct *lease_queries[DNS_UPSTREAM_WANS_MAX] = {0};
    int released_turn = 0;
    for (unsigned lane = 0; lane < service_lanes(s); lane++) {
        struct dns_service_turn *lease = service_turn(s, lane);
        unsigned state = __atomic_load_n(&lease->turn_state, __ATOMIC_ACQUIRE);
        struct dns_service_observation *turn = lease->turn_observation;
        if (state == DNS_SERVICE_TURN_COMMIT_PENDING && turn) {
            stats_inc(&s->stats.attempt_count); turn->sends++;
            if (!turn->first_sent) turn->first_sent = lease->turn_accepted_tick;
            if (lease->turn_endpoint) {
                s->cursor = lease->turn_endpoint->service_member_id;
                if (s->wan_count && lease->turn_endpoint->type == DNS_SERVER_UDP) {
                    uint64_t expected = 0;
                    __atomic_compare_exchange_n(&s->wans[lane].winner, &expected,
                        lease->turn_endpoint->service_member_id, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
                }
                __atomic_add_fetch(&lease->turn_endpoint->service_attempt_count, 1, __ATOMIC_RELAXED);
            }
        }
        if (state == DNS_SERVICE_TURN_COMMIT_PENDING || state == DNS_SERVICE_TURN_ABORT_PENDING) {
            released_turn = 1;
            if (turn) {
                __atomic_store_n(&turn->writer_pending, 0, __ATOMIC_RELEASE); observation_hint(turn, 0);
                lease_queries[lane] = turn->query;
            }
            lease_endpoints[lane] = lease->turn_endpoint;
            lease->turn_observation = NULL; lease->turn_endpoint = NULL;
            __atomic_store_n(&lease->turn_state, DNS_SERVICE_TURN_IDLE, __ATOMIC_RELEASE);
        }
    }
    pthread_mutex_unlock(&s->turn_lock);
    struct dns_service_observation *o;
    unsigned processed = 0;
    o = s->deferred_hints;
    if (!o) o = __atomic_exchange_n(&s->hints, NULL, __ATOMIC_ACQ_REL);
    while (o && processed++ < DNS_MAX_SERVERS) {
        struct dns_service_observation *next = o->hint_next;
        __atomic_store_n(&o->hint_queued, 0, __ATOMIC_RELEASE);
        if (!__atomic_load_n(&o->settled, __ATOMIC_ACQUIRE)) {
            if (__atomic_load_n(&o->terminal, __ATOMIC_ACQUIRE) &&
                !__atomic_load_n(&o->writer_pending, __ATOMIC_ACQUIRE)) {
                __atomic_store_n(&o->settled, 1, __ATOMIC_RELEASE);
                waiter_remove(s, o);
                stats_sub(&s->stats.in_flight, 1);
                if (o->success && o->sends) {
                    stats_inc(&s->stats.success_count);
                    if (o->accepted_tick >= o->first_sent) {
                        stats_add(&s->stats.response_latency_sum_ms, o->accepted_tick - o->first_sent);
                        stats_inc(&s->stats.response_latency_samples);
                    }
                } else {
                    unsigned end = s->stopping ? DNS_END_SHUTDOWN : __atomic_load_n(&o->end_reason, __ATOMIC_RELAXED);
                    if (end >= DNS_END_COUNT) end = DNS_END_OTHER;
                    if (o->sends) {
                        stats_inc(&s->stats.failure_count); stats_inc(&s->diagnostics.failure_end[end]);
                        unsigned event = __atomic_load_n(&o->last_event, __ATOMIC_RELAXED);
                        stats_inc(&s->diagnostics.failure_last_event[event <= DNS_EVENT_COUNT ? event : 0]);
                    } else {
                        stats_inc(&s->stats.skip_count); stats_inc(&s->diagnostics.skip_end[end]);
                        unsigned why = __atomic_load_n(&o->last_wait, __ATOMIC_RELAXED);
                        stats_inc(&s->diagnostics.skip_wait[why < DNS_WAIT_COUNT ? why : DNS_WAIT_NONE]);
                    }
                }
                release[release_count++] = o->query; /* observation lifetime pin */
            } else if (!o->waiting && !__atomic_load_n(&o->terminal, __ATOMIC_ACQUIRE) &&
                !__atomic_load_n(&o->writer_pending, __ATOMIC_ACQUIRE) &&
                !__atomic_load_n(&o->active_attempts, __ATOMIC_ACQUIRE)) {
                waiter_add(s, o);
                if (o->terminal) observation_hint(o, 0);
            }
        }
        release[release_count++] = o->query; /* hint lifetime pin */
        o = next;
    }
    s->deferred_hints = o;
    struct dns_query_struct *ready = NULL;
    if (!s->stopping && service_turn_available(s) &&
        now >= __atomic_load_n(&s->next_eligible, __ATOMIC_ACQUIRE)) {
        unsigned priority = UINT_MAX;
        struct dns_service_observation *selected = NULL;
        list_for_each_entry(o, &s->waiters, waiter) {
            if (o->terminal || o->settled || o->writer_pending || __atomic_load_n(&o->active_attempts, __ATOMIC_ACQUIRE)) continue;
            if (o->query->priority < priority) { selected = o; priority = o->query->priority; }
            if (!priority) break;
        }
        if (selected) {
            ready = selected->query; _dns_client_query_get(ready);
            list_move_tail(&selected->waiter, &s->waiters);
        }
    }
    unsigned long due = s->timer_due;
    for (unsigned i = 0; i < s->member_count; i++) {
        unsigned long retry = __atomic_load_n(&s->members[i]->service_retry_at, __ATOMIC_ACQUIRE);
        if (retry > now && retry < due) due = retry;
    }
    if (s->next_eligible > now && s->next_eligible < due) due = s->next_eligible;
    if (s->connection_due < due) due = s->connection_due;
    if (s->path_refresh_due > now && s->path_refresh_due < due) due = s->path_refresh_due;
    pthread_mutex_unlock(&s->lock);
    service_timer(s, due);
    for (unsigned lane = 0; lane < service_lanes(s); lane++) if (lease_endpoints[lane]) {
        _dns_attempt_finalize_retired(lease_queries[lane], lease_endpoints[lane]);
        dns_client_server_info_release(lease_endpoints[lane]);
    }
    if (released_turn) dns_server_refresh_notify();
    for (unsigned i = 0; i < release_count; i++) _dns_client_query_release(release[i]);
    if (s->deferred_hints || __atomic_load_n(&s->hints, __ATOMIC_ACQUIRE)) service_queue(s);
    if (ready) {
        if (!ready->terminal) _dns_client_send_query(ready);
        _dns_client_query_release(ready);
    }
}
void _dns_services_flush_pending(void)
{
    /* One detached batch per event-loop turn; newly queued work gets a wakeup,
     * not an unbounded self-feeding loop while sockets cannot make progress. */
    struct dns_upstream_service *s = __atomic_exchange_n(&pending_services, NULL, __ATOMIC_ACQ_REL);
    while (s) {
        struct dns_upstream_service *next = s->pending_next;
        __atomic_store_n(&s->wake_pending, 0, __ATOMIC_RELEASE);
        service_flush(s, get_tick_count());
        _dns_service_put(s); s = next;
    }
}
void _dns_services_run_due(unsigned long now)
{
    _dns_discovery_run_due(now);
    while (!list_empty(&service_timers)) {
        struct dns_upstream_service *s = list_first_entry(&service_timers, struct dns_upstream_service, timer);
        if (s->timer_due > now) break;
        list_del_init(&s->timer); s->timer_due = ULONG_MAX;
        service_reconcile(s, now);
        service_queue(s);
    }
    _dns_services_flush_pending();
}
unsigned long _dns_services_next_deadline(void)
{
    unsigned long due = _dns_discovery_next_deadline();
    if (!list_empty(&service_timers)) {
        struct dns_upstream_service *s = list_first_entry(&service_timers, struct dns_upstream_service, timer);
        if (s->timer_due < due) due = s->timer_due;
    }
    return due;
}
void _dns_services_stop(void)
{
    struct dns_upstream_service *s;
    list_for_each_entry(s, &services, list) {
        __atomic_store_n(&s->stopping, 1, __ATOMIC_RELEASE);
        list_del_init(&s->timer);
        if (s->discovery) { _dns_discovery_destroy(s->discovery); s->discovery = NULL; }
    }
}
void _dns_services_remove_all(void)
{
    _dns_services_flush_pending();
    _dns_paths_close();
    struct dns_upstream_service *s, *tmp;
    list_for_each_entry_safe(s, tmp, &services, list) {
        for (unsigned lane = 0; lane < service_lanes(s); lane++) {
            struct dns_service_turn *turn = service_turn(s, lane);
            unsigned state = __atomic_load_n(&turn->turn_state, __ATOMIC_ACQUIRE);
            if (state == DNS_SERVICE_TURN_RESERVED || state == DNS_SERVICE_TURN_WRITE_WAIT)
                __atomic_store_n(&turn->turn_state, DNS_SERVICE_TURN_ABORT_PENDING, __ATOMIC_RELEASE);
        }
        do { service_flush(s, get_tick_count()); } while (!list_empty(&s->waiters) ||
            s->deferred_hints || __atomic_load_n(&s->hints, __ATOMIC_ACQUIRE));
        for (unsigned i = 0; i < s->member_count; i++) dns_client_server_info_release(s->members[i]);
        s->member_count = 0;
        list_del_init(&s->list);
        _dns_service_put(s);
    }
}

static void service_snapshot(struct dns_upstream_service *s, struct dns_upstream_service_snapshot_v1 *out,
    struct dns_upstream_service_diagnostics_v1 *diagnostics)
{
    struct dns_server_info *pins[DNS_UPSTREAM_BACKENDS_MAX];
    unsigned char pin_current[DNS_UPSTREAM_BACKENDS_MAX];
    unsigned char ready_lanes[DNS_UPSTREAM_BACKENDS_MAX] = {0};
    unsigned pin_count = 0;
    pthread_mutex_lock(&s->lock);
    memset(out, 0, sizeof(*out));
    memcpy(out, &s->stats, offsetof(struct dns_upstream_service_snapshot_v1, query_count));
#define COPY_COUNTER(field) out->field = stats_read(&s->stats.field)
    COPY_COUNTER(query_count); COPY_COUNTER(attempt_count); COPY_COUNTER(success_count);
    COPY_COUNTER(failure_count); COPY_COUNTER(skip_count); COPY_COUNTER(in_flight);
    COPY_COUNTER(response_latency_sum_ms); COPY_COUNTER(response_latency_samples);
    COPY_COUNTER(attempt_rtt_sum_ms); COPY_COUNTER(attempt_rtt_samples);
    COPY_COUNTER(attempt_rtt_ambiguous_count); COPY_COUNTER(recv_count);
#undef COPY_COUNTER
    if (diagnostics) {
        memset(diagnostics, 0, sizeof(*diagnostics));
        diagnostics->struct_size = sizeof(*diagnostics); diagnostics->version = 1;
        diagnostics->qps = s->flags.max_query_rate; diagnostics->burst = s->flags.query_burst;
        diagnostics->cooldown_ms = s->flags.upstream_cooldown_ms ? s->flags.upstream_cooldown_ms : 200;
        for (unsigned i = 0; i < DNS_END_COUNT; i++) {
            diagnostics->failure_end[i] = stats_read(&s->diagnostics.failure_end[i]);
            diagnostics->skip_end[i] = stats_read(&s->diagnostics.skip_end[i]);
        }
        for (unsigned i = 0; i < DNS_WAIT_COUNT; i++) diagnostics->skip_wait[i] = stats_read(&s->diagnostics.skip_wait[i]);
        for (unsigned i = 0; i <= DNS_EVENT_COUNT; i++) diagnostics->failure_last_event[i] = stats_read(&s->diagnostics.failure_last_event[i]);
        for (unsigned i = 0; i < DNS_EVENT_COUNT; i++) diagnostics->events[i] = stats_read(&s->diagnostics.events[i]);
    }
    out->endpoint_count = 0; out->draining_count = 0;
    out->security = DNS_CLIENT_SERVER_SECURITY_UNKNOW;
    unsigned ready = 0;
    for (unsigned i = 0; i < s->member_count; i++) {
        struct dns_server_info *ep = s->members[i];
        if (ep->service_revoked) { out->draining_count++; continue; }
        if (out->endpoint_count < DNS_UPSTREAM_BACKENDS_MAX)
            safe_strncpy(out->selected_ips[out->endpoint_count++], ep->ip, sizeof(out->selected_ips[0]));
        if (_dns_service_endpoint_eligible(ep, get_tick_count())) {
            if (s->wan_count) ready_lanes[ep->service_wan] = 1;
            else ready++;
        }
        if (pin_count < DNS_UPSTREAM_BACKENDS_MAX) {
            int current = !ep->service_draining;
            if (s->wan_count) {
                struct dns_service_wan *wan = &s->wans[ep->service_wan];
                uint64_t winner = __atomic_load_n(&wan->winner, __ATOMIC_ACQUIRE);
                current = current && ep->service_wan_generation == __atomic_load_n(&wan->generation, __ATOMIC_ACQUIRE) &&
                    (!winner || winner == ep->service_member_id);
            }
            pin_current[pin_count] = current;
            pins[pin_count++] = ep; dns_client_server_info_get(ep);
        }
    }
    out->connection_count = __atomic_load_n(&s->connections, __ATOMIC_ACQUIRE);
    out->connection_cap = s->flags.max_upstream_connections ? s->flags.max_upstream_connections : out->endpoint_count;
    out->discovered_count = s->discovered_count; out->rejected_count = s->rejected_count;
    out->overflow_count = s->discovered_count > out->endpoint_count ? s->discovered_count - out->endpoint_count : 0;
    out->stale = s->stale;
    unsigned long now = get_tick_count();
    out->freshness_kind = s->config.ip_count ? DNS_FRESHNESS_NON_EXPIRING :
        s->freshness_known ? DNS_FRESHNESS_FINITE : DNS_FRESHNESS_UNKNOWN;
    if (out->freshness_kind == DNS_FRESHNESS_FINITE)
        out->freshness_remaining_ms = s->freshness_until > now ? s->freshness_until - now : 0;
    unsigned expected = out->endpoint_count;
    if (s->wan_count) {
        expected = s->wan_count;
        for (unsigned lane = 0; lane < s->wan_count; lane++) ready += ready_lanes[lane];
    }
    out->status = !out->endpoint_count ? (s->started ? DNS_SERVICE_UNAVAILABLE : DNS_SERVICE_DISCOVERING) :
        s->stale ? DNS_SERVICE_STALE : !ready ? DNS_SERVICE_UNAVAILABLE :
        ready < expected ? DNS_SERVICE_DEGRADED : DNS_SERVICE_READY;
    pthread_mutex_unlock(&s->lock);
    /* Endpoint locks are never nested under the service membership lock. */
    unsigned worst_rank = 0, failed_rank = 0, failed_security = DNS_CLIENT_SERVER_SECURITY_UNKNOW;
    for (unsigned i = 0; i < pin_count; i++) {
        pthread_mutex_lock(&pins[i]->lock);
        unsigned security = pins[i]->security_status;
        int connected = pins[i]->type == DNS_SERVER_UDP ? pins[i]->fd >= 0 : pins[i]->service_protocol_ready;
        pthread_mutex_unlock(&pins[i]->lock);
        unsigned rank = security == DNS_CLIENT_SERVER_SECURITY_VERIFY_FAILED ? 5 :
            security == DNS_CLIENT_SERVER_SECURITY_INSECURE ? 4 :
            security == DNS_CLIENT_SERVER_SECURITY_UNKNOW ? 3 :
            security == DNS_CLIENT_SERVER_SECURITY_NOT_APPLICABLE ? 2 : 1;
        /* A dormant alternate family has never completed TLS. Its Unknown
         * must not override the verified connection actually serving a WAN. */
        if (pin_current[i] && connected && rank > worst_rank) { worst_rank = rank; out->security = security; }
        if (rank >= 4 && rank > failed_rank) { failed_rank = rank; failed_security = security; }
        dns_client_server_info_release(pins[i]);
    }
    if (!worst_rank && failed_rank) out->security = failed_security;
    out->cooldown_remaining_ms = _dns_policy_service_cooldown(s, now);
    if (out->cooldown_remaining_ms) out->status = DNS_SERVICE_COOLDOWN;
}
#ifdef TEST
void _dns_service_snapshot_test(struct dns_upstream_service *s, struct dns_upstream_service_snapshot_v1 *out)
{ service_snapshot(s, out, NULL); }
#endif
int dns_client_get_service_diagnostics_v1(const char *id, struct dns_upstream_service_snapshot_v1 *base,
    struct dns_upstream_service_diagnostics_v1 *out)
{
    if (!id || !base || !out) return -1;
    int result = -1;
    pthread_mutex_lock(&registry_lock);
    struct dns_upstream_service *s;
    list_for_each_entry(s, &services, list) {
        if (strcmp(s->id, id)) continue;
        service_snapshot(s, base, out); result = 0; break;
    }
    pthread_mutex_unlock(&registry_lock);
    if (result && (base && out)) {
        struct dns_server_info *ep = _dns_endpoint_find(id);
        if (ep) { _dns_endpoint_snapshot(ep, base, out); dns_client_server_info_release(ep); result = 0; }
    }
    return result;
}
int dns_client_get_service_event_context_v1(const char *id, struct dns_upstream_event_context_snapshot_v1 *out)
{
    if (!id || !out) return -1;
    int result = -1;
    pthread_mutex_lock(&registry_lock);
    struct dns_upstream_service *s;
    list_for_each_entry(s, &services, list) {
        if (strcmp(s->id, id)) continue;
        memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out); out->version = 1;
        pthread_mutex_lock(&s->detail_lock);
        out->event_count = s->detail.event_count;
        memcpy(out->events, s->event_context, out->event_count * sizeof(out->events[0]));
        pthread_mutex_unlock(&s->detail_lock); result = 0; break;
    }
    pthread_mutex_unlock(&registry_lock);
    if (result) { struct dns_server_info *ep = _dns_endpoint_find(id);
        if (ep) { _dns_endpoint_context_snapshot(ep, out); dns_client_server_info_release(ep); result = 0; } }
    return result;
}
int dns_client_get_service_runtime_v1(const char *id, struct dns_upstream_runtime_v1 *out)
{
    if (!id || !out) return -1;
    memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out); out->version = 1;
    int result = -1; unsigned long now = get_tick_count();
    pthread_mutex_lock(&registry_lock);
    struct dns_upstream_service *s;
    list_for_each_entry(s, &services, list) {
        if (strcmp(s->id, id)) continue;
        pthread_mutex_lock(&s->lock);
        out->wan_count = service_lanes(s); out->configured_cap = s->flags.max_query_rate;
        out->qps_mode = s->flags.adaptive_query_rate ? 2 : s->flags.max_query_rate ? 1 : 0;
        struct dns_service_observation *o;
        list_for_each_entry(o, &s->waiters, waiter) {
            if (o->terminal || o->settled || o->writer_pending || o->active_attempts) continue;
            if (!o->query->priority) out->foreground_waiting++;
            else if (o->query->priority == 1) out->refresh_waiting++; else out->prefetch_waiting++;
        }
        for (unsigned lane = 0; lane < out->wan_count; lane++) {
            struct dns_upstream_wan_runtime_v1 *w = &out->wans[lane];
            struct dns_service_wan *wan = &s->wans[lane];
            safe_strncpy(w->interface, wan->interface, sizeof(w->interface)); w->interface_index = wan->index;
            w->generation = wan->generation;
            _dns_policy_wan_runtime(wan->policy ? wan->policy : !s->wan_count ? s->policy : NULL, now, w);
            for (unsigned i = 0; i < 2; i++) if (wan->candidates[i].ip[0]) {
                w->family_mask |= 1U << i;
                uint64_t retry = wan->family_retry_at[i] > now ? wan->family_retry_at[i] - now : 0;
                if (w->family_mask == (1U << i) || retry < w->retry_remaining_ms) w->retry_remaining_ms = retry;
            }
            uint64_t winner = __atomic_load_n(&wan->winner, __ATOMIC_ACQUIRE);
            for (unsigned i = 0; i < s->member_count; i++) {
                struct dns_server_info *ep = s->members[i];
                if (ep->service_wan != lane || ep->service_revoked || ep->service_draining ||
                    (s->wan_count && ep->service_wan_generation != wan->generation) ||
                    (winner && ep->service_member_id != winner) ||
                    (ep->type == DNS_SERVER_UDP ? ep->fd < 0 : !ep->service_protocol_ready)) continue;
                w->connected = 1; w->connected_family = ep->ai_family == AF_INET6 ? 6 : 4;
                safe_strncpy(w->ip, ep->ip, sizeof(w->ip));
                safe_strncpy(w->source, w->connected_family == 6 ? wan->source6 : wan->source4, sizeof(w->source)); break;
            }
        }
        pthread_mutex_unlock(&s->lock); result = 0; break;
    }
    pthread_mutex_unlock(&registry_lock);
    if (result) {
        struct dns_server_info *ep = _dns_endpoint_find(id);
        if (ep) {
            out->wan_count = 1; out->configured_cap = ep->flags.max_query_rate;
            out->qps_mode = ep->flags.adaptive_query_rate ? 2 : ep->flags.max_query_rate ? 1 : 0;
            struct dns_upstream_wan_runtime_v1 *w = &out->wans[0];
            safe_strncpy(w->interface, ep->flags.ifname, sizeof(w->interface)); safe_strncpy(w->ip, ep->ip, sizeof(w->ip));
            w->family_mask = ep->ai_family == AF_INET6 ? 2 : 1;
            w->connected = ep->status == DNS_SERVER_STATUS_CONNECTED; w->connected_family = ep->ai_family == AF_INET6 ? 6 : 4;
            _dns_policy_wan_runtime(ep->policy, now, w);
            unsigned long cooldown = _dns_policy_endpoint_cooldown(ep, now);
            if (cooldown > w->cooldown_remaining_ms) w->cooldown_remaining_ms = cooldown;
            dns_client_server_info_release(ep); result = 0;
        }
    }
    return result;
}
int dns_client_get_service_sources_v1(const char *id, struct dns_upstream_event_sources_v1 *out)
{
    if (!id || !out) return -1;
    memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out); out->version = 1;
    int result = -1;
    pthread_mutex_lock(&registry_lock);
    struct dns_upstream_service *s;
    list_for_each_entry(s, &services, list) {
        if (strcmp(s->id, id)) continue;
        pthread_mutex_lock(&s->detail_lock);
        if (s->event_sources) {
            out->event_count = s->detail.event_count;
            memcpy(out->events, s->event_sources, out->event_count * sizeof(out->events[0]));
        }
        pthread_mutex_unlock(&s->detail_lock); result = 0; break;
    }
    pthread_mutex_unlock(&registry_lock);
    if (result) {
        struct dns_server_info *ep = _dns_endpoint_find(id);
        if (ep) {
            pthread_mutex_lock(&ep->diagnostic->lock);
            if (ep->diagnostic->event_sources) {
                out->event_count = ep->diagnostic->detail.event_count;
                memcpy(out->events, ep->diagnostic->event_sources, out->event_count * sizeof(out->events[0]));
            }
            pthread_mutex_unlock(&ep->diagnostic->lock); dns_client_server_info_release(ep); result = 0;
        }
    }
    return result;
}
int dns_client_get_service_failures_v1(const char *id, struct dns_upstream_failure_snapshot_v1 *out)
{
    if (!id || !out) return -1;
    int result = -1;
    pthread_mutex_lock(&registry_lock);
    struct dns_upstream_service *s;
    list_for_each_entry(s, &services, list) {
        if (strcmp(s->id, id)) continue;
        pthread_mutex_lock(&s->detail_lock);
        if (s->failures) *out = *s->failures; else memset(out, 0, sizeof(*out));
        pthread_mutex_unlock(&s->detail_lock);
        result = 0; break;
    }
    pthread_mutex_unlock(&registry_lock);
    if (result) {
        struct dns_server_info *ep = _dns_endpoint_find(id);
        if (ep) {
            pthread_mutex_lock(&ep->diagnostic->lock);
            if (ep->diagnostic->failures) *out = *ep->diagnostic->failures; else memset(out, 0, sizeof(*out));
            pthread_mutex_unlock(&ep->diagnostic->lock); dns_client_server_info_release(ep); result = 0;
        }
    }
    if (result) return result;
    out->struct_size = sizeof(*out); out->version = 1;
    unsigned long now = get_tick_count();
    for (unsigned i = 0; i < DNS_UPSTREAM_RCODE_SLOTS; i++)
        if (out->rcode_counts[i]) out->last_rcode[i].event.age_ms = now >= out->last_rcode[i].event.tick_ms ? now - out->last_rcode[i].event.tick_ms : 0;
    for (unsigned i = 0; i < out->timeout_count; i++)
        out->timeouts[i].event.age_ms = now >= out->timeouts[i].event.tick_ms ? now - out->timeouts[i].event.tick_ms : 0;
    for (unsigned i = 0; i < out->io_count; i++)
        out->io_errors[i].event.age_ms = now >= out->io_errors[i].event.tick_ms ? now - out->io_errors[i].event.tick_ms : 0;
    return 0;
}
int dns_client_get_service_policy_v1(const char *id, struct dns_upstream_policy_snapshot_v1 *out)
{
    if (!id || !out) return -1;
    int result = -1;
    pthread_mutex_lock(&registry_lock);
    struct dns_upstream_service *s;
    list_for_each_entry(s, &services, list) {
        if (strcmp(s->id, id)) continue;
        pthread_mutex_lock(&s->detail_lock); *out = s->detail; pthread_mutex_unlock(&s->detail_lock);
        out->struct_size = sizeof(*out); out->version = 1;
        out->family = s->config.family; out->response_timeout_ms = s->config.response_timeout_ms;
        out->query_timeout_ms = s->config.query_timeout_ms; out->connect_timeout_ms = s->config.connect_timeout_ms;
        out->connect_delay_ms = s->config.connect_delay_ms;
        out->keepalive_ms = s->config.keepalive_disabled || (s->type != DNS_SERVER_HTTPS && s->type != DNS_SERVER_HTTP3) ? 0 : s->config.keepalive_ms;
        unsigned long now = get_tick_count();
        for (unsigned i = 0; i < out->event_count; i++) out->events[i].age_ms = now >= out->events[i].tick_ms ? now - out->events[i].tick_ms : 0;
        pthread_mutex_lock(&s->lock);
        for (unsigned i = 0; i < out->path_count; i++) for (unsigned j = 0; j < s->member_count; j++) {
            struct dns_server_info *ep = s->members[j];
            if (strcmp(ep->ip, out->paths[i].ip)) continue;
            if ((s->flags.upstream_wan_count || s->flags.ifname[0]) && strcmp(ep->flags.ifname, out->paths[i].interface)) continue;
            out->paths[i].selected = !ep->service_revoked;
            out->paths[i].connected = ep->status == DNS_SERVER_STATUS_CONNECTED;
            out->paths[i].keepalive_ms = out->paths[i].connected ? ep->service_keepalive_interval_ms : 0;
            out->paths[i].active_attempts = __atomic_load_n(&ep->active_attempts, __ATOMIC_RELAXED);
            out->paths[i].attempts = __atomic_load_n(&ep->service_attempt_count, __ATOMIC_RELAXED);
            out->paths[i].successes = __atomic_load_n(&ep->service_success_count, __ATOMIC_RELAXED);
            out->paths[i].failures = __atomic_load_n(&ep->service_failure_count, __ATOMIC_RELAXED);
        }
        pthread_mutex_unlock(&s->lock); result = 0; break;
    }
    pthread_mutex_unlock(&registry_lock);
    if (result) { struct dns_server_info *ep = _dns_endpoint_find(id);
        if (ep) { _dns_endpoint_policy_snapshot(ep, out); dns_client_server_info_release(ep); result = 0; } }
    return result;
}
void _dns_services_network_tick(void)
{
    _dns_paths_network_tick();
    struct dns_upstream_service *s;
    list_for_each_entry(s, &services, list) {
        if (!s->started || s->stopping) continue;
        /* The bounded route cache also handles changes not reported by netlink,
         * including rule updates and a temporarily unavailable monitor socket. */
        unsigned long now = get_tick_count();
        _dns_paths_refresh(s, now);
        service_reconcile(s, now); service_queue(s);
    }
}
int dns_client_get_service_snapshot_v1(struct dns_upstream_service_snapshot_v1 *out, unsigned capacity)
{
    if (!out && capacity) return -1;
    unsigned count = 0;
    pthread_mutex_lock(&registry_lock);
    struct dns_upstream_service *s;
    list_for_each_entry(s, &services, list) {
        if (count < capacity) service_snapshot(s, &out[count], NULL);
        count++;
    }
    pthread_mutex_unlock(&registry_lock);
    pthread_mutex_lock(&client.server_list_lock);
    struct dns_server_info *ep;
    unsigned legacy_count = 0;
    list_for_each_entry(ep, &client.dns_server_list, list)
        if (!ep->service && ep->type != DNS_SERVER_MDNS) legacy_count++;
    unsigned available = count < capacity ? capacity - count : 0;
    unsigned fill = legacy_count < available ? legacy_count : available;
    struct dns_server_info **pins = fill ? calloc(fill, sizeof(*pins)) : NULL;
    if (fill && !pins) { pthread_mutex_unlock(&client.server_list_lock); return -1; }
    unsigned pinned = 0;
    list_for_each_entry(ep, &client.dns_server_list, list) {
        if (pinned == fill) break;
        if (ep->service || ep->type == DNS_SERVER_MDNS) continue;
        dns_client_server_info_get(ep); pins[pinned++] = ep;
    }
    pthread_mutex_unlock(&client.server_list_lock);
    for (unsigned i = 0; i < fill; i++) {
        ep = pins[i];
        struct dns_upstream_service_snapshot_v1 *v = &out[count + i];
        if (ep->diagnostic) {
            _dns_endpoint_snapshot(ep, v, NULL);
            pthread_mutex_lock(&ep->lock);
            v->query_count = stats_read(&ep->stats.total); v->success_count = stats_read(&ep->stats.success_count);
            v->recv_count = stats_read(&ep->stats.recv_count);
            v->legacy_avg_time = dns_stats_server_stats_avg_time_get(&ep->stats);
            v->attempt_count = v->failure_count = v->skip_count = v->in_flight = 0;
            v->response_latency_sum_ms = v->response_latency_samples = 0;
            v->attempt_rtt_sum_ms = v->attempt_rtt_samples = v->attempt_rtt_ambiguous_count = 0;
            pthread_mutex_unlock(&ep->lock);
        } else {
            /* Memory-pressure fallback retains honest legacy counters; callers
             * cannot mistake these for the closed diagnostic accounting. */
            pthread_mutex_lock(&ep->lock);
            memset(v, 0, sizeof(*v)); v->version = 1; v->struct_size = sizeof(*v);
            safe_strncpy(v->authority, ep->host, sizeof(v->authority));
            safe_strncpy(v->selected_ips[0], ep->ip, sizeof(v->selected_ips[0]));
            snprintf(v->service_id, sizeof(v->service_id), "legacy-%u", count + i);
            v->port = ep->port; v->transport = ep->type; v->endpoint_count = 1;
            v->query_count = stats_read(&ep->stats.total); v->success_count = stats_read(&ep->stats.success_count);
            v->recv_count = stats_read(&ep->stats.recv_count);
            v->legacy_avg_time = dns_stats_server_stats_avg_time_get(&ep->stats);
            v->freshness_kind = DNS_FRESHNESS_NOT_APPLICABLE;
            v->security = ep->security_status;
            v->status = !v->query_count ? DNS_SERVICE_UNKNOWN : atomic_read(&ep->is_alive) ? DNS_SERVICE_READY : DNS_SERVICE_UNAVAILABLE;
            pthread_mutex_unlock(&ep->lock);
        }
        dns_client_server_info_release(ep);
    }
    free(pins); count += legacy_count;
    return count;
}
/* Pin under ownership locks; copied snapshots never hold membership/list
 * locks while taking a transport lock. */
static int service_endpoint_pins(const char *id, struct dns_server_info **pins, unsigned capacity)
{
    struct dns_upstream_service *found = NULL, *s;
    pthread_mutex_lock(&registry_lock);
    list_for_each_entry(s, &services, list) if (!strcmp(id, s->id)) { found = s; _dns_service_get(s); break; }
    pthread_mutex_unlock(&registry_lock);
    if (!found) {
        struct dns_server_info *ep = _dns_endpoint_find(id);
        if (!ep) return -1;
        if (capacity) pins[0] = ep; else dns_client_server_info_release(ep);
        return 1;
    }
    pthread_mutex_lock(&found->lock);
    unsigned count = found->member_count, fill = count < capacity ? count : capacity;
    for (unsigned i = 0; i < fill; i++) { pins[i] = found->members[i]; dns_client_server_info_get(pins[i]); }
    pthread_mutex_unlock(&found->lock); _dns_service_put(found); return count;
}
int dns_client_get_service_endpoints_v1(const char *id, struct dns_upstream_endpoint_snapshot_v1 *out, unsigned capacity)
{
    if (!id || (!out && capacity)) return -1;
    struct dns_server_info *pins[DNS_UPSTREAM_BACKENDS_MAX * 2];
    unsigned cap = capacity < DNS_UPSTREAM_BACKENDS_MAX * 2 ? capacity : DNS_UPSTREAM_BACKENDS_MAX * 2;
    int count = service_endpoint_pins(id, pins, cap);
    if (count < 0) return -1;
    unsigned fill = (unsigned)count < cap ? (unsigned)count : cap;
    for (unsigned i = 0; i < fill; i++) {
        _dns_endpoint_backend_snapshot(pins[i], &out[i]); dns_client_server_info_release(pins[i]);
    }
    return count;
}
int dns_client_get_service_endpoint_activity_v1(const char *id,
    struct dns_upstream_endpoint_activity_v1 *out, unsigned capacity)
{
    if (!id || (!out && capacity)) return -1;
    struct dns_server_info *pins[DNS_UPSTREAM_BACKENDS_MAX * 2];
    unsigned cap = capacity < DNS_UPSTREAM_BACKENDS_MAX * 2 ? capacity : DNS_UPSTREAM_BACKENDS_MAX * 2;
    int count = service_endpoint_pins(id, pins, cap);
    if (count < 0) return -1;
    unsigned fill = (unsigned)count < cap ? (unsigned)count : cap;
    for (unsigned i = 0; i < fill; i++) {
        memset(&out[i], 0, sizeof(out[i]));
        _dns_endpoint_backend_snapshot(pins[i], &out[i].endpoint);
        _dns_policy_endpoint_activity(pins[i], &out[i]);
        dns_client_server_info_release(pins[i]);
    }
    return count;
}

/* Caller owns q->lock; no service mutex nesting in transport admission. */
void _dns_service_attempt_active(struct dns_query_struct *q, struct dns_upstream_service *service, int delta)
{
    if (!service) return;
    for (struct dns_service_observation *o = q->service_observations; o; o = o->next) {
        if (o->service != service) continue;
        if (delta > 0) __atomic_add_fetch(&o->active_attempts, 1, __ATOMIC_ACQ_REL);
        else {
            __atomic_sub_fetch(&o->active_attempts, 1, __ATOMIC_ACQ_REL);
            observation_hint(o, 1);
        }
        break;
    }
}
