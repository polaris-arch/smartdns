/* Observe ordinary upstreams without routing them through the pool scheduler.
 * Storage is one bounded ring per endpoint and one record per targeted query.
 * Observations never retain queries or schedule work of their own. */
#include "upstream_observer.h"
#include "upstream_policy.h"
#include "server_info.h"
#include "smartdns/util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct dns_endpoint_observation {
    struct dns_endpoint_observation *next;
    struct dns_server_info *endpoint;
    unsigned long first_sent, accepted_tick;
    uint64_t sends;
    unsigned accepted, last_wait, last_event;
};

void _dns_endpoint_observer_init(struct dns_server_info *ep)
{
    if (ep->service || ep->type == DNS_SERVER_MDNS || ep->diagnostic) return;
    struct dns_endpoint_diagnostics *d = calloc(1, sizeof(*d));
    if (!d) return; /* Observability allocation must not make DNS unavailable. */
    /* Canonical configuration identity: exclude structure padding and list
     * order; distinguish transport destinations, TLS authority and egress. */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned length = 0;
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) { EVP_MD_CTX_free(ctx); free(d); return; }
#define OBS_STR(v) EVP_DigestUpdate(ctx, (v), strlen(v) + 1)
#define OBS_NUM(v) do { uint64_t n_ = (uint64_t)(v); unsigned char b_[8]; \
    for (unsigned j_ = 0; j_ < 8; j_++) b_[7-j_] = (unsigned char)(n_ >> (j_*8)); \
    EVP_DigestUpdate(ctx, b_, sizeof(b_)); } while (0)
    OBS_STR("ordinary-endpoint-v1"); OBS_STR(ep->host); OBS_STR(ep->ip); OBS_NUM(ep->port); OBS_NUM(ep->type);
    OBS_NUM(ep->flags.server_flag); OBS_NUM(ep->flags.result_flag); OBS_NUM(ep->flags.set_mark);
    OBS_NUM(ep->flags.tcp_keepalive); OBS_NUM(ep->flags.drop_packet_latency_ms); OBS_NUM(ep->flags.fallback);
    OBS_NUM(ep->flags.max_query_rate); OBS_NUM(ep->flags.query_burst); OBS_NUM(ep->flags.upstream_cooldown_ms);
    OBS_NUM(ep->flags.max_concurrent_queries); OBS_STR(ep->flags.quota_group);
    OBS_STR(ep->flags.proxyname); OBS_STR(ep->flags.ifname); OBS_NUM(ep->flags.subnet_all_query_types);
    OBS_NUM(ep->flags.ipv4_ecs.enable); OBS_STR(ep->flags.ipv4_ecs.ip); OBS_NUM(ep->flags.ipv4_ecs.subnet);
    OBS_NUM(ep->flags.ipv6_ecs.enable); OBS_STR(ep->flags.ipv6_ecs.ip); OBS_NUM(ep->flags.ipv6_ecs.subnet);
    if (ep->type == DNS_SERVER_HTTPS || ep->type == DNS_SERVER_HTTP3) {
        const struct client_dns_server_flag_https *f = &ep->flags.https;
        if (f->spi_len < 0 || (unsigned)f->spi_len > sizeof(f->spki)) { EVP_MD_CTX_free(ctx); free(d); return; }
        OBS_NUM(f->spi_len); EVP_DigestUpdate(ctx, f->spki, f->spi_len);
        OBS_STR(f->hostname); OBS_STR(f->httphost); OBS_STR(f->proxyname); OBS_STR(f->path);
        OBS_STR(f->tls_host_verify); OBS_STR(f->alpn); OBS_NUM(f->skip_check_cert);
    } else if (ep->type == DNS_SERVER_TLS || ep->type == DNS_SERVER_QUIC) {
        const struct client_dns_server_flag_tls *f = &ep->flags.tls;
        if (f->spi_len < 0 || (unsigned)f->spi_len > sizeof(f->spki)) { EVP_MD_CTX_free(ctx); free(d); return; }
        OBS_NUM(f->spi_len); EVP_DigestUpdate(ctx, f->spki, f->spi_len);
        OBS_STR(f->hostname); OBS_STR(f->tls_host_verify); OBS_STR(f->alpn); OBS_NUM(f->skip_check_cert);
    } else if (ep->type == DNS_SERVER_UDP) OBS_NUM(ep->flags.udp.ttl);
#undef OBS_STR
#undef OBS_NUM
    int ok = EVP_DigestFinal_ex(ctx, digest, &length) == 1 && length == 32;
    EVP_MD_CTX_free(ctx);
    if (!ok) { free(d); return; }
    pthread_mutex_init(&d->lock, NULL);
    d->base.struct_size = sizeof(d->base); d->base.version = 1;
    for (unsigned i = 0; i < length; i++) snprintf(d->base.service_id + i * 2, 3, "%02x", digest[i]);
    safe_strncpy(d->base.authority, ep->host[0] ? ep->host : ep->ip, sizeof(d->base.authority));
    safe_strncpy(d->base.selected_ips[0], ep->ip, sizeof(d->base.selected_ips[0]));
    if (ep->type == DNS_SERVER_HTTPS || ep->type == DNS_SERVER_HTTP3)
        safe_strncpy(d->base.path, ep->flags.https.path, sizeof(d->base.path));
    d->base.port = ep->port; d->base.transport = ep->type; d->base.endpoint_count = 1;
    d->base.freshness_kind = DNS_FRESHNESS_NOT_APPLICABLE;
    d->breakdown.struct_size = sizeof(d->breakdown); d->breakdown.version = 1;
    d->breakdown.qps = ep->flags.max_query_rate; d->breakdown.burst = ep->flags.query_burst;
    d->breakdown.cooldown_ms = ep->flags.upstream_cooldown_ms ? ep->flags.upstream_cooldown_ms : 1000;
    ep->diagnostic = d;
}
void _dns_endpoint_observer_destroy(struct dns_server_info *ep)
{
    if (!ep->diagnostic) return;
    pthread_mutex_destroy(&ep->diagnostic->lock); free(ep->diagnostic); ep->diagnostic = NULL;
}
static struct dns_endpoint_observation *find_observation(struct dns_query_struct *q, struct dns_server_info *ep)
{
    for (struct dns_endpoint_observation *o = q->endpoint_observations; o; o = o->next)
        if (o->endpoint == ep) return o;
    return NULL;
}
void _dns_endpoint_observe(struct dns_query_struct *q, struct dns_server_info *ep)
{
    if (!ep->diagnostic) return;
    pthread_mutex_lock(&q->lock);
    int needed = !q->terminal && !find_observation(q, ep);
    pthread_mutex_unlock(&q->lock);
    if (!needed) return;
    struct dns_endpoint_observation *o = calloc(1, sizeof(*o));
    if (!o) return;
    pthread_mutex_lock(&q->lock);
    if (q->terminal || find_observation(q, ep)) { pthread_mutex_unlock(&q->lock); free(o); return; }
    dns_client_server_info_get(ep); o->endpoint = ep;
    o->next = q->endpoint_observations; q->endpoint_observations = o;
    pthread_mutex_lock(&ep->diagnostic->lock);
    ep->diagnostic->base.query_count++; ep->diagnostic->base.in_flight++;
    pthread_mutex_unlock(&ep->diagnostic->lock);
    pthread_mutex_unlock(&q->lock);
}
void _dns_endpoint_wait_locked(struct dns_query_struct *q, struct dns_server_info *ep, unsigned why)
{
    if (!ep->diagnostic) return;
    struct dns_endpoint_observation *o = find_observation(q, ep);
    if (o) o->last_wait = why < DNS_WAIT_COUNT ? why : DNS_WAIT_NONE;
}
void _dns_endpoint_sent_locked(struct dns_query_struct *q, struct dns_server_info *ep)
{
    if (!ep->diagnostic) return;
    struct dns_endpoint_observation *o = find_observation(q, ep);
    if (!o) return;
    if (!o->sends) o->first_sent = get_tick_count();
    o->sends++;
    pthread_mutex_lock(&ep->diagnostic->lock); ep->diagnostic->base.attempt_count++;
    pthread_mutex_unlock(&ep->diagnostic->lock);
}
void _dns_endpoint_rtt_locked(struct dns_server_info *ep, unsigned elapsed, int ambiguous)
{
    if (!ep->diagnostic) return;
    pthread_mutex_lock(&ep->diagnostic->lock);
    if (ambiguous) ep->diagnostic->base.attempt_rtt_ambiguous_count++;
    else { ep->diagnostic->base.attempt_rtt_sum_ms += elapsed; ep->diagnostic->base.attempt_rtt_samples++; }
    pthread_mutex_unlock(&ep->diagnostic->lock);
}
void _dns_endpoint_result(struct dns_query_struct *q, struct dns_server_info *ep, int accepted)
{
    if (!ep->diagnostic) return;
    pthread_mutex_lock(&q->lock);
    struct dns_endpoint_observation *o = find_observation(q, ep);
    if (o) {
        pthread_mutex_lock(&ep->diagnostic->lock); ep->diagnostic->base.recv_count++;
        if (accepted && o->sends && !o->accepted) {
            o->accepted = 1; o->accepted_tick = get_tick_count();
            /* OK_WAIT retains a valid negative answer while the native query
             * may still wait for other replies. This endpoint already answered
             * successfully; do not keep it pending until the query is freed. */
            ep->diagnostic->base.in_flight--;
            ep->diagnostic->base.success_count++;
            if (o->accepted_tick >= o->first_sent) {
                ep->diagnostic->base.response_latency_sum_ms += o->accepted_tick - o->first_sent;
                ep->diagnostic->base.response_latency_samples++;
            }
        }
        pthread_mutex_unlock(&ep->diagnostic->lock);
    }
    pthread_mutex_unlock(&q->lock);
}
void _dns_endpoint_event(struct dns_query_struct *q, struct dns_server_info *ep, unsigned event, int count)
{
    if (!ep->diagnostic || event >= DNS_EVENT_COUNT) return;
    if (count) {
        pthread_mutex_lock(&ep->diagnostic->lock); ep->diagnostic->breakdown.events[event]++;
        pthread_mutex_unlock(&ep->diagnostic->lock);
    }
    if (!q) return;
    pthread_mutex_lock(&q->lock);
    struct dns_endpoint_observation *o = find_observation(q, ep);
    if (o) o->last_event = event + 1;
    pthread_mutex_unlock(&q->lock);
}
unsigned _dns_query_end_reason(struct dns_query_struct *q)
{
    unsigned long now = get_tick_count();
    return q->has_result ? DNS_END_OTHER_RESULT :
        (dns_query_budget_timed_out(q->budget) || (now >= q->created_tick &&
        now - q->created_tick >= (q->lifetime_ms ? q->lifetime_ms : DNS_QUERY_LIFETIME))) ? DNS_END_DEADLINE :
        dns_query_budget_exhausted(q->budget) ? DNS_END_BUDGET_OR_CANCEL : DNS_END_OTHER;
}
void _dns_endpoint_query_finish(struct dns_query_struct *q)
{
    /* Called only at the final query release, before releasing its budget.
     * This also waits out any writes which raced cancellation: an actual send
     * must not be prematurely classified as an unsent query. */
    unsigned reason = _dns_query_end_reason(q);
    for (struct dns_endpoint_observation *o = q->endpoint_observations; o; o = o->next) {
        if (o->accepted) continue; /* Already settled at the first accepted reply. */
        struct dns_endpoint_diagnostics *d = o->endpoint->diagnostic;
        unsigned end = reason == DNS_END_OTHER_RESULT && q->result_endpoint == o->endpoint ?
            DNS_END_UNACCEPTED_RESULT : reason;
        pthread_mutex_lock(&d->lock);
        d->base.in_flight--;
        if (o->sends) {
            d->base.failure_count++; d->breakdown.failure_end[end]++;
            d->breakdown.failure_last_event[o->last_event <= DNS_EVENT_COUNT ? o->last_event : 0]++;
        } else {
            d->base.skip_count++; d->breakdown.skip_end[end]++;
            d->breakdown.skip_wait[o->last_wait]++;
        }
        pthread_mutex_unlock(&d->lock);
    }
}
void _dns_endpoint_query_free(struct dns_query_struct *q)
{
    struct dns_endpoint_observation *o = q->endpoint_observations;
    while (o) { struct dns_endpoint_observation *next = o->next;
        dns_client_server_info_release(o->endpoint); free(o); o = next; }
    q->endpoint_observations = NULL;
}
struct dns_server_info *_dns_endpoint_find(const char *id)
{
    struct dns_server_info *found = NULL, *ep;
    pthread_mutex_lock(&client.server_list_lock);
    list_for_each_entry(ep, &client.dns_server_list, list) {
        if (!ep->diagnostic || strcmp(ep->diagnostic->base.service_id, id)) continue;
        dns_client_server_info_get(ep); found = ep; break;
    }
    pthread_mutex_unlock(&client.server_list_lock); return found;
}
void _dns_endpoint_snapshot(struct dns_server_info *ep, struct dns_upstream_service_snapshot_v1 *base,
    struct dns_upstream_service_diagnostics_v1 *breakdown)
{
    pthread_mutex_lock(&ep->diagnostic->lock); *base = ep->diagnostic->base;
    if (breakdown) *breakdown = ep->diagnostic->breakdown;
    pthread_mutex_unlock(&ep->diagnostic->lock);
    pthread_mutex_lock(&ep->lock);
    base->security = ep->security_status;
    base->connection_count = ep->fd >= 0;
    base->legacy_avg_time = base->response_latency_samples ?
        (double)base->response_latency_sum_ms / base->response_latency_samples : 0;
    base->cooldown_remaining_ms = _dns_policy_endpoint_cooldown(ep, get_tick_count());
    base->status = base->cooldown_remaining_ms ? DNS_SERVICE_COOLDOWN : !base->query_count ? DNS_SERVICE_UNKNOWN :
        atomic_read(&ep->is_alive) ? DNS_SERVICE_READY : DNS_SERVICE_UNAVAILABLE;
    pthread_mutex_unlock(&ep->lock);
}
void _dns_endpoint_backend_snapshot(struct dns_server_info *ep, struct dns_upstream_endpoint_snapshot_v1 *out)
{
    memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out); out->version = 1;
    safe_strncpy(out->service_id, ep->service ? ep->service->id : ep->diagnostic->base.service_id, sizeof(out->service_id));
    safe_strncpy(out->ip, ep->ip, sizeof(out->ip)); out->port = ep->port;
    pthread_mutex_lock(&ep->lock);
    out->security = ep->security_status; out->active_attempts = ep->active_attempts;
    unsigned long now = get_tick_count(), retry = __atomic_load_n(&ep->service_retry_at, __ATOMIC_ACQUIRE);
    unsigned long cooldown = _dns_policy_endpoint_cooldown(ep, now);
    out->retry_remaining_ms = retry > now ? retry - now : 0;
    if (cooldown > out->retry_remaining_ms) out->retry_remaining_ms = cooldown;
    out->state = __atomic_load_n(&ep->service_revoked, __ATOMIC_ACQUIRE) ? DNS_ENDPOINT_DRAINING :
        out->retry_remaining_ms ? DNS_ENDPOINT_BACKOFF :
        (ep->status == DNS_SERVER_STATUS_CONNECTED || ep->status == DNS_SERVER_STATUS_CONNECTIONLESS) ? DNS_ENDPOINT_READY :
        ep->status == DNS_SERVER_STATUS_CONNECTING ? DNS_ENDPOINT_CONNECTING : DNS_ENDPOINT_NEW;
    out->attempt_count = __atomic_load_n(&ep->service_attempt_count, __ATOMIC_RELAXED);
    out->success_count = __atomic_load_n(&ep->service_success_count, __ATOMIC_RELAXED);
    out->failure_count = __atomic_load_n(&ep->service_failure_count, __ATOMIC_RELAXED);
    pthread_mutex_unlock(&ep->lock);
}
void _dns_endpoint_policy_snapshot(struct dns_server_info *ep, struct dns_upstream_policy_snapshot_v1 *out)
{
    pthread_mutex_lock(&ep->diagnostic->lock); *out = ep->diagnostic->detail;
    pthread_mutex_unlock(&ep->diagnostic->lock);
    out->struct_size = sizeof(*out); out->version = 1;
    out->response_timeout_ms = DNS_QUERY_TIMEOUT; out->query_timeout_ms = DNS_QUERY_LIFETIME;
    /* These are observations of the actual socket, not an extra reachability
     * probe and not the pool-only family/connection-racing configuration. */
    out->path_count = 1;
    struct dns_upstream_path_v1 *path = &out->paths[0];
    safe_strncpy(path->ip, ep->ip, sizeof(path->ip)); path->family = strchr(ep->ip, ':') ? 6 : 4;
    safe_strncpy(path->interface, ep->flags.ifname, sizeof(path->interface));
    path->state = DNS_PATH_UNKNOWN; path->selected = 1;
    struct dns_upstream_endpoint_snapshot_v1 backend; _dns_endpoint_backend_snapshot(ep, &backend);
    path->active_attempts = backend.active_attempts;
    path->attempts = backend.attempt_count; path->successes = backend.success_count; path->failures = backend.failure_count;
    pthread_mutex_lock(&ep->lock);
    path->connected = ep->status == DNS_SERVER_STATUS_CONNECTED || ep->status == DNS_SERVER_STATUS_CONNECTIONLESS;
    struct sockaddr_storage local = {0}; socklen_t size = sizeof(local);
    if (ep->fd >= 0 && getsockname(ep->fd, (struct sockaddr *)&local, &size) == 0) {
        if (local.ss_family == AF_INET && ((struct sockaddr_in *)&local)->sin_addr.s_addr)
            inet_ntop(AF_INET, &((struct sockaddr_in *)&local)->sin_addr, path->source, sizeof(path->source));
        else if (local.ss_family == AF_INET6 && !IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *)&local)->sin6_addr))
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&local)->sin6_addr, path->source, sizeof(path->source));
    }
    pthread_mutex_unlock(&ep->lock);
    unsigned long now = get_tick_count();
    for (unsigned i = 0; i < out->event_count; i++)
        out->events[i].age_ms = now >= out->events[i].tick_ms ? now - out->events[i].tick_ms : 0;
}
void _dns_endpoint_context_snapshot(struct dns_server_info *ep, struct dns_upstream_event_context_snapshot_v1 *out)
{
    memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out); out->version = 1;
    pthread_mutex_lock(&ep->diagnostic->lock); out->event_count = ep->diagnostic->detail.event_count;
    memcpy(out->events, ep->diagnostic->context, out->event_count * sizeof(out->events[0]));
    pthread_mutex_unlock(&ep->diagnostic->lock);
}

void _dns_endpoint_io_error(struct dns_query_struct *q, struct dns_server_info *ep, unsigned phase, int error)
{
    if (!ep->diagnostic || !error || error == ECANCELED || error == EAGAIN || error == EWOULDBLOCK || error == EINPROGRESS) return;
    ep->service_system_error = error; ep->service_error_code = error;
    if (ep->service_tls_error) phase = DNS_PHASE_TLS;
    _dns_service_diagnostic_event(q, ep, DNS_EVENT_IO_OR_PROTOCOL);
    _dns_service_detail(q, ep, DNS_DETAIL_TRANSPORT_ERROR, phase, error, 0, 0);
}
