/* Logical upstream services. GPL-3.0-or-later. */
#ifndef SMARTDNS_UPSTREAM_SERVICE_H
#define SMARTDNS_UPSTREAM_SERVICE_H
#include "smartdns/dns_client.h"
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define DNS_UPSTREAM_BACKENDS_MAX 64
#define DNS_UPSTREAM_IP_TEXT_MAX 64
#define DNS_UPSTREAM_SERVICE_ID_MAX 65
enum dns_upstream_service_status_v1 {
 DNS_SERVICE_UNKNOWN, DNS_SERVICE_READY, DNS_SERVICE_DEGRADED, DNS_SERVICE_COOLDOWN,
 DNS_SERVICE_DISCOVERING, DNS_SERVICE_UNAVAILABLE, DNS_SERVICE_STALE
};
enum dns_upstream_endpoint_state_v1 {
 DNS_ENDPOINT_NEW, DNS_ENDPOINT_CONNECTING, DNS_ENDPOINT_READY, DNS_ENDPOINT_BACKOFF, DNS_ENDPOINT_DRAINING
};
enum dns_upstream_freshness_v1 {
 DNS_FRESHNESS_UNKNOWN, DNS_FRESHNESS_FINITE, DNS_FRESHNESS_NON_EXPIRING, DNS_FRESHNESS_NOT_APPLICABLE
};
struct dns_upstream_pool_config {
    unsigned max_backends;
    unsigned ip_count;
    char ips[DNS_UPSTREAM_BACKENDS_MAX][DNS_UPSTREAM_IP_TEXT_MAX];
};
int dns_client_add_service(const char *host, int port, dns_server_type_t type,
    const struct client_dns_server_flags *flags, const struct dns_upstream_pool_config *pool);
int dns_client_add_service_to_group(const char *group, const char *host, int port,
    dns_server_type_t type, const struct client_dns_server_flags *flags);
/* Validate all services after configuration groups exist. No network IO here. */
int dns_client_services_start(void);

/* Copied, versioned service snapshots. No pointers into mutable client state. */
struct dns_upstream_service_snapshot_v1 {
    unsigned struct_size, version;
    char service_id[DNS_UPSTREAM_SERVICE_ID_MAX];
    char authority[256], path[256];
    unsigned port, transport, pool_enabled, backend_cap, connection_cap;
    unsigned endpoint_count, connection_count, draining_count;
    char selected_ips[DNS_UPSTREAM_BACKENDS_MAX][DNS_UPSTREAM_IP_TEXT_MAX];
    unsigned group_count;
    char groups[64][128];
    unsigned discovered_count, rejected_count, overflow_count, stale;
    unsigned status, security;
    double legacy_avg_time; /* ordinary non-pool legacy metric only */
    uint64_t query_count, attempt_count, success_count, failure_count, skip_count, in_flight;
    uint64_t response_latency_sum_ms, response_latency_samples;
    uint64_t attempt_rtt_sum_ms, attempt_rtt_samples, attempt_rtt_ambiguous_count, recv_count;
    uint64_t cooldown_remaining_ms, freshness_remaining_ms;
    unsigned freshness_kind; /* remaining is meaningful only for FINITE; never export ULONG_MAX */
};
struct dns_upstream_endpoint_snapshot_v1 {
    unsigned struct_size, version;
    char service_id[DNS_UPSTREAM_SERVICE_ID_MAX], ip[DNS_UPSTREAM_IP_TEXT_MAX];
    unsigned port, state, security, active_attempts;
    uint64_t attempt_count, success_count, failure_count, retry_remaining_ms;
};
/* Returns required count; fills min(capacity, count), caller retries if larger.
 * Snapshot is coherent per call. NULL output/capacity=0 is the sizing query. */
int dns_client_get_service_snapshot_v1(struct dns_upstream_service_snapshot_v1 *out, unsigned capacity);
int dns_client_get_service_endpoints_v1(const char *service_id,
    struct dns_upstream_endpoint_snapshot_v1 *out, unsigned capacity);

/* Independent ABI: do not extend snapshot_v1, which older callers allocate. */
enum dns_service_wait_v1 {
    DNS_WAIT_NONE, DNS_WAIT_RATE, DNS_WAIT_COOLDOWN, DNS_WAIT_RECOVERY,
    DNS_WAIT_NO_BACKEND, DNS_WAIT_TURN, DNS_WAIT_CONCURRENCY, DNS_WAIT_WRITE, DNS_WAIT_SCHEDULER,
    DNS_WAIT_COUNT
};
enum dns_service_end_v1 {
    DNS_END_OTHER_RESULT, DNS_END_DEADLINE, DNS_END_BUDGET_OR_CANCEL,
    DNS_END_SHUTDOWN, DNS_END_OTHER, DNS_END_UNACCEPTED_RESULT, DNS_END_COUNT
};
enum dns_service_event_v1 {
    DNS_EVENT_HTTP_429, DNS_EVENT_HTTP_503, DNS_EVENT_HTTP_OTHER,
    DNS_EVENT_DNS_RCODE, DNS_EVENT_DNS_REJECTED, DNS_EVENT_ATTEMPT_TIMEOUT,
    DNS_EVENT_IO_OR_PROTOCOL, DNS_EVENT_COUNT
};
struct dns_upstream_service_diagnostics_v1 {
    unsigned struct_size, version, qps, burst, cooldown_ms;
    uint64_t failure_end[DNS_END_COUNT], skip_end[DNS_END_COUNT];
    uint64_t skip_wait[DNS_WAIT_COUNT];
    /* Last observed event is evidence, not a claim of exclusive root cause.
     * Slot zero means none recorded; all slots sum to service failure_count. */
    uint64_t failure_last_event[DNS_EVENT_COUNT + 1];
    /* Event counts can exceed queries and must never be used as a denominator. */
    uint64_t events[DNS_EVENT_COUNT];
};
/* Base accounting and breakdowns copied under the same service lock. */
int dns_client_get_service_diagnostics_v1(const char *service_id,
    struct dns_upstream_service_snapshot_v1 *base, struct dns_upstream_service_diagnostics_v1 *out);
struct dns_client_loop_diagnostics_v1 {
    unsigned struct_size, version, thread_id, cpu_clock_available;
    uint64_t iterations, zero_waits, zero_wait_no_events, ready_events, wakeups, periodic_runs;
    uint64_t cpu_total_ns, sample_cpu_ns, sample_wall_ms, sample_tick_ms, sample_age_ms;
};
int dns_client_get_loop_diagnostics_v1(struct dns_client_loop_diagnostics_v1 *out);
#ifdef __cplusplus
}
#endif
#endif
