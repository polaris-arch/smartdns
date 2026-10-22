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
#ifdef __cplusplus
}
#endif
#endif
