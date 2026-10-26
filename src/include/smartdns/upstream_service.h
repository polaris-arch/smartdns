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
    unsigned family; /* 0 dual, 4 IPv4, 6 IPv6. Applies to transport only. */
    unsigned response_timeout_ms, query_timeout_ms, connect_timeout_ms, connect_delay_ms;
    unsigned keepalive_ms, keepalive_disabled, connect_delay_set;
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

/* Optional endpoint activity companion. Original endpoint-v1 stays unchanged.
 * Send peaks use fixed 100ms bins, not an inferred provider quota. */
struct dns_upstream_endpoint_activity_v1 {
    unsigned struct_size, version;
    struct dns_upstream_endpoint_snapshot_v1 endpoint;
    uint64_t http_429, http_503, cooldown_remaining_ms, recovery_in_flight;
    uint64_t sends_current_100ms, sends_peak_100ms, peak_unix_ms, last_backpressure_unix_ms;
};
int dns_client_get_service_endpoint_activity_v1(const char *service_id,
    struct dns_upstream_endpoint_activity_v1 *out, unsigned capacity);

/* Independent bounded policy/detail ABI. Never extend callers' snapshot-v1. */
#define DNS_UPSTREAM_DETAIL_EVENTS 32
#define DNS_UPSTREAM_DETAIL_PATHS 128
enum dns_upstream_detail_kind { DNS_DETAIL_RESPONSE_TIMEOUT, DNS_DETAIL_DNS_REJECT,
    DNS_DETAIL_TRANSPORT_ERROR, DNS_DETAIL_IDLE_CLOSE, DNS_DETAIL_GOAWAY,
    DNS_DETAIL_KEEPALIVE_SENT, DNS_DETAIL_KEEPALIVE_ACK, DNS_DETAIL_KEEPALIVE_TIMEOUT,
    DNS_DETAIL_CONNECT_TIMEOUT, DNS_DETAIL_QUERY_TIMEOUT, DNS_DETAIL_HTTP_429, DNS_DETAIL_HTTP_503, DNS_DETAIL_DNS_RCODE, DNS_DETAIL_COUNT };
enum dns_upstream_phase { DNS_PHASE_RESPONSE, DNS_PHASE_CONNECT, DNS_PHASE_TLS,
    DNS_PHASE_HTTP2, DNS_PHASE_HTTP3, DNS_PHASE_SOCKET, DNS_PHASE_POLICY };
enum dns_tls_operation { DNS_TLS_OP_NONE, DNS_TLS_OP_HANDSHAKE, DNS_TLS_OP_READ, DNS_TLS_OP_WRITE, DNS_TLS_OP_EVENTS };
enum dns_upstream_reject_reason { DNS_REJECT_UNCLASSIFIED, DNS_REJECT_FILTERED,
    DNS_REJECT_TRUNCATED, DNS_REJECT_NO_USABLE_RECORDS, DNS_REJECT_COMPLETED,
    DNS_REJECT_QUESTION, DNS_REJECT_COUNT };
enum dns_upstream_path_state { DNS_PATH_ELIGIBLE, DNS_PATH_FAMILY_DISABLED,
    DNS_PATH_NO_ROUTE, DNS_PATH_NO_SOURCE, DNS_PATH_BINDING_ERROR, DNS_PATH_UNKNOWN };
struct dns_upstream_event_v1 {
    uint64_t sequence, tick_ms, age_ms;
    char ip[DNS_UPSTREAM_IP_TEXT_MAX];
    unsigned kind, phase, family, port, elapsed_ms, limit_ms, query_id;
    int code, system_error;
    uint64_t tls_error;
    char message[128];
};
struct dns_upstream_path_v1 {
    char ip[DNS_UPSTREAM_IP_TEXT_MAX], source[DNS_UPSTREAM_IP_TEXT_MAX], interface[64];
    unsigned family, state, selected, connected, active_attempts, keepalive_ms;
    int system_error;
    uint64_t attempts, successes, failures;
};
struct dns_upstream_policy_snapshot_v1 {
    unsigned struct_size, version, family, response_timeout_ms, query_timeout_ms;
    unsigned connect_timeout_ms, connect_delay_ms, keepalive_ms, event_count, path_count;
    uint64_t sequence, dropped_events, kind_counts[DNS_DETAIL_COUNT], reject_counts[DNS_REJECT_COUNT];
    uint64_t response_histogram[9]; /* <=10,25,50,100,250,500,1000,2000,above; timeouts separate */
    struct dns_upstream_event_v1 events[DNS_UPSTREAM_DETAIL_EVENTS];
    struct dns_upstream_path_v1 paths[DNS_UPSTREAM_DETAIL_PATHS];
};
int dns_client_get_service_policy_v1(const char *service_id, struct dns_upstream_policy_snapshot_v1 *out);
/* Optional companion to policy-v1: join by sequence, never by array position.
 * Wall time is captured when the event occurs; monotonic ages survive NTP steps. */
struct dns_upstream_event_context_v1 {
    uint64_t sequence, unix_ms;
    char domain[256];
    unsigned qtype, dns_summary_valid, rcode, truncated;
    unsigned answers, authority, additional, a_records, aaaa_records, cname_records, soa_records;
};
struct dns_upstream_event_context_snapshot_v1 {
    unsigned struct_size, version, event_count;
    struct dns_upstream_event_context_v1 events[DNS_UPSTREAM_DETAIL_EVENTS];
};
int dns_client_get_service_event_context_v1(const char *service_id,
    struct dns_upstream_event_context_snapshot_v1 *out);
/* Separate companion preserves the published context-v1 allocation size.
 * Sources are a bitset: foreground=1, stale cache hit=2, expiry timer=4,
 * proactive prefetch=8; merged refreshes can carry more than one bit. */
struct dns_upstream_event_source_v1 {
    uint64_t sequence, wan_generation;
    unsigned origin_flags, queue_wait_ms, priority;
    char interface[DNS_SERVER_IFNAME_LEN];
};
struct dns_upstream_event_sources_v1 {
    unsigned struct_size, version, event_count;
    struct dns_upstream_event_source_v1 events[DNS_UPSTREAM_DETAIL_EVENTS];
};
int dns_client_get_service_sources_v1(const char *service_id, struct dns_upstream_event_sources_v1 *out);
struct dns_upstream_wan_runtime_v1 {
    char interface[DNS_SERVER_IFNAME_LEN], ip[DNS_UPSTREAM_IP_TEXT_MAX], source[DNS_UPSTREAM_IP_TEXT_MAX];
    unsigned interface_index, family_mask, connected_family, connected;
    unsigned rate_known, current_rate, known_good_rate, probe_ceiling;
    uint64_t generation, cooldown_remaining_ms, retry_remaining_ms, http_429, last_backpressure_unix_ms;
};
struct dns_upstream_runtime_v1 {
    unsigned struct_size, version, wan_count, qps_mode, configured_cap;
    unsigned foreground_waiting, refresh_waiting, prefetch_waiting;
    struct dns_upstream_wan_runtime_v1 wans[DNS_UPSTREAM_WANS_MAX];
};
int dns_client_get_service_runtime_v1(const char *service_id, struct dns_upstream_runtime_v1 *out);
/* Independent bounded failure evidence. RCODE counters/last-per-code do not
 * disappear when the general event ring is overwritten. Cumulative is process
 * lifetime, not durable across reload/restart. Older v1 ABIs are unchanged. */
#define DNS_UPSTREAM_RCODE_SLOTS 17 /* base codes0..15, slot16 for other */
#define DNS_UPSTREAM_FAILURE_RECENT 8
struct dns_upstream_attempt_progress_v1 {
    unsigned generation, wire_started, request_complete, headers_received, http_status;
    uint64_t admitted_tick, first_sent_tick, last_sent_tick, complete_tick, headers_tick;
};
enum dns_timeout_stage { DNS_TIMEOUT_UNKNOWN, DNS_TIMEOUT_NOT_SENT, DNS_TIMEOUT_SENDING,
    DNS_TIMEOUT_WAIT_HEADERS, DNS_TIMEOUT_READ_BODY, DNS_TIMEOUT_WAIT_RESPONSE, DNS_TIMEOUT_STAGE_COUNT };
struct dns_upstream_failure_event_v1 {
    struct dns_upstream_event_v1 event;
    struct dns_upstream_event_context_v1 context;
    struct dns_upstream_attempt_progress_v1 progress;
    uint64_t connection_generation;
    unsigned active_attempts, tls_operation, tls_error_count, tls_error_overflow, timeout_stage;
    unsigned origin_flags, queue_wait_ms;
    char interface[DNS_SERVER_IFNAME_LEN];
    uint64_t wan_generation;
    unsigned quic_close_valid, quic_close_local, quic_close_transport;
    uint64_t quic_close_code, quic_close_frame;
    uint64_t tls_errors[4];
};
struct dns_upstream_failure_snapshot_v1 {
    unsigned struct_size, version, timeout_count, io_count;
    uint64_t rcode_counts[DNS_UPSTREAM_RCODE_SLOTS], timeout_stages[DNS_TIMEOUT_STAGE_COUNT];
    struct dns_upstream_failure_event_v1 last_rcode[DNS_UPSTREAM_RCODE_SLOTS];
    struct dns_upstream_failure_event_v1 timeouts[DNS_UPSTREAM_FAILURE_RECENT];
    struct dns_upstream_failure_event_v1 io_errors[DNS_UPSTREAM_FAILURE_RECENT];
};
int dns_client_get_service_failures_v1(const char *service_id, struct dns_upstream_failure_snapshot_v1 *out);
/* Recommendations never select an interface or prove Internet reachability. */
#define DNS_NETWORK_INTERFACES_MAX 256
enum dns_network_interface_role {
    DNS_INTERFACE_OTHER, DNS_INTERFACE_DEFAULT_EXIT, DNS_INTERFACE_PPP,
    DNS_INTERFACE_NAMED_WAN, DNS_INTERFACE_INTERNAL, DNS_INTERFACE_TUNNEL
};
struct dns_network_interface_v1 {
    unsigned struct_size, version, index, up, running, loopback, point_to_point;
    unsigned ipv4_count, ipv6_count;
    char name[DNS_SERVER_IFNAME_LEN], address4[DNS_UPSTREAM_IP_TEXT_MAX], address6[DNS_UPSTREAM_IP_TEXT_MAX];
    unsigned link_type, master_index, default_route4, default_route6;
    unsigned link_inventory_complete, route_inventory_complete, role, recommended;
    char kind[32];
};
/* Copied snapshot, sizing/fill contract matches the other copied APIs. */
int dns_client_get_network_interfaces_v1(struct dns_network_interface_v1 *out, unsigned capacity);
/* A callback can attach a semantic rejection reason without changing its action. */
void dns_client_response_reject_reason(unsigned reason);

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
