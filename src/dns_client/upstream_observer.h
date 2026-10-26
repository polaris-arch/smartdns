/* Passive diagnostics for endpoints outside the pool scheduler. */
#ifndef DNS_CLIENT_UPSTREAM_OBSERVER_H
#define DNS_CLIENT_UPSTREAM_OBSERVER_H
#include "upstream_service.h"
#ifdef __cplusplus
extern "C" {
#endif
struct dns_endpoint_diagnostics {
    pthread_mutex_t lock;
    struct dns_upstream_service_snapshot_v1 base;
    struct dns_upstream_service_diagnostics_v1 breakdown;
    struct dns_upstream_failure_snapshot_v1 *failures;
    struct dns_upstream_policy_snapshot_v1 detail;
    struct dns_upstream_event_context_v1 context[DNS_UPSTREAM_DETAIL_EVENTS];
    struct dns_upstream_event_source_v1 *event_sources;
};
void _dns_endpoint_observer_init(struct dns_server_info *ep);
void _dns_endpoint_observer_destroy(struct dns_server_info *ep);
void _dns_endpoint_observe(struct dns_query_struct *q, struct dns_server_info *ep);
/* The *_locked hooks run with the query lock, without taking it recursively. */
void _dns_endpoint_sent_locked(struct dns_query_struct *q, struct dns_server_info *ep);
void _dns_endpoint_wait_locked(struct dns_query_struct *q, struct dns_server_info *ep, unsigned why);
void _dns_endpoint_rtt_locked(struct dns_server_info *ep, unsigned elapsed, int ambiguous);
void _dns_endpoint_result(struct dns_query_struct *q, struct dns_server_info *ep, int accepted);
void _dns_endpoint_event(struct dns_query_struct *q, struct dns_server_info *ep, unsigned event, int count);
void _dns_endpoint_io_error(struct dns_query_struct *q, struct dns_server_info *ep, unsigned phase, int error);
void _dns_endpoint_query_finish(struct dns_query_struct *q);
void _dns_endpoint_query_free(struct dns_query_struct *q);
struct dns_server_info *_dns_endpoint_find(const char *id);
void _dns_endpoint_snapshot(struct dns_server_info *ep, struct dns_upstream_service_snapshot_v1 *base,
    struct dns_upstream_service_diagnostics_v1 *breakdown);
void _dns_endpoint_backend_snapshot(struct dns_server_info *ep, struct dns_upstream_endpoint_snapshot_v1 *out);
void _dns_endpoint_policy_snapshot(struct dns_server_info *ep, struct dns_upstream_policy_snapshot_v1 *out);
void _dns_endpoint_context_snapshot(struct dns_server_info *ep, struct dns_upstream_event_context_snapshot_v1 *out);
unsigned _dns_query_end_reason(struct dns_query_struct *q);
#ifdef __cplusplus
}
#endif
#endif
