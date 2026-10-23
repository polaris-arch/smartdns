/* Logical upstream ownership and send-turn state. GPL-3.0-or-later. */
#ifndef DNS_CLIENT_UPSTREAM_SERVICE_H
#define DNS_CLIENT_UPSTREAM_SERVICE_H
#include "dns_client.h"
#include "smartdns/upstream_service.h"
#include <limits.h>
#ifdef __cplusplus
extern "C" {
#endif
struct dns_upstream_discovery;
struct dns_discovery_snapshot;
struct dns_service_observation;
enum dns_service_turn_state {
    DNS_SERVICE_TURN_IDLE, DNS_SERVICE_TURN_SELECTING, DNS_SERVICE_TURN_RESERVED, DNS_SERVICE_TURN_WRITING,
    DNS_SERVICE_TURN_WRITE_WAIT, DNS_SERVICE_TURN_COMMIT_PENDING, DNS_SERVICE_TURN_ABORT_PENDING
};
struct dns_service_observation {
    struct dns_service_observation *next, *hint_next;
    struct list_head waiter;
    struct dns_query_struct *query;
    struct dns_upstream_service *service;
    unsigned long first_sent, accepted_tick;
    uint64_t sends;
    unsigned last_wait, end_reason, last_event;
    unsigned terminal, success, waiting, writer_pending, settled, active_attempts, hint_queued, registered;
};
#ifdef TEST
extern void (*_dns_service_observe_published_test_hook)(struct dns_service_observation *);
#endif
struct dns_upstream_service {
    struct list_head list;
    struct list_head timer;
    unsigned long timer_due;
    struct dns_discovery_snapshot *desired;
    unsigned started;
    atomic_t refs;
    pthread_mutex_t lock;
    /* Leaf lock: never acquire endpoint/query/policy/service locks while held. */
    pthread_mutex_t turn_lock;
    char id[DNS_UPSTREAM_SERVICE_ID_MAX], host[DNS_MAX_HOSTNAME];
    int port;
    dns_server_type_t type;
    struct client_dns_server_flags flags;
    struct dns_upstream_pool_config config;
    struct dns_upstream_policy *policy;
    struct dns_upstream_discovery *discovery;
    struct dns_server_info *members[DNS_UPSTREAM_BACKENDS_MAX * 2];
    unsigned member_count, selected_count, connections, active_attempts;
    unsigned discovered_count, rejected_count, stale;
    unsigned long freshness_until, next_eligible;
    unsigned next_wait;
    uint64_t member_sequence, cursor, turn_sequence;
    unsigned turn_state, cancel_requested, wake_pending, stopping;
    struct dns_server_info *turn_endpoint;
    struct dns_service_observation *turn_observation;
    unsigned turn_attempt_generation;
    unsigned long turn_accepted_tick;
    struct dns_upstream_service *pending_next;
    struct list_head waiters; /* Ready observations only, not all in-flight work. */
    struct dns_service_observation *hints, *deferred_hints;
    struct dns_upstream_service_snapshot_v1 stats;
    struct dns_upstream_service_diagnostics_v1 diagnostics;
    unsigned freshness_known; /* Observation only: published positive-membership TTL. */
};
void _dns_service_get(struct dns_upstream_service *s);
void _dns_service_put(struct dns_upstream_service *s);
void _dns_services_run_due(unsigned long now);
void _dns_services_flush_pending(void);
unsigned long _dns_services_next_deadline(void);
void _dns_services_stop(void);
void _dns_services_remove_all(void);
struct dns_server_info *_dns_service_select(struct dns_upstream_service *s, struct dns_query_struct *q,
    int (*eligible)(struct dns_server_info *, void *), void *context);
int _dns_service_write_pending(struct dns_query_struct *q, struct dns_server_info *ep, unsigned generation);
void _dns_service_unsent_retire(struct dns_query_struct *q, struct dns_server_info *endpoint, unsigned generation);
int _dns_service_write_begin(struct dns_query_struct *q, struct dns_server_info *endpoint, unsigned generation);
void _dns_service_write_result(struct dns_query_struct *q, struct dns_server_info *endpoint,
    unsigned generation, int accepted, int retryable);
void _dns_service_attempt_active(struct dns_query_struct *q, struct dns_upstream_service *service, int delta);
void _dns_service_query_result(struct dns_query_struct *q, struct dns_server_info *endpoint, int accepted);
void _dns_service_query_terminal(struct dns_query_struct *q);
void _dns_service_query_free(struct dns_query_struct *q);
void _dns_service_prepare_connection(struct dns_server_info *endpoint);
int _dns_service_connection_acquire(struct dns_server_info *endpoint);
void _dns_service_connection_release(struct dns_server_info *endpoint);
void _dns_service_endpoint_failure(struct dns_server_info *endpoint);
void _dns_service_endpoint_ready(struct dns_server_info *endpoint);
int _dns_service_endpoint_eligible(struct dns_server_info *endpoint, unsigned long now);
int _dns_service_has_ecs(struct dns_upstream_service *s);
void _dns_service_diagnostic_event(struct dns_query_struct *q, struct dns_server_info *ep, unsigned event);
void _dns_service_diagnostic_http(struct dns_query_struct *q, struct dns_server_info *ep, int status);
void _dns_client_loop_diagnostic_start(unsigned long now);
void _dns_client_loop_diagnostic_poll(unsigned long now, int timeout, int events);
void _dns_client_loop_diagnostic_ready(struct dns_server_info *ep, unsigned events, unsigned long now, int eligible);
void _dns_client_loop_diagnostic_wake(void);
void _dns_client_loop_diagnostic_period(void);

#ifdef TEST
void _dns_service_snapshot_test(struct dns_upstream_service *s, struct dns_upstream_service_snapshot_v1 *out);
#endif
#ifdef __cplusplus
}
#endif
#endif
