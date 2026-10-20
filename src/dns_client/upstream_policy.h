#ifndef SMARTDNS_UPSTREAM_POLICY_H
#define SMARTDNS_UPSTREAM_POLICY_H
#include "dns_client.h"
#include <time.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Admission is not a transport error. */
#define DNS_ADMIT_OK 0
#define DNS_ADMIT_WAIT 1
#define DNS_ADMIT_DONE 2
int _dns_policy_attach(struct dns_server_info *server);
void _dns_policy_detach(struct dns_server_info *server);
int _dns_policy_retry_after_ms(const char *value, time_t wall_now, uint64_t *delay);
int _dns_http_age(unsigned char *data, int len, const char *value);
void _dns_policy_http_error(struct dns_server_info *server, int status, const char *retry_after);
int _dns_attempt_wire_begin(struct dns_query_struct *query, struct dns_server_info *server, unsigned int generation);
int _dns_attempt_begin(struct dns_query_struct *query, struct dns_server_info *server);
int _dns_attempt_live(struct dns_query_struct *query, struct dns_server_info *server, unsigned int generation);
void _dns_attempt_replied(struct dns_query_struct *query, struct dns_server_info *server);
int _dns_attempt_retire(struct dns_query_struct *query, struct dns_server_info *server, unsigned int generation);
unsigned int _dns_attempt_generation(struct dns_query_struct *query, struct dns_server_info *server);
void _dns_attempt_mark_sent(struct dns_query_struct *query, struct dns_server_info *server, unsigned int generation);
void _dns_attempt_mark_buffered(struct dns_query_struct *query, struct dns_server_info *server);
void _dns_attempt_expire(struct dns_query_struct *query, unsigned long now);
void _dns_attempt_free_all(struct dns_query_struct *query);
int _dns_query_budget_take(struct dns_query_budget *budget);
#ifdef __cplusplus
}
#endif
#endif
