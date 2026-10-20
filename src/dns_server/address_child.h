/* Internal ordinary typed requests owned by the strict address-mode join. */
#ifndef SMARTDNS_SERVER_ADDRESS_CHILD_H
#define SMARTDNS_SERVER_ADDRESS_CHILD_H

#include "smartdns/dns.h"

struct dns_request;
struct dns_query_budget;
struct dns_server_post_context;
struct dns_address_child_state;

enum dns_address_child_result {
	DNS_ADDRESS_CHILD_POSITIVE,
	DNS_ADDRESS_CHILD_NODATA,
	DNS_ADDRESS_CHILD_NXDOMAIN,
	DNS_ADDRESS_CHILD_POLICY,
	DNS_ADDRESS_CHILD_FAILURE,
};

/* The wire is borrowed only during a result callback. A separate final_release
 * callback (wire == NULL) releases the owner's custody after all native work.
 * Either callback can run synchronously inside start. */
typedef void (*dns_address_child_callback)(void *arg, enum dns_address_child_result result,
										  const unsigned char *wire, int len, int final_release);

/* Nonzero means no request was admitted and no callback will run. After zero,
 * exactly one result and one final_release callback are owed. The caller must
 * attach both join slots and their owner references before starting either.
 * Cancel only the supplied, operation-owned budget; no native pending leader
 * is joined and no dns_request pointer escapes this interface. */
int _dns_server_address_child_start(const struct dns_request *parent, dns_type_t qtype,
								  struct dns_query_budget *budget, dns_address_child_callback callback, void *arg);

/* Native pipeline hooks. Nested CNAME work inherits admission and provenance,
 * but never inherits the root observer or its ownership reference. */
int _dns_server_address_child_inherit(struct dns_request *child, const struct dns_request *parent);
void _dns_server_address_child_copy(struct dns_request *request, struct dns_request *from);
void _dns_server_address_child_release(struct dns_request *request);
int _dns_server_address_child_check_context(struct dns_request *request, const char *route);
void _dns_server_address_child_upstream(struct dns_request *request, const unsigned char *wire, int len);
void _dns_server_address_child_post(struct dns_server_post_context *context);
int _dns_server_address_child_cache_positive(struct dns_request *request, unsigned char *wire, int *len, int ttl_cap);
/* Separate from child custody: ordinary A/AAAA warmers retain their behavior.
 * Only the eligibility of a native cache packet for address reuse changes. */
void _dns_server_address_cache_prepare(struct dns_request *request);
void _dns_server_address_cache_upstream(struct dns_request *request, const unsigned char *wire, int len);
int _dns_server_address_cache_proven(struct dns_request *request, const unsigned char *wire, int len);

#endif
