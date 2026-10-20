/* Wire-safe helpers for the bounded ANY responder. No raw compressed RDATA relocation. */
#ifndef SMARTDNS_DNS_ANY_H
#define SMARTDNS_DNS_ANY_H
#include <stdint.h>
#include "smartdns/dns.h"
#ifdef __cplusplus
extern "C" {
#endif
#define DNS_ANY_MAX_RECORDS 64
#define DNS_ANY_MAX_ALIAS 8
struct dns_any_input {
	const unsigned char *data;
	int len;
	unsigned short qtype;
	uint32_t age;
};
int dns_any_type_from_name(const char *name);
/* Validates a full packet, ages each ordinary TTL independently, leaves OPT unchanged.
 * age=0 preserves wire TTLs. minimum excludes OPT and is zero for uncacheable packets. */
int dns_any_wire_age(unsigned char *data, int len, uint32_t age, uint32_t *minimum);
int dns_any_empty_response(const char *domain, int rcode, int tc, unsigned char *out, int capacity);
/* No heap allocation. Returns 1..64 proven direct Answer addresses, or -1.
 * Narrow cache-proof path: no aliases/authority; at most one empty root OPT. */
int dns_any_plain_addresses(const char *domain, int qtype, const unsigned char *wire, int len,
						   unsigned char addresses[DNS_ANY_MAX_RECORDS][DNS_RR_AAAA_LEN]);
/* Returns encoded length, or -1 for failure/conflict. Missing children are data=NULL.
 * Synthesized AD/AA/CD are clear. Only coherent configured answer types are retained. */
int dns_any_merge(const char *domain, const struct dns_any_input *input, int count, int partial,
				  unsigned char *out, int capacity);
#ifdef __cplusplus
}
#endif
#endif
