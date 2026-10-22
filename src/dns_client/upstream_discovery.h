#ifndef SMARTDNS_UPSTREAM_DISCOVERY_H
#define SMARTDNS_UPSTREAM_DISCOVERY_H

#include "smartdns/dns.h"
#include <stdint.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DNS_DISCOVERY_FAMILY_LIMIT 64
#define DNS_DISCOVERY_ADDRESS_LIMIT 128
#define DNS_DISCOVERY_CNAME_LIMIT 8

enum dns_discovery_status {
    DNS_DISCOVERY_PENDING,
    DNS_DISCOVERY_READY,
    DNS_DISCOVERY_STALE,
    DNS_DISCOVERY_EMPTY,
    DNS_DISCOVERY_FAILED,
    DNS_DISCOVERY_REJECTED,
    DNS_DISCOVERY_INCONSISTENT
};
struct dns_discovery_address {
    int family;
    unsigned char addr[16];
    char text[64];
    unsigned long valid_until;
};
struct dns_discovery_snapshot {
    uint64_t generation;
    unsigned int count, discovered, rejected, zero_ttl;
    unsigned int stale;
    unsigned long expires;
    enum dns_discovery_status status;
    struct dns_discovery_address addresses[DNS_DISCOVERY_ADDRESS_LIMIT];
};
struct dns_upstream_discovery;
typedef void (*dns_discovery_callback)(const struct dns_discovery_snapshot *, void *);

/* Lifecycle and timers are serialized on the client IO thread. create may precede
 * thread startup; destroy may also run after it has joined. A callback may destroy
 * its own discovery. Snapshot storage is borrowed only for that callback. */
struct dns_upstream_discovery *_dns_discovery_create(const char *host, dns_discovery_callback callback, void *user);
int _dns_discovery_start(struct dns_upstream_discovery *discovery);
void _dns_discovery_destroy(struct dns_upstream_discovery *discovery);
unsigned long _dns_discovery_next_deadline(void); /* ULONG_MAX if none */
void _dns_discovery_run_due(unsigned long now);

/* Numeric address classification shared with bounded correctness fixtures. */
int _dns_discovery_address_allowed(int family, const unsigned char *address);

#ifdef TEST
/* Feed the same packet parser/state reducer without issuing network requests. */
int _dns_discovery_test_begin(struct dns_upstream_discovery *discovery, unsigned long now);
int _dns_discovery_test_answer(struct dns_upstream_discovery *discovery, int qtype,
                             struct dns_packet *packet, unsigned long now);
void _dns_discovery_test_failure(struct dns_upstream_discovery *discovery, int qtype, unsigned long now);
void _dns_discovery_test_expire(struct dns_upstream_discovery *discovery, unsigned long now);
void *_dns_discovery_test_hold_request(struct dns_upstream_discovery *discovery, int qtype);
int _dns_discovery_test_deliver(void *request, int result_type, struct dns_packet *packet);
#endif
#ifdef __cplusplus
}
#endif
#endif
