#ifndef SMARTDNS_UPSTREAM_RATE_H
#define SMARTDNS_UPSTREAM_RATE_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define DNS_RATE_WINDOWS 16
struct dns_rate_window {
    uint64_t second;
    unsigned sent, accepted, rejected, rate, demand;
};
struct dns_rate_controller {
    unsigned cap, current, known_good, probe_cap;
    uint64_t first_sent, changed, last_rejected, last_increase, probe_after;
    struct dns_rate_window windows[DNS_RATE_WINDOWS];
};
void _dns_rate_init(struct dns_rate_controller *r, unsigned cap);
void _dns_rate_sent(struct dns_rate_controller *r, uint64_t now);
void _dns_rate_demand(struct dns_rate_controller *r, uint64_t now);
void _dns_rate_accepted(struct dns_rate_controller *r, uint64_t sent, uint64_t now);
int _dns_rate_rejected(struct dns_rate_controller *r, uint64_t sent, uint64_t now);
#ifdef __cplusplus
}
#endif
#endif
