/* Controller-approved, expiring application-owned egress. GPL-3.0-or-later. */
#ifndef SMARTDNS_EGRESS_CONTRACT_H
#define SMARTDNS_EGRESS_CONTRACT_H
#include <stdint.h>
struct dns_server_info;
#define DNS_EGRESS_MARK 0x4000U
uint64_t _dns_egress_now(void);
uint64_t _dns_egress_epoch(void);
void _dns_egress_invalidate(void);
int _dns_egress_lease(const char *interface, int family, long long configured_mark,
    unsigned *mark, char session[65]);
int _dns_egress_io_allowed(struct dns_server_info *server);
#ifdef TEST
extern void (*_dns_egress_before_bind)(void);
extern uint64_t (*_dns_egress_test_now)(void);
#endif
int _dns_socket_prepare(struct dns_server_info *server, int fd);
int _dns_egress_socket_current(struct dns_server_info *server);
#endif
