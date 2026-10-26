#ifndef SMARTDNS_UPSTREAM_NETWORK_H
#define SMARTDNS_UPSTREAM_NETWORK_H
#include "smartdns/upstream_service.h"
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
void _dns_network_classify(struct dns_network_interface_v1 *out, unsigned count);
/* Parser is shared with offline route/link fixtures; no network side effects. */
int _dns_network_message(struct dns_network_interface_v1 *out, unsigned count, const void *data, size_t size);
#ifdef __cplusplus
}
#endif
#endif
