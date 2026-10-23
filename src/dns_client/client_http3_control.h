#ifndef SMARTDNS_HTTP3_CONTROL_H
#define SMARTDNS_HTTP3_CONTROL_H
#include "dns_client.h"
int _dns_http3_control_poll(struct dns_server_info *server);
void _dns_http3_control_free(struct dns_server_info *server);
int _dns_http3_request_allowed(struct dns_server_info *server, uint64_t stream_id, int started);
int _dns_http3_keepalive(struct dns_server_info *s);
int _dns_http3_is_draining(struct dns_server_info *server);
int _dns_http3_connection_error(struct dns_server_info *server, uint64_t code);
uint64_t _dns_http3_error(struct dns_server_info *server);
int _dns_http3_control_shutdown(struct dns_server_info *server);
#ifdef TEST
int _dns_http3_control_test_feed(struct dns_server_info *server, unsigned slot,
                               const unsigned char *data, size_t len);
#endif
#endif
