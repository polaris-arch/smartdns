#ifndef SMARTDNS_SERVER_ANY_H
#define SMARTDNS_SERVER_ANY_H
#include "dns_server.h"
#ifdef __cplusplus
extern "C" {
#endif
/* 0: handled; -1: context is not eligible, retain transparent normal path. */
int _dns_server_process_any(struct dns_request *request, const char *group_name);
void _dns_server_any_period(void);
void _dns_server_any_destroy(void);
void _dns_server_any_cancel_connection(struct dns_server_conn_head *conn);
void _dns_server_any_cancel_http2_resets(struct dns_server_conn_tls_client *conn);
#ifdef __cplusplus
}
#endif
#endif
