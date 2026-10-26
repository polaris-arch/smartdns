/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _DNS_SERVER_PREFETCH_
#define _DNS_SERVER_PREFETCH_

#include "dns_server.h"
#include "smartdns/dns_cache.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

int _dns_server_prefetch_request(char *domain, dns_type_t qtype, struct dns_server_query_option *server_query_option,
								 int prefetch_flag);
int _dns_server_prefetch_cached(char *domain, dns_type_t qtype, struct dns_server_query_option *options,
    int prefetch_flags, uint64_t cache_generation);
void _dns_server_prefetch_run(unsigned long now);
unsigned long _dns_server_prefetch_deadline(void);
void _dns_server_prefetch_done(void *ticket);
void _dns_server_prefetch_stop(void);
void _dns_server_prefetch_start(void);
#ifdef TEST
extern int _dns_prefetch_test_paused;
void _dns_server_prefetch_test_run(unsigned long now);
#endif

dns_cache_tmout_action_t _dns_server_prefetch_domain(struct dns_conf_group *conf_group, struct dns_cache *dns_cache);

dns_cache_tmout_action_t _dns_server_prefetch_expired_domain(struct dns_conf_group *conf_group,
															 struct dns_cache *dns_cache);
#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
