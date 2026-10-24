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

#define _GNU_SOURCE

#include "upstream_observer.h"
#include "smartdns/util.h"
#include <limits.h>

#include "client_http2.h"
#include "client_http3.h"
#include "client_http3_control.h"
#include "client_https.h"
#include "client_mdns.h"
#include "client_quic.h"
#include "client_socket.h"
#include "client_tcp.h"
#include "client_tls.h"
#include "client_udp.h"
#include "conn_stream.h"
#include "dns_client.h"
#include "ecs.h"
#include "group.h"
#include "packet.h"
#include "pending_server.h"
#include "proxy.h"
#include "query.h"
#include "upstream_policy.h"
#include "upstream_service.h"

static _Thread_local unsigned response_reject_reason;
#include "server_info.h"
#include "wake_event.h"

static int is_client_init;
struct dns_client client;

void dns_client_flags_init(struct client_dns_server_flags *flags)
{
	memset(flags, 0, sizeof(*flags));
}

static int _dns_client_server_package_address_match(struct dns_server_info *server_info, struct sockaddr *addr,
													socklen_t addr_len)
{
	if (server_info->type == DNS_SERVER_MDNS) {
		return 0;
	}

	if (addr_len != server_info->ai_addrlen) {
		return -1;
	}

	if (memcmp(addr, &server_info->addr, addr_len) != 0) {
		return -1;
	}

	return 0;
}

int _dns_client_recv(struct dns_server_info *server_info, unsigned char *inpacket, int inpacket_len,
					 struct sockaddr *from, socklen_t from_len)
{
	int len = 0;
	int i = 0;
	int j = 0;
	int qtype = 0;
	int qclass = 0;
	char domain[DNS_MAX_CNAME_LEN] = {0};
	int rr_count = 0;
	struct dns_rrs *rrs = NULL;
	unsigned char packet_buff[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	int ret = 0;
	struct dns_query_struct *query = NULL;
	int request_num = 0;
	int has_opt = 0;

	packet->head.tc = 0;

	if (_dns_client_server_package_address_match(server_info, from, from_len) != 0) {
		tlog(TLOG_DEBUG, "packet from invalid server.");
		return -1;
	}
	stats_inc(&server_info->stats.recv_count);

	/* decode domain from udp packet */
	len = dns_decode(packet, DNS_PACKSIZE, inpacket, inpacket_len);
	if (len != 0) {
		char host_name[DNS_MAX_CNAME_LEN];
		tlog(TLOG_INFO, "decode failed, packet len = %d, tc = %d, id = %d, from = %s\n", inpacket_len, packet->head.tc,
			 packet->head.id, get_host_by_addr(host_name, sizeof(host_name), from));
		if (dns_conf.dns_save_fail_packet) {
			dns_packet_save(dns_conf.dns_save_fail_packet_dir, "client", host_name, inpacket, inpacket_len);
		}
		return -1;
	}

	/* not answer, return error */
	if (packet->head.qr != DNS_OP_IQUERY) {
		tlog(TLOG_DEBUG, "message type error.\n");
		return -1;
	}

	tlog(TLOG_DEBUG,
		 "qdcount = %d, ancount = %d, nscount = %d, nrcount = %d, len = %d, id = %d, tc = %d, rd = %d, ra = %d, rcode "
		 "= %d, payloadsize = %d\n",
		 packet->head.qdcount, packet->head.ancount, packet->head.nscount, packet->head.nrcount, inpacket_len,
		 packet->head.id, packet->head.tc, packet->head.rd, packet->head.ra, packet->head.rcode,
		 dns_get_OPT_payload_size(packet));

	/* get question */
	for (j = 0; j < DNS_RRS_END && domain[0] == '\0'; j++) {
		rrs = dns_get_rrs_start(packet, (dns_rr_type)j, &rr_count);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
			dns_get_domain(rrs, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass);
			tlog(TLOG_DEBUG, "domain: %s qtype: %d  qclass: %d\n", domain, qtype, qclass);
			break;
		}
	}

	if (dns_get_OPT_payload_size(packet) > 0) {
		has_opt = 1;
	}

	atomic_set(&server_info->is_alive, 1);
	int latency = get_tick_count() - server_info->send_tick;
	dns_stats_server_stats_avg_time_add(&server_info->stats, latency);

	/* get query reference */
	query = _dns_client_get_request(domain, qtype, packet->head.id);
	if (query == NULL) {
		return 0;
	}

    if (!dns_query_budget_remaining_ms(query->budget)) {
        _dns_client_query_remove(query);
        _dns_client_query_release(query);
        return 0;
    }
	if (has_opt == 0 && server_info->flags.result_flag & DNSSERVER_FLAG_CHECK_EDNS) {
		_dns_client_query_release(query);
		return 0;
	}

	/* avoid multiple replies */
	if (_dns_replied_check_add(query, server_info) != 0) {
		_dns_client_query_release(query);
		return 0;
	}

    _dns_attempt_response_sample(query, server_info);
	_dns_attempt_retire(query, server_info, 0);
	request_num = atomic_read(&query->dns_request_sent);
	if (request_num < 0) {
		_dns_client_query_release(query);
		tlog(TLOG_ERROR, "send count is invalid, %d", request_num);
		return -1;
	}

	/* notify caller dns query result */
	if (query->callback) {
        unsigned saved_reason = response_reject_reason;
        response_reject_reason = DNS_REJECT_UNCLASSIFIED;
		ret = query->callback(query->domain, DNS_QUERY_RESULT, server_info, packet, inpacket, inpacket_len,
							  query->user_ptr);

        unsigned reject_reason = response_reject_reason;
        response_reject_reason = saved_reason;
        int accepted = (ret == DNS_CLIENT_ACTION_OK || ret == DNS_CLIENT_ACTION_OK_WAIT) &&
            (packet->head.rcode == DNS_RC_NOERROR || packet->head.rcode == DNS_RC_NXDOMAIN);
        int completed = !accepted && reject_reason == DNS_REJECT_COMPLETED &&
            (packet->head.rcode == DNS_RC_NOERROR || packet->head.rcode == DNS_RC_NXDOMAIN);
        if (!accepted && !completed) _dns_service_diagnostic_event(query, server_info,
            packet->head.rcode != DNS_RC_NOERROR && packet->head.rcode != DNS_RC_NXDOMAIN ?
            DNS_EVENT_DNS_RCODE : DNS_EVENT_DNS_REJECTED);
        if (!accepted) {
            int bad_rcode = packet->head.rcode != DNS_RC_NOERROR && packet->head.rcode != DNS_RC_NXDOMAIN;
            _dns_service_detail_dns(query, server_info, bad_rcode ? DNS_DETAIL_DNS_RCODE : DNS_DETAIL_DNS_REJECT,
                DNS_PHASE_RESPONSE, bad_rcode ? packet->head.rcode : reject_reason, packet);
        }
        /* A late valid response can no longer be consumed by the native
         * request. Preserve its completion evidence without penalizing the
         * endpoint or scheduling another backend attempt. Real wire RCODE
         * errors above remain observable even after another provider won. */
        if (completed) {
            if (server_info->service) stats_inc(&server_info->service->stats.recv_count);
            ret = DNS_CLIENT_ACTION_UNDEFINE;
        } else _dns_service_query_result(query, server_info, accepted);
		if (ret == DNS_CLIENT_ACTION_RETRY || ret == DNS_CLIENT_ACTION_DROP) {
			/* remove this result */
			_dns_replied_check_remove(query, server_info);
			if (ret == DNS_CLIENT_ACTION_RETRY) {
				/* A rejected DNS answer does not justify reconnecting to evade limits. */
				_dns_client_retry_dns_query(query);
			}
		} else {
            _dns_attempt_replied(query, server_info);
			if (ret == DNS_CLIENT_ACTION_OK) {
				pthread_mutex_lock(&query->lock);
                query->result_service = server_info->service;
                query->result_endpoint = server_info;
				query->has_result = 1;
                pthread_mutex_unlock(&query->lock);
			} else if (ret != DNS_CLIENT_ACTION_OK_WAIT) {
				tlog(TLOG_DEBUG, "query %s result is invalid, %d", query->domain, ret);
			}

			if (request_num == 0 && ret != DNS_CLIENT_ACTION_MAY_RETRY && ret != DNS_CLIENT_ACTION_OK_WAIT) {
				/* if all server replied, or done, stop query, release resource */
				_dns_client_query_remove(query);
			}
		}
	}

	stats_inc(&server_info->stats.success_count);
	_dns_client_query_release(query);
	return 0;
}

static int _dns_client_process(struct dns_server_info *server_info, struct epoll_event *event, unsigned long now)
{
    pthread_mutex_lock(&server_info->lock);
    server_info->http3_control_epoch++;
    int has_proxy = server_info->proxy != NULL;
    pthread_mutex_unlock(&server_info->lock);
	if (has_proxy) {
		int ret = _dns_proxy_handshake(server_info, event, now);
		if (ret != 0) {
			return ret;
		}
	}

	if (server_info->type == DNS_SERVER_UDP || server_info->type == DNS_SERVER_MDNS) {
		/* receive from udp */
		return _dns_client_process_udp(server_info, event, now);
	} else if (server_info->type == DNS_SERVER_TCP) {
		/* receive from tcp */
		return _dns_client_process_tcp(server_info, event, now);
	} else if (server_info->type == DNS_SERVER_TLS || server_info->type == DNS_SERVER_HTTPS ||
			   server_info->type == DNS_SERVER_QUIC || server_info->type == DNS_SERVER_HTTP3) {
		/* receive from tls */
		return _dns_client_process_tls(server_info, event, now);
	} else {
		return -1;
	}

	return 0;
}

static int _dns_client_send_http(struct dns_server_info *server_info, struct dns_query_struct *query, void *packet_data,
								 int packet_data_len)
{
	/* If ALPN is negotiated and is NOT h2, use HTTP/1.1 */
	if (server_info->alpn_selected[0] != '\0' && strncmp(server_info->alpn_selected, "h2", 2) != 0) {
		return _dns_client_send_http1(server_info, query, packet_data, packet_data_len);
	}

	/* Default to HTTP/2 buffering (stream-based).
	   If ALPN later turns out to be H1, _dns_client_process_stream_writes will handle it. */
	return _dns_client_send_http2(server_info, query, packet_data, packet_data_len);
}

static int _dns_client_check_server_prohibit(struct dns_server_info *server_info, int prohibit_time)
{
	if (server_info->prohibit) {
		if (server_info->is_already_prohibit == 0) {
			server_info->is_already_prohibit = 1;
			_dns_server_inc_prohibit_server_num(server_info);
			time(&server_info->last_send);
			time(&server_info->last_recv);
			if (server_info->type != DNS_SERVER_MDNS) {
				tlog(TLOG_INFO, "server %s not alive, prohibit", server_info->ip);
			}
			_dns_client_shutdown_socket(server_info);
		}

		time_t now = 0;
		time(&now);
		if ((now - prohibit_time < server_info->last_send)) {
			return 1;
		}
		server_info->prohibit = 0;
		server_info->is_already_prohibit = 0;
		_dns_server_dec_prohibit_server_num(server_info);
		if (now - prohibit_time >= server_info->last_send) {
			_dns_client_close_socket(server_info);
		}
	}
	return 0;
}

static int _dns_client_send_one_packet(struct dns_server_info *server_info, struct dns_query_struct *query,
									   void *packet_data, int packet_data_len)
{
	int ret = 0;
	int send_err = 0;

	stats_inc(&server_info->stats.total);
	errno = 0;
	server_info->send_tick = get_tick_count();

	while (1) {
		switch (server_info->type) {
        case DNS_SERVER_UDP: {
            unsigned generation = _dns_attempt_generation(query, server_info);
            if (server_info->service && _dns_attempt_wire_begin(query, server_info, generation) != DNS_ADMIT_OK) {
                _dns_attempt_retire(query, server_info, generation); return -1;
            }
            ret = _dns_client_send_udp(server_info, packet_data, packet_data_len);
            send_err = errno;
            if (!ret) _dns_attempt_mark_sent(query, server_info, generation);
            if (server_info->service) {
                if (ret) {
                    /* Datagram failure leaves no buffered owner. Revoke this
                     * lease, but do not self-feed a new turn on socket pressure. */
                    if (send_err == EAGAIN || send_err == EWOULDBLOCK)
                        __atomic_store_n(&server_info->service->next_eligible,
                            get_tick_count() + 100, __ATOMIC_RELEASE);
                    _dns_service_write_result(query, server_info, generation, 0, 0);
                }
            }
            break;
        }
		case DNS_SERVER_TCP:
			/* tcp query */
			ret = _dns_client_send_framed(server_info, query, packet_data, packet_data_len);
			send_err = errno;
			break;
		case DNS_SERVER_TLS:
			/* tls query */
			ret = _dns_client_send_framed(server_info, query, packet_data, packet_data_len);
			send_err = errno;
			break;
		case DNS_SERVER_HTTPS:
			/* https query - buffer raw data in stream, protocol determined later */
			ret = _dns_client_send_http(server_info, query, packet_data, packet_data_len);
			send_err = errno;
			break;
		case DNS_SERVER_MDNS:
			/* mdns query */
			ret = _dns_client_send_udp_mdns(server_info, packet_data, packet_data_len);
			send_err = errno;
			break;
		case DNS_SERVER_QUIC:
			/* quic query */
			ret = _dns_client_send_quic(query, server_info, packet_data, packet_data_len);
			send_err = errno;
			break;
		case DNS_SERVER_HTTP3:
			/* http3 query */
			ret = _dns_client_send_http3(query, server_info, packet_data, packet_data_len);
			send_err = errno;
			break;
		default:
			/* unsupported query type */
			ret = -1;
			break;
		}

		if (ret != 0) {
            _dns_endpoint_io_error(query, server_info, DNS_PHASE_SOCKET, send_err);
			switch (send_err) {
			case EBADF:
			case ECONNRESET:
			case EPIPE:
			case EDESTADDRREQ:
			case EINVAL:
			case EISCONN:
			case ENOTCONN:
			case ENOTSOCK:
			case EOPNOTSUPP: {
				tlog(TLOG_DEBUG, "send query to %s failed, %s, type: %d", server_info->ip, strerror(send_err),
					 server_info->type);
                _dns_service_endpoint_failure(server_info);
				_dns_client_close_socket(server_info);
                /* Reconnect is scheduled through the same admission path. */
				_dns_attempt_retire(query, server_info, 0);
				return -1;
			}
			default:
				break;
			}

			tlog(TLOG_DEBUG, "send query to %s failed, %s, type: %d", server_info->ip, strerror(send_err),
				 server_info->type);
			time_t now = 0;
			time(&now);
			if (server_info->service) {
                if (send_err != EAGAIN && send_err != EWOULDBLOCK) _dns_service_endpoint_failure(server_info);
            } else if (now - 10 > server_info->last_recv || send_err != ENOMEM) {
				server_info->prohibit = 1;
			}

			_dns_attempt_retire(query, server_info, 0);
			return -1;
		}
		break;
	}
	time(&server_info->last_send);

	return 0;
}

struct service_dispatch_context {
    struct dns_query_struct *query;
    unsigned long now;
    int pass;
};
static int _dns_client_service_eligible(struct dns_server_info *server, void *opaque)
{
    struct service_dispatch_context *ctx = opaque;
    if (!ctx->pass && server->flags.fallback && ctx->now - ctx->query->created_tick < DNS_QUERY_TIMEOUT) return 0;
    if (server->service) return _dns_service_endpoint_eligible(server, ctx->now);
    pthread_mutex_lock(&server->lock);
    int eligible = !_dns_client_check_server_prohibit(server, ctx->pass ? 5 : 60);
    pthread_mutex_unlock(&server->lock);
    return eligible;
}
/* A routing group contains logical services, not their endpoint declarations.
 * Configuration bounds groups to DNS_MAX_SERVERS. Stack snapshots avoid allocating
 * under the global registry lock or per deferred scheduler tick. */
static int _dns_client_send_packet_services(struct dns_query_struct *query, void *packet, int len,
    struct dns_server_group *group, unsigned long now)
{
    struct { struct dns_upstream_service *service; struct dns_server_info *server; } targets[DNS_MAX_SERVERS];
    unsigned count = 0;
    struct dns_server_group_member *member;
    list_for_each_entry(member, &group->head, list) {
        if (count == DNS_MAX_SERVERS) break;
        targets[count].service = member->service; targets[count].server = member->server;
        if (member->service) _dns_service_get(member->service);
        else dns_client_server_info_get(member->server);
        count++;
    }
    pthread_mutex_unlock(&client.server_list_lock);
    unsigned char buffer[DNS_IN_PACKSIZE];
    unsigned sent = 0;
    atomic_inc(&query->dns_request_sent);
    struct service_dispatch_context ctx = {.query = query, .now = now, .pass = 0};
    for (unsigned i = 0; i < count; i++) {
        struct dns_server_info *server = targets[i].server;
        if (targets[i].service) {
            server = _dns_service_select(targets[i].service, query, _dns_client_service_eligible, &ctx);
            if (!server) continue;
        } else {
            _dns_endpoint_observe(query, server);
            if (!_dns_client_service_eligible(server, &ctx) || _dns_attempt_begin(query, server) != DNS_ADMIT_OK) continue;
        }
        _dns_service_prepare_connection(server);
        pthread_mutex_lock(&server->lock);
        int socket_result = server->fd < 0 ? _dns_client_create_socket(server) : 0;
        int socket_errno = errno;
        pthread_mutex_unlock(&server->lock);
        if (socket_result) {
            _dns_endpoint_io_error(query, server, DNS_PHASE_CONNECT, socket_errno);
            if (server->service && socket_errno != EAGAIN) _dns_service_endpoint_failure(server);
            _dns_attempt_retire(query, server, 0);
        } else {
            void *data = NULL; int data_len = 0;
            if (_dns_client_setup_server_packet(server, query, packet, len, buffer, &data, &data_len))
                _dns_attempt_retire(query, server, 0);
            else if (!_dns_client_send_one_packet(server, query, data, data_len)) sent++;
        }
        if (targets[i].service) dns_client_server_info_release(server);
        if (sent && query->single_upstream) break;
    }
    atomic_dec(&query->dns_request_sent);
    for (unsigned i = 0; i < count; i++) {
        if (targets[i].service) _dns_service_put(targets[i].service);
        else dns_client_server_info_release(targets[i].server);
    }
    query->next_send_tick = now + 100;
    return 0;
}

int _dns_client_send_packet(struct dns_query_struct *query, void *packet, int len)
{
	struct dns_server_group_member *member;
	unsigned char buffer[DNS_IN_PACKSIZE];
	int sent = 0;
	unsigned long now = get_tick_count();
	query->send_tick = now;
	if (query->terminal || !dns_query_budget_remaining_ms(query->budget)) return 0;
	/* Preserve configured group fanout. Admission only suppresses the affected endpoint. */
	pthread_mutex_lock(&client.server_list_lock);
	struct dns_server_group *group = query->server_group;
	if (!query->bootstrap_only && now - query->created_tick >= (DNS_QUERY_RETRY - 1) * DNS_QUERY_TIMEOUT) {
		struct dns_server_group *fallback = _dns_client_get_group("fallback");
		if (fallback) group = fallback;
	}
    if (group->service_members) return _dns_client_send_packet_services(query, packet, len, group, now);
	atomic_inc(&query->dns_request_sent); /* protect against reentrant completion */
    unsigned bootstrap_count = 0, bootstrap_selected = 0;
    if (query->bootstrap_only && query->single_upstream) {
        list_for_each_entry(member, &group->head, list) bootstrap_count++;
        if (bootstrap_count) bootstrap_selected = query->bootstrap_cursor++ % bootstrap_count;
    }
	for (int pass = 0; pass < 2 && sent == 0; pass++) {
        unsigned bootstrap_index = 0;
		list_for_each_entry(member, &group->head, list) {
            /* Only the validated bootstrap group participates. A successful UDP
             * send is not a successful resolution: rotate on the next bounded
             * retry so a silent head cannot starve another configured resolver. */
            if (bootstrap_count && bootstrap_index++ != bootstrap_selected) continue;
			struct dns_server_info *server_info = member->server;
            _dns_endpoint_observe(query, server_info);
			void *data = NULL;
			int data_len = 0;
			if (pass == 0 && server_info->flags.fallback && now - query->created_tick < DNS_QUERY_TIMEOUT) continue;
			if (_dns_client_check_server_prohibit(server_info, pass == 0 ? 60 : 5)) continue;
			/* Never create sockets or allocate a stream for admission-denied work. */
			if (_dns_attempt_begin(query, server_info) != DNS_ADMIT_OK) continue;
			if (server_info->fd <= 0 && _dns_client_create_socket(server_info) != 0) {
                int socket_error = errno;
                _dns_endpoint_io_error(query, server_info, DNS_PHASE_CONNECT, socket_error);
				_dns_attempt_retire(query, server_info, 0);
				server_info->prohibit = 1;
				continue;
			}
			if (_dns_client_setup_server_packet(server_info, query, packet, len, buffer, &data, &data_len) != 0) {
				_dns_attempt_retire(query, server_info, 0); continue;
			}
			if (_dns_client_send_one_packet(server_info, query, data, data_len) == 0) {
				sent++;
				if (query->single_upstream) break;
			}
		}
	}
	atomic_dec(&query->dns_request_sent);
	pthread_mutex_unlock(&client.server_list_lock);
	/* Deferred admissions remain on the existing query list, not a second queue. */
	query->next_send_tick = now + 100;
	return 0;
}

struct dns_query_budget *dns_client_query_budget_new(const char *group_name)
{
    struct dns_server_group *selected = _dns_client_get_dnsserver_group(group_name);
    if (!selected) return NULL;
    unsigned int members = 0, lifetime = 0;
    pthread_mutex_lock(&client.server_list_lock);
    struct dns_server_group *groups[2] = {selected, _dns_client_get_group("fallback")};
    for (int i = 0; i < 2; i++) {
        if (!groups[i] || (i && groups[i] == selected)) continue;
        struct dns_server_group_member *member;
        list_for_each_entry(member, &groups[i]->head, list) {
            if (members < UINT_MAX / DNS_QUERY_RETRY) members++;
            unsigned member_lifetime = member->service && member->service->config.query_timeout_ms ?
                member->service->config.query_timeout_ms : DNS_QUERY_LIFETIME;
            if (member_lifetime > lifetime) lifetime = member_lifetime;
        }
    }
    pthread_mutex_unlock(&client.server_list_lock);
    return dns_query_budget_new(members ? members * DNS_QUERY_RETRY : 1, lifetime ? lifetime : DNS_QUERY_LIFETIME);
}

int dns_client_query(const char *domain, int qtype, dns_client_callback callback, void *user_ptr,
					 const char *group_name, struct dns_query_options *options)
{
	struct dns_query_struct *query = NULL;
	int ret = 0;
	int unused __attribute__((unused));

	if (domain == NULL) {
		goto errout;
	}

	if (atomic_read(&client.run) == 0) {
		goto errout;
	}

	query = zalloc(1, sizeof(*query));
	if (query == NULL) {
		goto errout;
	}

	INIT_HLIST_NODE(&query->domain_node);
	INIT_LIST_HEAD(&query->dns_request_list);
	INIT_LIST_HEAD(&query->conn_stream_list);
	pthread_mutex_init(&query->lock, NULL);
	atomic_set(&query->refcnt, 0);
	atomic_set(&query->dns_request_sent, 0);
	atomic_set(&query->retry_count, DNS_QUERY_RETRY);
	hash_init(query->replied_map);
	safe_strncpy(query->domain, domain, DNS_MAX_CNAME_LEN);
	query->user_ptr = user_ptr;
	query->callback = callback;
	query->qtype = qtype;
	query->send_tick = 0;
	query->created_tick = get_tick_count();
	query->next_send_tick = query->created_tick;
	query->single_upstream = !!(options->enable_flag & DNS_QUEY_OPTION_SINGLE_UPSTREAM);
	query->checking_disabled = !!(options->enable_flag & DNS_QUEY_OPTION_CD);
    query->bootstrap_only = !!(options->enable_flag & DNS_QUEY_OPTION_BOOTSTRAP_ONLY);
	if (options->enable_flag & DNS_QUEY_OPTION_BUDGET) {
		query->budget = options->budget;
		dns_query_budget_get(query->budget);
	}
	query->lifetime_ms = DNS_QUERY_LIFETIME;
	query->has_result = 0;
    query->result_service = NULL;
	query->server_group = query->bootstrap_only ? _dns_client_get_group("bootstrap-dns") :
        _dns_client_get_dnsserver_group(group_name);
    if (query->bootstrap_only && (!query->server_group || list_empty(&query->server_group->head) ||
        query->server_group->service_members)) goto errout;
    if (query->bootstrap_only)
        query->bootstrap_cursor = (options->enable_flag & DNS_QUEY_OPTION_BOOTSTRAP_START) ? options->bootstrap_start :
            __atomic_fetch_add(&query->server_group->bootstrap_query_sequence, 1, __ATOMIC_RELAXED);
	if (query->server_group == NULL) {
		tlog(TLOG_ERROR, "get dns server group %s failed.", group_name);
		goto errout;
	}

    if (!query->budget) {
        if (query->bootstrap_only) {
            unsigned count = 0;
            struct dns_server_group_member *member;
            list_for_each_entry(member, &query->server_group->head, list) count++;
            query->budget = dns_query_budget_new(count * DNS_QUERY_RETRY, DNS_QUERY_LIFETIME);
        } else query->budget = dns_client_query_budget_new(group_name);
        if (!query->budget) goto errout;
    }

    unsigned remaining = dns_query_budget_remaining_ms(query->budget);
    if (remaining) query->lifetime_ms = remaining;
	query->conf = dns_server_get_rule_group(options->conf_group_name);
	if (query->conf == NULL) {
		tlog(TLOG_ERROR, "get dns config group %s failed.", options->conf_group_name);
		goto errout;
	}

	if (_dns_client_query_parser_options(query, options) != 0) {
		tlog(TLOG_ERROR, "parser options for %s failed.", domain);
		goto errout;
	}

	_dns_client_query_get(query);
	/* add query to hashtable */
	if (_dns_client_add_hashmap(query) != 0) {
		tlog(TLOG_ERROR, "add query to hash map failed.");
		goto errout;
	}

	/* send query */
	_dns_client_query_get(query);
	ret = _dns_client_send_query(query);
	if (ret != 0) {
		_dns_client_query_release(query);
		goto errout_del_list;
	}

	pthread_mutex_lock(&client.domain_map_lock);
	if (hash_hashed(&query->domain_node)) {
		if (list_empty(&client.dns_request_list)) {
			_dns_client_do_wakeup_event();
		}

		list_add_tail(&query->dns_request_list, &client.dns_request_list);
	}
	pthread_mutex_unlock(&client.domain_map_lock);

	tlog(TLOG_INFO, "request: %s, qtype: %d, id: %d, group: %s", domain, qtype, query->sid,
		 query->server_group->group_name);
	_dns_client_query_release(query);

	return 0;
errout_del_list:
	query->callback = NULL;
	_dns_client_query_remove(query);
	query = NULL;
errout:
	if (query) {
		dns_query_budget_put(query->budget);
		free(query);
	}
	return -1;
}

static void _dns_client_period_run_second(void)
{
	_dns_services_network_tick();
	_dns_client_check_tcp();
	_dns_client_check_servers();
	_dns_client_add_pending_servers();
}

static void _dns_client_period_run(unsigned int msec)
{
	struct dns_query_struct *query = NULL;
	struct dns_query_struct *tmp = NULL;

	LIST_HEAD(check_list);
	unsigned long now = get_tick_count();

	/* get query which timed out to check list */
	pthread_mutex_lock(&client.domain_map_lock);
	list_for_each_entry_safe(query, tmp, &client.dns_request_list, dns_request_list)
	{
		if (now >= query->next_send_tick) {
			list_add(&query->period_list, &check_list);
			_dns_client_query_get(query);
		}
	}
	pthread_mutex_unlock(&client.domain_map_lock);

	list_for_each_entry_safe(query, tmp, &check_list, period_list)
	{
		/* free timed out query, and notify caller */
		list_del_init(&query->period_list);

		_dns_attempt_expire(query, now);
		/* Retain the existing four 500ms rounds as a finite nominal lifetime.
		 * Deferral never grants a fresh lifetime or creates duplicate active work. */
		if (query->terminal) {
			/* already completed by a callback */
		} else if (now - query->created_tick >= query->lifetime_ms ||
				   !dns_query_budget_remaining_ms(query->budget)) {
			_dns_client_query_remove(query);
		} else if (atomic_read(&query->dns_request_sent) == 0) {
			if (query->has_result || dns_query_budget_exhausted(query->budget)) {
				_dns_client_query_remove(query);
			} else {
				_dns_client_send_query(query);
			}
		}
		query->next_send_tick = now + 100;
		_dns_client_query_release(query);
	}

    /* Capacity or token availability need not cause a socket readiness edge. */
    pthread_mutex_lock(&client.server_list_lock);
    struct dns_server_info *server;
    list_for_each_entry(server, &client.dns_server_list, list) {
        if (server->status != DNS_SERVER_STATUS_CONNECTED) continue;
        /* Datagram transports own no conn_streams or H3 control state. Query
         * expiry/cancellation was handled above; do not prune an empty list. */
        if (server->type == DNS_SERVER_UDP || server->type == DNS_SERVER_MDNS) continue;
        server->http3_control_epoch++;
        if (_dns_client_conn_prune(server)) { _dns_client_close_socket(server); continue; }
        if (server->type == DNS_SERVER_HTTP3 && _dns_http3_is_draining(server) && list_empty(&server->conn_stream_list)) {
            _dns_client_close_socket(server); continue; /* graceful drain completed */
        }
        /* Pruning may remove the last server-list entry while H2 still owns
         * its canceled flow-controlled body. Pump that owner to abort/discard. */
        if (server->type != DNS_SERVER_HTTP3 && list_empty(&server->conn_stream_list) &&
            !server->http2_write_owner) continue;
        if (server->type == DNS_SERVER_HTTPS) {
            if (!strncmp(server->alpn_selected, "h2", 2)) {
                if (_dns_client_http2_process_write(server) < 0) { _dns_service_endpoint_failure(server); _dns_client_close_socket(server); }
            } else if (!server->send_buff.len && _dns_client_process_stream_writes(server) < 0) { _dns_service_endpoint_failure(server); _dns_client_close_socket(server); }
        } else if (server->type == DNS_SERVER_TCP || server->type == DNS_SERVER_TLS) {
            if (_dns_client_process_stream_writes(server) < 0) { _dns_service_endpoint_failure(server); _dns_client_close_socket(server); }
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
        } else if (server->type == DNS_SERVER_QUIC || server->type == DNS_SERVER_HTTP3) {
            struct epoll_event event = {.events = EPOLLOUT};
            event.data.ptr = server;
            _dns_client_process_quic(server, &event, now);
#endif
        }
    }
    pthread_mutex_unlock(&client.server_list_lock);

	if (msec % 10 == 0) {
		_dns_client_period_run_second();
	}
}

void _dns_client_event_batch_pin(struct epoll_event *events, int count)
{
    for (int i = 0; i < count; i++)
        if (events[i].data.fd != client.fd_wakeup && events[i].data.ptr)
            dns_client_server_info_get(events[i].data.ptr);
}
void _dns_client_event_batch_unpin(struct epoll_event *events, int count)
{
    for (int i = 0; i < count; i++)
        if (events[i].data.fd != client.fd_wakeup && events[i].data.ptr)
            dns_client_server_info_release(events[i].data.ptr);
}

static void *_dns_client_work(void *arg)
{
	struct epoll_event events[DNS_MAX_EVENTS + 1];
	int num = 0;
	int i = 0;
	unsigned long now = {0};
	unsigned int msec = 0;
	unsigned int sleep = 100;
	int sleep_time = 0;
	unsigned long expect_time = 0;
	unsigned long start_time = 0;

	now = get_tick_count();
	start_time = now;
	expect_time = now + sleep;
    _dns_client_loop_diagnostic_start(now);

	while (atomic_read(&client.run)) {
		now = get_tick_count();
        _dns_services_run_due(now);

		if (now >= expect_time) {
			unsigned long elapsed_from_start = now - start_time;
			unsigned int current_period = (elapsed_from_start + sleep / 2) / sleep;

			if (current_period > msec) {
				msec = current_period;
			}

			expect_time = start_time + (msec + 1) * sleep;
			_dns_client_period_run(msec);
            _dns_client_loop_diagnostic_period();
			msec++;

			/* When client is idle, the sleep time is 1000ms, to reduce CPU usage */
			pthread_mutex_lock(&client.domain_map_lock);
			if (list_empty(&client.dns_request_list)) {
				if (msec % 10 != 0) {
					msec = ((msec / 10) + 1) * 10;
					expect_time = start_time + msec * sleep;
				}
			}
			pthread_mutex_unlock(&client.domain_map_lock);
		}

		sleep_time = (int)(expect_time - now);
		if (sleep_time < 0) {
			sleep_time = 0;
		}

        unsigned long service_due = _dns_services_next_deadline();
        if (service_due <= now) sleep_time = 0;
        else if (service_due - now < (unsigned long)sleep_time) sleep_time = service_due - now;
		num = epoll_wait(client.epoll_fd, events, DNS_MAX_EVENTS, sleep_time);
        _dns_client_loop_diagnostic_poll(get_tick_count(), sleep_time, num);
		if (num < 0) {
			usleep(100000);
			continue;
		}

        /* epoll returns borrowed pointers for the whole batch. Bootstrap/TTL
         * callbacks can revoke later entries, so pin every endpoint before any
         * callback or timer runs, not only when its individual event is reached. */
        _dns_client_event_batch_pin(events, num);
		for (i = 0; i < num; i++) {
			struct epoll_event *event = &events[i];
			struct dns_server_info *server_info = (struct dns_server_info *)event->data.ptr;
			if (event->data.fd == client.fd_wakeup) {
				_dns_client_clear_wakeup_event();
                _dns_client_loop_diagnostic_wake();
                /* New work must leave the idle 1s cadence. Restore the existing
                 * 100ms scan grid without resetting any query/attempt deadline. */
                unsigned long wake_now = get_tick_count();
                if (expect_time > wake_now + sleep) {
                    msec = (wake_now - start_time) / sleep;
                    expect_time = start_time + (msec + 1) * sleep;
                }
				continue;
			}

			if (server_info == NULL) {
				tlog(TLOG_WARN, "server info is invalid.");
				continue;
			}

            _dns_services_run_due(get_tick_count());
            pthread_mutex_lock(&server_info->lock);
            int live_event = server_info->fd >= 0 &&
                (!server_info->service || !__atomic_load_n(&server_info->service_revoked, __ATOMIC_ACQUIRE) ||
                    server_info->active_attempts);
            _dns_client_loop_diagnostic_ready(server_info, event->events, now, live_event);
            pthread_mutex_unlock(&server_info->lock);
            if (live_event) {
                server_info->service_error_phase = DNS_PHASE_SOCKET;
                server_info->service_error_code = server_info->service_system_error = 0;
                server_info->service_tls_error = 0;
                int processed = _dns_client_process(server_info, event, now);
                if (processed < 0 && (server_info->service || server_info->diagnostic) &&
                    !_dns_policy_endpoint_cooldown(server_info, get_tick_count())) {
                    if (server_info->service_normal_close) {
                        _dns_service_detail(NULL, server_info, DNS_DETAIL_IDLE_CLOSE,
                            server_info->service_error_phase, 0, 0, 0);
                    } else {
                        _dns_service_diagnostic_event(NULL, server_info, DNS_EVENT_IO_OR_PROTOCOL);
                        _dns_service_detail(NULL, server_info, DNS_DETAIL_TRANSPORT_ERROR,
                            server_info->service_error_phase, server_info->service_error_code, 0, 0);
                        _dns_service_endpoint_failure(server_info);
                    }
                }
                if (processed >= 0 && (server_info->type == DNS_SERVER_HTTP3 || server_info->type == DNS_SERVER_QUIC))
                    _dns_service_transport_changed(server_info);
            }
            _dns_services_flush_pending();
		}
        _dns_client_event_batch_unpin(events, num);
	}

	close(client.epoll_fd);
	client.epoll_fd = -1;

	return NULL;
}

void dns_client_response_reject_reason(unsigned reason)
{
    response_reject_reason = reason < DNS_REJECT_COUNT ? reason : DNS_REJECT_UNCLASSIFIED;
}

int dns_client_init(void)
{
	pthread_attr_t attr;
	int epollfd = -1;
	int fd_wakeup = -1;
	int ret = 0;

	if (is_client_init == 1) {
		return -1;
	}

	if (client.epoll_fd > 0) {
		return -1;
	}

	memset(&client, 0, sizeof(client));
	pthread_attr_init(&attr);
	atomic_set(&client.dns_server_num, 0);
	atomic_set(&client.dns_server_prohibit_num, 0);
	atomic_set(&client.run_period, 0);

	epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (epollfd < 0) {
		tlog(TLOG_ERROR, "create epoll failed, %s\n", strerror(errno));
		goto errout;
	}

	pthread_mutex_init(&client.server_list_lock, NULL);
	INIT_LIST_HEAD(&client.dns_server_list);

	pthread_mutex_init(&client.domain_map_lock, NULL);
	hash_init(client.domain_map);
	hash_init(client.group);
	INIT_LIST_HEAD(&client.dns_request_list);

	if (dns_client_add_group(DNS_SERVER_GROUP_DEFAULT) != 0) {
		tlog(TLOG_ERROR, "add default server group failed.");
		goto errout;
	}

	if (_dns_client_add_mdns_server() != 0) {
		tlog(TLOG_ERROR, "add mdns server failed.");
		goto errout;
	}

	client.default_group = _dns_client_get_group(DNS_SERVER_GROUP_DEFAULT);
	client.epoll_fd = epollfd;
	atomic_set(&client.run, 1);

	/* start work task */
	ret = pthread_create(&client.tid, &attr, _dns_client_work, NULL);
	if (ret != 0) {
		tlog(TLOG_ERROR, "create client work thread failed, %s\n", strerror(errno));
		goto errout;
	}

	fd_wakeup = _dns_client_create_wakeup_event();
	if (fd_wakeup < 0) {
		tlog(TLOG_ERROR, "create wakeup event failed, %s\n", strerror(errno));
		goto errout;
	}

	client.fd_wakeup = fd_wakeup;
	is_client_init = 1;

	return 0;
errout:
	if (client.tid) {
		void *retval = NULL;
		atomic_set(&client.run, 0);
		pthread_join(client.tid, &retval);
		client.tid = 0;
	}

	if (epollfd > 0) {
		close(epollfd);
	}

	if (fd_wakeup > 0) {
		close(fd_wakeup);
	}

	pthread_mutex_destroy(&client.server_list_lock);
	pthread_mutex_destroy(&client.domain_map_lock);

	return -1;
}

void dns_client_exit(void)
{
	if (is_client_init == 0) {
		return;
	}

	if (client.tid) {
		void *ret = NULL;
		atomic_set(&client.run, 0);
		_dns_client_do_wakeup_event();
		pthread_join(client.tid, &ret);
		client.tid = 0;
	}

	/* free all resources */
    _dns_services_stop();
	_dns_client_close_wakeup_event();
	_dns_client_remove_all_pending_servers();
	_dns_client_server_remove_all();
	_dns_client_query_remove_all();
	_dns_client_group_remove_all();
    _dns_services_remove_all();

	pthread_mutex_destroy(&client.server_list_lock);
	pthread_mutex_destroy(&client.domain_map_lock);
	if (client.ssl_ctx) {
		SSL_CTX_free(client.ssl_ctx);
		client.ssl_ctx = NULL;
	}

	if (client.ssl_quic_ctx) {
		SSL_CTX_free(client.ssl_quic_ctx);
		client.ssl_quic_ctx = NULL;
	}

	is_client_init = 0;
}
