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

#include "server.h"
#include "client_subnet.h"
#include "dns_conf_group.h"
#include "proxy_names.h"
#include "server_group.h"
#include "smartdns/util.h"

#include <getopt.h>
#include <errno.h>
#include <arpa/inet.h>

int _config_upstream_wan_interfaces(void *data, int argc, char *argv[])
{
    char names[DNS_UPSTREAM_WANS_MAX][DNS_SERVER_IFNAME_LEN] = {{0}};
    unsigned count = 0;
    if (argc < 2) return -1;
    for (int i = 1; i < argc; i++) {
        const char *begin = argv[i];
        while (*begin) {
            const char *end = strchr(begin, ','); size_t n = end ? (size_t)(end - begin) : strlen(begin);
            if (!n || n >= DNS_SERVER_IFNAME_LEN || count == DNS_UPSTREAM_WANS_MAX) return -1;
            for (size_t at = 0; at < n; at++) {
                char c = begin[at];
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strchr("_.:-", c))) return -1;
            }
            memcpy(names[count], begin, n);
            for (unsigned old = 0; old < count; old++) if (!strcmp(names[old], names[count])) return -1;
            count++;
            if (!end) break;
            begin = end + 1; if (!*begin) return -1;
        }
    }
    if (!count) return -1;
    if (data) {
        struct dns_servers *server = data;
        server->upstream_wan_count = count; memcpy(server->upstream_wan_interfaces, names, sizeof(names));
    } else {
        dns_conf.upstream_wan_count = count; memcpy(dns_conf.upstream_wan_interfaces, names, sizeof(names));
    }
    return 0;
}

/* Strict bounded pool parsing. Keep the original authority separate from its
 * numeric backends; legacy host-ip substitution is intentionally unchanged. */
static int _config_pool_number(const char *text, unsigned int *value)
{
	unsigned int n = 0;
	if (!text || !*text) return -1;
	for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
		if (*p < '0' || *p > '9' || n > 64) return -1;
		n = n * 10 + (*p - '0');
	}
	if (!n || n > 64) return -1;
	*value = n;
	return 0;
}

static int _config_pool_ips(struct dns_servers *server, const char *text)
{
	const char *at = text;
	if (!at || !*at) return -1;
	while (*at) {
		const char *end = strchr(at, ',');
		size_t len = end ? (size_t)(end - at) : strlen(at);
		char literal[DNS_MAX_IPLEN], normalized[DNS_MAX_IPLEN];
		struct in_addr a4;
		struct in6_addr a6;
		int family;
		if (!len || len >= sizeof(literal)) return -1;
		memcpy(literal, at, len); literal[len] = '\0';
		if (inet_pton(AF_INET, literal, &a4) == 1) {
			family = AF_INET;
		} else if (inet_pton(AF_INET6, literal, &a6) == 1) {
			if (IN6_IS_ADDR_V4MAPPED(&a6)) {
				memcpy(&a4, &a6.s6_addr[12], sizeof(a4)); family = AF_INET;
			} else family = AF_INET6;
		} else return -1;
		if (family == AF_INET) {
			uint32_t ip = ntohl(a4.s_addr);
			if (ip == INADDR_ANY || IN_MULTICAST(ip) || ip == INADDR_BROADCAST) return -1;
			if (!inet_ntop(AF_INET, &a4, normalized, sizeof(normalized))) return -1;
		} else {
			if (IN6_IS_ADDR_UNSPECIFIED(&a6) || IN6_IS_ADDR_MULTICAST(&a6)) return -1;
			if (!inet_ntop(AF_INET6, &a6, normalized, sizeof(normalized))) return -1;
		}
		unsigned int i;
		for (i = 0; i < server->pool_ip_count; i++)
			if (!strcmp(server->pool_ips[i], normalized)) break;
		if (i == server->pool_ip_count) {
			if (i == 64) return -1;
			safe_strncpy(server->pool_ips[i], normalized, sizeof(server->pool_ips[i]));
			server->pool_ip_count++;
		}
		if (!end) break;
		at = end + 1;
		if (!*at) return -1;
	}
	return 0;
}

static int _config_server(int argc, char *argv[], dns_server_type_t type, int default_port)
{
	int index = dns_conf.server_num;
	struct dns_servers *server = NULL;
	int port = -1;
	char *ip = NULL;
	char scheme[DNS_MAX_CNAME_LEN] = {0};
	int opt = 0;
	int optind_last = 0;
	unsigned int result_flag = 0;
	unsigned int server_flag = 0;
	unsigned char *spki = NULL;
	int drop_packet_latency_ms = 0;
	int tcp_keepalive = -1;
    unsigned path_options_seen = 0, wan_option_seen = 0, rate_cap_seen = 0;
	int is_bootstrap_dns = 0;
	const char *host_ip = NULL;
	unsigned int host_ip_occurrences = 0;
	int legacy_host_ip_invalid = 0;
	int legacy_connection_invalid = 0;
	const char *connection_limit_text = NULL;
	int no_tls_host_name = 0;
	int no_tls_host_verify = 0;
	const char *group_name = NULL;

	int ttl = 0;
	/* clang-format off */
	static struct option long_options[] = {
		{"drop-packet-latency", required_argument, NULL, 'D'},
		{"exclude-default-group", no_argument, NULL, 'e'}, /* exclude this from default group */
		{"group", required_argument, NULL, 'g'}, /* add to group */
		{"proxy", required_argument, NULL, 'p'}, /* proxy server */
		{"no-check-certificate", no_argument, NULL, 'k'}, /* do not check certificate */
		{"bootstrap-dns", no_argument, NULL, 'b'}, /* set as bootstrap dns */
		{"interface", required_argument, NULL, 250}, /* interface */
#ifdef FEATURE_CHECK_EDNS
		/* experimental feature */
		{"check-edns", no_argument, NULL, 251},   /* check edns */
#endif 
		{"whitelist-ip", no_argument, NULL, 252}, /* filtering with whitelist-ip */
		{"blacklist-ip", no_argument, NULL, 253}, /* filtering with blacklist-ip */
		{"set-mark", required_argument, NULL, 254}, /* set mark */
		{"subnet", required_argument, NULL, 256}, /* set subnet */
		{"hitchhiking", no_argument, NULL, 257}, /* hitchhiking */
		{"host-ip", required_argument, NULL, 258}, /* host ip */
		{"spki-pin", required_argument, NULL, 259}, /* check SPKI pin */
		{"host-name", required_argument, NULL, 260}, /* host name */
		{"http-host", required_argument, NULL, 261}, /* http host */
		{"tls-host-verify", required_argument, NULL, 262 }, /* verify tls hostname */
		{"tcp-keepalive", required_argument, NULL, 263}, /* tcp keepalive */
		{"subnet-all-query-types", no_argument, NULL, 264}, /* send subnent for all query types.*/
		{"fallback", no_argument, NULL, 265}, /* fallback */
		{"alpn", required_argument, NULL, 266}, /* alpn */
		{"max-query-rate", required_argument, NULL, 267},
		{"query-burst", required_argument, NULL, 268},
		{"max-concurrent-queries", required_argument, NULL, 269},
		{"quota-group", required_argument, NULL, 270},
		{"upstream-round-robin", no_argument, NULL, 271},
		{"max-upstream-connections", required_argument, NULL, 272},
		{"upstream-ip-pool", no_argument, NULL, 273},
		{"max-upstream-backends", required_argument, NULL, 274},
		{"upstream-cooldown-ms", required_argument, NULL, 275},
        {"upstream-wan", required_argument, NULL, 282},
        {"adaptive-query-rate", required_argument, NULL, 283},
        {"upstream-wan-interfaces", required_argument, NULL, 284},
        {"upstream-retry-cooldown-ms", required_argument, NULL, 285},
        {"upstream-service", no_argument, NULL, 286},
        {"upstream-family", required_argument, NULL, 276},
        {"upstream-response-timeout-ms", required_argument, NULL, 277},
        {"upstream-query-timeout-ms", required_argument, NULL, 278},
        {"upstream-connect-timeout-ms", required_argument, NULL, 279},
        {"upstream-connect-delay-ms", required_argument, NULL, 280},
        {"upstream-keepalive-ms", required_argument, NULL, 281},
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */
	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		return -1;
	}

	ip = argv[1];
	if (index >= DNS_MAX_SERVERS) {
		tlog(TLOG_WARN, "exceeds max server number, %s", ip);
		return 0;
	}

	server = &dns_conf.servers[index];
	const char *source_file = conf_get_conf_file();
	safe_strncpy(server->source_file, source_file ? source_file : "<configuration>", sizeof(server->source_file));
	server->source_line = conf_get_current_lineno();
	server->spki[0] = '\0';
	server->path[0] = '\0';
	server->hostname[0] = '\0';
	server->httphost[0] = '\0';
	server->tls_host_verify[0] = '\0';
	server->proxyname[0] = '\0';
	server->set_mark = -1;
	server->drop_packet_latency_ms = drop_packet_latency_ms;
	server->tcp_keepalive = tcp_keepalive;
	server->subnet_all_query_types = 0;
	server->upstream_round_robin = 0;
	server->max_upstream_connections = 0;
	server->upstream_ip_pool = 0;
    server->upstream_wan_mode = 0; server->upstream_wan_count = 0;
    memset(server->upstream_wan_interfaces, 0, sizeof(server->upstream_wan_interfaces));
	server->pool_compat_skip = 0;
	server->max_upstream_backends = 0;
	server->pool_ip_count = 0;
	memset(server->pool_ips, 0, sizeof(server->pool_ips));

	if (parse_uri(ip, scheme, server->server, &port, server->path) != 0) {
		return -1;
	}
	safe_strncpy(server->authority, server->server, sizeof(server->authority));

	if (scheme[0] != '\0') {
		if (strcasecmp(scheme, "https") == 0) {
			type = DNS_SERVER_HTTPS;
			default_port = DEFAULT_DNS_HTTPS_PORT;
		} else if (strcasecmp(scheme, "http3") == 0) {
			type = DNS_SERVER_HTTP3;
			default_port = DEFAULT_DNS_HTTPS_PORT;
		} else if (strcasecmp(scheme, "h3") == 0) {
			type = DNS_SERVER_HTTP3;
			default_port = DEFAULT_DNS_HTTPS_PORT;
		} else if (strcasecmp(scheme, "quic") == 0) {
			type = DNS_SERVER_QUIC;
			default_port = DEFAULT_DNS_QUIC_PORT;
		} else if (strcasecmp(scheme, "tls") == 0) {
			type = DNS_SERVER_TLS;
			default_port = DEFAULT_DNS_TLS_PORT;
		} else if (strcasecmp(scheme, "tcp") == 0) {
			type = DNS_SERVER_TCP;
			default_port = DEFAULT_DNS_PORT;
		} else if (strcasecmp(scheme, "udp") == 0) {
			type = DNS_SERVER_UDP;
			default_port = DEFAULT_DNS_PORT;
		} else {
			tlog(TLOG_ERROR, "invalid scheme: %s", scheme);
			return -1;
		}
	}

	if (dns_is_quic_supported() == 0) {
		if (type == DNS_SERVER_QUIC || type == DNS_SERVER_HTTP3) {
			tlog(TLOG_ERROR, "QUIC/HTTP3 is not supported in this version.");
			tlog(TLOG_ERROR, "Please install the latest release with QUIC/HTTP3 support.");
			return -1;
		}
	}

	/* if port is not defined, set port to default 53 */
	if (port == PORT_NOT_DEFINED) {
		port = default_port;
	}

	/* get current group */
	if (_config_current_group()) {
		group_name = _config_current_group()->group_name;
	}

	/* if server is defined in a group, exclude from default group */
	if (group_name && group_name[0] != '\0') {
		server_flag |= SERVER_FLAG_EXCLUDE_DEFAULT;
	}

	/* process extra options */
	optind = 1;
	optind_last = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "D:kg:p:eb", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'D': {
			drop_packet_latency_ms = atoi(optarg);
			break;
		}
		case 'e': {
			server_flag |= SERVER_FLAG_EXCLUDE_DEFAULT;
			break;
		}
		case 'g': {
			/* first group, add later */
			if (group_name == NULL) {
				group_name = optarg;
				break;
			}

			if (_dns_conf_get_group_set(optarg, server) != 0) {
				tlog(TLOG_ERROR, "add group failed.");
				goto errout;
			}
			break;
		}
		case 'p': {
			if (_dns_conf_get_proxy_name(optarg) == NULL) {
				tlog(TLOG_ERROR, "add proxy server failed.");
				goto errout;
			}
			safe_strncpy(server->proxyname, optarg, PROXY_NAME_LEN);
			break;
		}

		case 'k': {
			server->skip_check_cert = 1;
			no_tls_host_verify = 1;
			break;
		}
		case 'b': {
			is_bootstrap_dns = 1;
			break;
		}
		case 250: {
			safe_strncpy(server->ifname, optarg, MAX_INTERFACE_LEN);
			break;
		}
		case 251: {
			result_flag |= DNSSERVER_FLAG_CHECK_EDNS;
			break;
		}
		case 252: {
			result_flag |= DNSSERVER_FLAG_WHITELIST_IP;
			break;
		}
		case 253: {
			result_flag |= DNSSERVER_FLAG_BLACKLIST_IP;
			break;
		}
		case 254: {
			server->set_mark = atoll(optarg);
			break;
		}
		case 256: {
			_conf_client_subnet(optarg, &server->ipv4_ecs, &server->ipv6_ecs);
			break;
		}
		case 257: {
			server_flag |= SERVER_FLAG_HITCHHIKING;
			break;
		}
		case 258: {
			host_ip = optarg;
			host_ip_occurrences++;
			if (check_is_ipaddr(optarg) != 0) legacy_host_ip_invalid = 1;
			break;
		}
		case 259: {
			safe_strncpy(server->spki, optarg, DNS_MAX_SPKI_LEN);
			break;
		}
		case 260: {
			safe_strncpy(server->hostname, optarg, DNS_MAX_CNAME_LEN);
			if (strncmp(server->hostname, "-", 2) == 0) {
				server->hostname[0] = '\0';
				no_tls_host_name = 1;
			}
			break;
		}
		case 261: {
			safe_strncpy(server->httphost, optarg, DNS_MAX_CNAME_LEN);
			break;
		}
		case 262: {
			safe_strncpy(server->tls_host_verify, optarg, DNS_MAX_CNAME_LEN);
			if (strncmp(server->tls_host_verify, "-", 2) == 0) {
				server->tls_host_verify[0] = '\0';
				no_tls_host_verify = 1;
			}
			break;
		}
		case 263: {
			server->tcp_keepalive = atoi(optarg);
			break;
		}
		case 264: {
			server->subnet_all_query_types = 1;
			break;
		}
		case 265: {
			server->fallback = 1;
			break;
		}
        case 276:
            if (path_options_seen & 1) return -1;
            path_options_seen |= 1;
            if (!strcmp(optarg, "dual")) server->upstream_family = 0;
            else if (!strcmp(optarg, "ipv4")) server->upstream_family = 4;
            else if (!strcmp(optarg, "ipv6")) server->upstream_family = 6;
            else return -1;
            break;
        case 277: case 278: case 279: case 280: case 281: {
            unsigned bit = 1U << (opt - 275);
            if (path_options_seen & bit) return -1;
            path_options_seen |= bit;
            if (!*optarg) return -1;
            for (const char *p = optarg; *p; p++) if (*p < '0' || *p > '9') return -1;
            errno = 0; char *end = NULL; unsigned long v = strtoul(optarg, &end, 10);
            unsigned max = opt == 278 ? 60000 : opt == 281 ? 600000 : opt == 280 ? 2000 : 10000;
            unsigned min = opt == 280 || opt == 281 ? 0 : 50;
            if (errno || *end || v < min || v > max || (opt == 281 && v && v < 1000)) return -1;
            if (opt == 277) server->upstream_response_timeout_ms = v;
            if (opt == 278) server->upstream_query_timeout_ms = v;
            if (opt == 279) server->upstream_connect_timeout_ms = v;
            if (opt == 280) server->upstream_connect_delay_ms = v + 1; /* zero is an explicit immediate race */
            if (opt == 281) { server->upstream_keepalive_ms = v; server->upstream_keepalive_disabled = !v; }
            break;
        }
		case 275: case 285: {
            if (!*optarg) return -1;
            for (const char *digit = optarg; *digit; digit++) if (*digit < '0' || *digit > '9') return -1;
            char *end = NULL;
            errno = 0;
            unsigned long value = strtoul(optarg, &end, 10);
            if (errno || *end || value < 1 || value > 10000) return -1;
            if (opt == 275) server->upstream_cooldown_ms = value;
            else server->upstream_retry_cooldown_ms = value;
            break;
        }
        case 282:
            if (wan_option_seen & 1) return -1;
            wan_option_seen |= 1;
            if (!strcmp(optarg, "inherit")) server->upstream_wan_mode = 0;
            else if (!strcmp(optarg, "off")) server->upstream_wan_mode = 1;
            else if (!strcmp(optarg, "custom")) server->upstream_wan_mode = 2;
            else {
                if (wan_option_seen & 2) return -1;
                wan_option_seen |= 2;
                char *args[] = {"upstream-wan-interfaces", optarg};
                if (_config_upstream_wan_interfaces(server, 2, args)) return -1;
                server->upstream_wan_mode = 2;
            }
            break;
        case 284: {
            if (wan_option_seen & 2) return -1;
            wan_option_seen |= 2;
            char *args[] = {"upstream-wan-interfaces", optarg};
            if (_config_upstream_wan_interfaces(server, 2, args)) return -1;
            break;
        }
        case 283:
            if (wan_option_seen & 4) return -1;
            wan_option_seen |= 4;
            if (!strcmp(optarg, "on")) { server->adaptive_query_rate = 1; server->query_rate_disabled = 0; }
            else if (!strcmp(optarg, "off")) { server->adaptive_query_rate = 0; server->query_rate_disabled = 1; }
            else return -1;
            break;
        case 286:
            server->upstream_service = 1;
            server->upstream_ip_pool = 1;
            break;
		case 267:
		case 268:
		case 269: {
            for (const char *digit = optarg; *digit; digit++) if (*digit < '0' || *digit > '9') return -1;
			char *end = NULL;
            errno = 0;
			unsigned long value = strtoul(optarg, &end, 10);
			if (errno || !*optarg || *optarg == '-' || *end || value > (opt == 267 ? 1000000UL : 65535UL) || (opt == 268 && value == 0)) return -1;
			if (opt == 267) { server->max_query_rate = value; rate_cap_seen = 1; }
			else if (opt == 268) server->query_burst = value;
			else server->max_concurrent_queries = value;
			break;
		}
		case 271:
			server->upstream_round_robin = 1;
			break;
		case 272:
			if (_config_pool_number(optarg, &server->max_upstream_connections)) return -1;
			connection_limit_text = optarg;
			if (optarg[0] < '1' || optarg[0] > '4' || optarg[1]) legacy_connection_invalid = 1;
			break;
		case 273:
			server->upstream_ip_pool = 1;
			break;
		case 274:
			if (_config_pool_number(optarg, &server->max_upstream_backends)) return -1;
			break;
		case 270:
			if (!*optarg || strlen(optarg) >= sizeof(server->quota_group)) return -1;
			safe_strncpy(server->quota_group, optarg, sizeof(server->quota_group));
			break;
		case 266: {
			safe_strncpy(server->alpn, optarg, DNS_MAX_ALPN_LEN);
			break;
		}
		default:
			/* Do not silently turn malformed opt-in options into defaults. */
			if ((optopt >= 275 && optopt <= 286) || optopt == 271 || optopt == 272 || optopt == 273 || optopt == 274 || optopt == 258) return -1;
			if (optind > optind_last) {
				tlog(TLOG_WARN, "unknown server option: %s at '%s:%d'.", argv[optind - 1], conf_get_conf_file(),
					 conf_get_current_lineno());
			}
			break;
		}

		optind_last = optind;
	}

    server->upstream_path_options = path_options_seen;
	if (server->upstream_ip_pool) {
		if (server->upstream_round_robin || is_bootstrap_dns || (server->proxyname[0] && !server->upstream_service) ||
			type == DNS_SERVER_MDNS || host_ip_occurrences > 1) {
			tlog(TLOG_ERROR, "upstream-ip-pool requires a domain authority and cannot use proxy, bootstrap, mDNS or legacy RR");
			return -1;
		}
		if (!server->max_upstream_backends) server->max_upstream_backends = 4;
		if (server->max_upstream_connections > server->max_upstream_backends) return -1;
		if (host_ip && _config_pool_ips(server, host_ip)) return -1;
		if (server->pool_ip_count > server->max_upstream_backends)
			tlog(TLOG_WARN, "service %s configured %u destination candidates; healthy connections are reused and candidates retained for failover",
				server->server, server->pool_ip_count);
	} else {
        /* Global inheritance may appear after this line. Resolve logical
         * service ownership and path-only validation after the full parse. */
		if (server->max_upstream_backends || legacy_host_ip_invalid || legacy_connection_invalid) return -1;
		/* Preserve the legacy single-digit 1..4 grammar, including rejection of 01. */
		if (connection_limit_text && (connection_limit_text[0] < '1' || connection_limit_text[0] > '4' ||
			connection_limit_text[1] != '\0')) return -1;
		if (server->upstream_round_robin) {
			if (!server->quota_group[0]) return -1;
			if (!server->max_upstream_connections) server->max_upstream_connections = 2;
		} else if (server->max_upstream_connections) return -1;
	}
    if (server->query_rate_disabled) server->max_query_rate = server->query_burst = 0;
    if (server->adaptive_query_rate) {
        if (is_bootstrap_dns || (type != DNS_SERVER_HTTPS && type != DNS_SERVER_TLS &&
            type != DNS_SERVER_QUIC && type != DNS_SERVER_HTTP3)) {
            tlog(TLOG_ERROR, "adaptive-query-rate requires non-bootstrap DoH, DoT, DoQ or DoH3");
            return -1;
        }
        if (rate_cap_seen && !server->max_query_rate) return -1;
        if (!server->max_query_rate) server->max_query_rate = 20;
        if (server->query_burst > 1) return -1;
    }
	if (server->query_burst && !server->max_query_rate) return -1;
    if (!server->upstream_retry_cooldown_ms) {
        server->upstream_retry_cooldown_ms = 1000;
    }
	if (!server->upstream_cooldown_ms) server->upstream_cooldown_ms = 200;
	if (server->max_query_rate && !server->query_burst) server->query_burst = 1;
	if (server->quota_group[0]) {
		for (int n = 0; n < index; n++) {
			struct dns_servers *other = &dns_conf.servers[n];
			if (strcmp(other->quota_group, server->quota_group) == 0 &&
				(other->max_query_rate != server->max_query_rate || other->query_burst != server->query_burst ||
                 other->adaptive_query_rate != server->adaptive_query_rate ||
                 other->upstream_cooldown_ms != server->upstream_cooldown_ms ||
				 other->upstream_round_robin != server->upstream_round_robin ||
				 (server->upstream_round_robin && other->max_upstream_connections != server->max_upstream_connections))) {
				tlog(TLOG_ERROR, "conflicting rate/burst/round-robin/connection limit for quota group %s", server->quota_group);
				return -1;
			}
		}
	}

	if (check_is_ipaddr(server->server) != 0) {
		/* if server is domain name, then verify domain */
		if (server->tls_host_verify[0] == '\0' && no_tls_host_verify == 0) {
			safe_strncpy(server->tls_host_verify, server->server, DNS_MAX_CNAME_LEN);
		}

		if (server->hostname[0] == '\0' && no_tls_host_name == 0) {
			safe_strncpy(server->hostname, server->server, DNS_MAX_CNAME_LEN);
		}

		if (server->httphost[0] == '\0') {
			safe_strncpy(server->httphost, server->server, DNS_MAX_CNAME_LEN);
		}

		if (host_ip && !server->upstream_ip_pool) {
			safe_strncpy(server->server, host_ip, DNS_MAX_IPLEN);
		}
	}

	/* if server is domain name, then verify domain */
	if (server->tls_host_verify[0] == '\0' && server->hostname[0] != '\0' && no_tls_host_verify == 0) {
		safe_strncpy(server->tls_host_verify, server->hostname, DNS_MAX_CNAME_LEN);
	}

	/* add new server */
	server->type = type;
	server->port = port;
	server->result_flag = result_flag;
	server->server_flag = server_flag;
	server->ttl = ttl;
	server->drop_packet_latency_ms = drop_packet_latency_ms;

	if (server->type == DNS_SERVER_HTTPS || server->type == DNS_SERVER_HTTP3) {
		if (server->path[0] == 0) {
			safe_strncpy(server->path, "/", sizeof(server->path));
		}

		if (server->httphost[0] == '\0') {
			set_http_host(server->server, server->port, DEFAULT_DNS_HTTPS_PORT, server->httphost);
		}
	}

	if (group_name) {
		if (_dns_conf_get_group_set(group_name, server) != 0) {
			tlog(TLOG_ERROR, "add group failed.");
			goto errout;
		}
	}

	dns_conf.server_num++;
	tlog(TLOG_DEBUG, "add server %s, flag: %X, ttl: %d", ip, result_flag, ttl);

	if (is_bootstrap_dns) {
		server->server_flag |= SERVER_FLAG_EXCLUDE_DEFAULT;
		_dns_conf_get_group_set("bootstrap-dns", server);
		dns_conf_exist_bootstrap_dns = 1;
	}

	return 0;

errout:
	if (spki) {
		free(spki);
	}

	return -1;
}

int _config_server_udp(void *data, int argc, char *argv[])
{
	return _config_server(argc, argv, DNS_SERVER_UDP, DEFAULT_DNS_PORT);
}

int _config_server_tcp(void *data, int argc, char *argv[])
{
	return _config_server(argc, argv, DNS_SERVER_TCP, DEFAULT_DNS_PORT);
}

int _config_server_tls(void *data, int argc, char *argv[])
{
	return _config_server(argc, argv, DNS_SERVER_TLS, DEFAULT_DNS_TLS_PORT);
}

int _config_server_https(void *data, int argc, char *argv[])
{
	int ret = 0;
	ret = _config_server(argc, argv, DNS_SERVER_HTTPS, DEFAULT_DNS_HTTPS_PORT);

	return ret;
}

int _config_server_quic(void *data, int argc, char *argv[])
{
	int ret = 0;
	ret = _config_server(argc, argv, DNS_SERVER_QUIC, DEFAULT_DNS_QUIC_PORT);

	return ret;
}

int _config_server_http3(void *data, int argc, char *argv[])
{
	int ret = 0;
	ret = _config_server(argc, argv, DNS_SERVER_HTTP3, DEFAULT_DNS_HTTPS_PORT);

	return ret;
}
