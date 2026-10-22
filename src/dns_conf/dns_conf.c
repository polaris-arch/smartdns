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

#include "smartdns/dns_conf.h"
#include "smartdns/lib/idna.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"

#include "address.h"
#include "any.h"
#include "bind.h"
#include "bootstrap_dns.h"
#include "client_rule.h"
#include "client_subnet.h"
#include "cname.h"
#include "conf_file.h"
#include "ddns_domain.h"
#include "dhcp_lease_dnsmasq.h"
#include "dns64.h"
#include "dns_conf_group.h"
#include "domain_rule.h"
#include "domain_set.h"
#include "group.h"
#include "host_file.h"
#include "https_record.h"
#include "ip_alias.h"
#include "ip_rule.h"
#include "ip_set.h"
#include "ipset.h"
#include "local_domain.h"
#include "nameserver.h"
#include "nftset.h"
#include "plugin.h"
#include "proxy_names.h"
#include "proxy_server.h"
#include "ptr.h"
#include "qtype_soa.h"
#include "server.h"
#include "server_group.h"
#include "smartdns_domain.h"
#include "speed_check_mode.h"
#include "srv_record.h"
#include "txt_record.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

static struct config_enum_list dns_conf_response_mode_enum[] = {
	{"first-ping", DNS_RESPONSE_MODE_FIRST_PING_IP},
	{"fastest-ip", DNS_RESPONSE_MODE_FASTEST_IP},
	{"fastest-response", DNS_RESPONSE_MODE_FASTEST_RESPONSE},
	{NULL, 0}};

struct dns_config dns_conf;

struct config_enum_list *response_mode_list(void)
{
	return dns_conf_response_mode_enum;
}

static int _config_option_parser_filepath(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		return -1;
	}

	conf_get_conf_fullpath(argv[1], data, DNS_MAX_PATH);

	return 0;
}

static int _config_bind_cert_san(void *data, int argc, char *argv[])
{
	char *san = data;
	size_t san_len = 0;
	int i = 0;

	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		return -1;
	}

	for (i = 1; i < argc; i++) {
		unsigned char addr[16] = {0};
		const char *prefix = "DNS:";
		const char *value = argv[i];
		int len = 0;

		if (strncasecmp(value, "DNS:", 4) == 0 || strncasecmp(value, "IP:", 3) == 0) {
			prefix = "";
		} else if (inet_pton(AF_INET, value, addr) == 1 || inet_pton(AF_INET6, value, addr) == 1) {
			prefix = "IP:";
		}

		len = snprintf(san + san_len, DNS_MAX_PATH - san_len, "%s%s%s", san_len > 0 ? "," : "", prefix, value);
		if (len < 0 || (size_t)len >= DNS_MAX_PATH - san_len) {
			return -1;
		}
		san_len += len;
	}

	return 0;
}

static int _config_log_level(void *data, int argc, char *argv[])
{
	/* read log level and set */
	char *value = argv[1];

	if (strncasecmp("debug", value, MAX_LINE_LEN) == 0) {
		dns_conf.log_level = TLOG_DEBUG;
	} else if (strncasecmp("info", value, MAX_LINE_LEN) == 0) {
		dns_conf.log_level = TLOG_INFO;
	} else if (strncasecmp("notice", value, MAX_LINE_LEN) == 0) {
		dns_conf.log_level = TLOG_NOTICE;
	} else if (strncasecmp("warn", value, MAX_LINE_LEN) == 0) {
		dns_conf.log_level = TLOG_WARN;
	} else if (strncasecmp("error", value, MAX_LINE_LEN) == 0) {
		dns_conf.log_level = TLOG_ERROR;
	} else if (strncasecmp("fatal", value, MAX_LINE_LEN) == 0) {
		dns_conf.log_level = TLOG_FATAL;
	} else if (strncasecmp("off", value, MAX_LINE_LEN) == 0) {
		dns_conf.log_level = TLOG_OFF;
	} else {
		return -1;
	}

	return 0;
}

static int _dns_conf_setup_mdns(void)
{
	if (dns_conf.mdns_lookup != 1) {
		return 0;
	}

	return _conf_domain_rule_nameserver(DNS_SERVER_GROUP_LOCAL, DNS_SERVER_GROUP_MDNS);
}

static int _config_server_name(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		return -1;
	}

	utf8_to_punycode(argv[1], strlen(argv[1]), dns_conf.server_name, DNS_MAX_SERVER_NAME_LEN);

	return 0;
}

static struct config_item _config_item[] = {
	CONF_CUSTOM("any-response-mode", _config_any_mode, NULL),
	CONF_CUSTOM("any-aggregate-types", _config_any_types, NULL),
	CONF_CUSTOM("any-aggregate-concurrency", _config_any_number, group_member(any.concurrency)),
	CONF_CUSTOM("any-aggregate-max-attempts", _config_any_number, group_member(any.max_attempts)),
	CONF_CUSTOM("any-aggregate-timeout-ms", _config_any_number, group_member(any.timeout_ms)),
	CONF_CUSTOM("any-aggregate-partial", _config_any_partial, NULL),
	CONF_CUSTOM("server-name", _config_server_name, NULL),
	CONF_YESNO("resolv-hostname", &dns_conf.resolv_hostname),
	CONF_CUSTOM("bind", _config_bind_ip_udp, NULL),
	CONF_CUSTOM("bind-tcp", _config_bind_ip_tcp, NULL),
	CONF_CUSTOM("bind-tls", _config_bind_ip_tls, NULL),
	CONF_CUSTOM("bind-https", _config_bind_ip_https, NULL),
	CONF_CUSTOM("bind-http", _config_bind_ip_http, NULL),
	CONF_CUSTOM("bind-cert-root-key-file", _config_option_parser_filepath, &dns_conf.bind_root_ca_key_file),
	CONF_YESNOAUTO("bind-cert-generate", &dns_conf.bind_cert_generate),
	CONF_CUSTOM("bind-cert-san", _config_bind_cert_san, dns_conf.bind_cert_san),
	CONF_INT("bind-cert-validity-days", &dns_conf.bind_ca_validity_days, 0, 9999),
	CONF_CUSTOM("bind-cert-file", _config_option_parser_filepath, &dns_conf.bind_ca_file),
	CONF_CUSTOM("bind-cert-key-file", _config_option_parser_filepath, &dns_conf.bind_ca_key_file),
	CONF_STRING("bind-cert-key-pass", dns_conf.bind_ca_key_pass, DNS_MAX_PATH),
	CONF_CUSTOM("server", _config_server_udp, NULL),
	CONF_CUSTOM("server-tcp", _config_server_tcp, NULL),
	CONF_CUSTOM("server-tls", _config_server_tls, NULL),
	CONF_CUSTOM("server-https", _config_server_https, NULL),
	CONF_CUSTOM("server-h3", _config_server_http3, NULL),
	CONF_CUSTOM("server-http3", _config_server_http3, NULL),
	CONF_CUSTOM("server-quic", _config_server_quic, NULL),
	CONF_YESNO("mdns-lookup", &dns_conf.mdns_lookup),
	CONF_YESNO("local-ptr-enable", &dns_conf.local_ptr_enable),
	CONF_CUSTOM("nameserver", _config_nameserver, NULL),
	CONF_YESNO("expand-ptr-from-address", &dns_conf.expand_ptr_from_address),
	CONF_CUSTOM("address", _config_address, NULL),
	CONF_CUSTOM("cname", _config_cname, NULL),
	CONF_CUSTOM("srv-record", _config_srv_record, NULL),
	CONF_CUSTOM("https-record", _config_https_record, NULL),
	CONF_CUSTOM("txt-record", _config_txt_record, NULL),
	CONF_CUSTOM("proxy-server", _config_proxy_server, NULL),
	CONF_YESNO_FUNC("ipset-timeout", _dns_conf_group_yesno, group_member(ipset_nftset.ipset_timeout_enable)),
	CONF_CUSTOM("ipset", _config_ipset, NULL),
	CONF_CUSTOM("ipset-no-speed", _config_ipset_no_speed, NULL),
	CONF_YESNO_FUNC("nftset-timeout", _dns_conf_group_yesno, group_member(ipset_nftset.nftset_timeout_enable)),
	CONF_YESNO("nftset-debug", &dns_conf.nftset_debug_enable),
	CONF_CUSTOM("nftset", _config_nftset, NULL),
	CONF_CUSTOM("nftset-no-speed", _config_nftset_no_speed, NULL),
	CONF_CUSTOM("speed-check-mode", _config_speed_check_mode, NULL),
	CONF_INT("tcp-idle-time", &dns_conf.tcp_idle_time, 0, 3600),
	CONF_SSIZE("cache-size", &dns_conf.cachesize, -1, CONF_INT_MAX),
	CONF_SSIZE("cache-mem-size", &dns_conf.cache_max_memsize, 0, CONF_INT_MAX),
	CONF_CUSTOM("cache-file", _config_option_parser_filepath, (char *)&dns_conf.cache_file),
	CONF_CUSTOM("data-dir", _config_option_parser_filepath, (char *)&dns_conf.data_dir),
	CONF_YESNO("cache-persist", &dns_conf.cache_persist),
	CONF_INT("cache-checkpoint-time", &dns_conf.cache_checkpoint_time, 0, 3600 * 24 * 7),
	CONF_YESNO_FUNC("prefetch-domain", _dns_conf_group_yesno, group_member(dns_prefetch)),
	CONF_YESNO_FUNC("serve-expired", _dns_conf_group_yesno, group_member(dns_serve_expired)),
	CONF_INT_FUNC("serve-expired-ttl", _dns_conf_group_int, group_member(dns_serve_expired_ttl), 0, CONF_INT_MAX),
	CONF_INT_FUNC("serve-expired-reply-ttl", _dns_conf_group_int, group_member(dns_serve_expired_reply_ttl), 0,
				  CONF_INT_MAX),
	CONF_INT_FUNC("serve-expired-prefetch-time", _dns_conf_group_int, group_member(dns_serve_expired_prefetch_time), 0,
				  CONF_INT_MAX),
	CONF_YESNO_FUNC("dualstack-ip-selection", _dns_conf_group_yesno, group_member(dualstack_ip_selection)),
	CONF_YESNO_FUNC("dualstack-ip-allow-force-AAAA", _dns_conf_group_yesno,
					group_member(dns_dualstack_ip_allow_force_AAAA)),
	CONF_INT_FUNC("dualstack-ip-selection-threshold", _dns_conf_group_int,
				  group_member(dns_dualstack_ip_selection_threshold), 0, 1000),
	CONF_CUSTOM("dns64", _config_dns64, NULL),
	CONF_CUSTOM("log-level", _config_log_level, NULL),
	CONF_CUSTOM("log-file", _config_option_parser_filepath, (char *)dns_conf.log_file),
	CONF_SIZE("log-size", &dns_conf.log_size, 0, 1024 * 1024 * 1024),
	CONF_INT("log-num", &dns_conf.log_num, 0, 1024),
	CONF_YESNO("log-color", &dns_conf.log_color_mode),
	CONF_YESNO("log-console", &dns_conf.log_console),
	CONF_YESNO("log-syslog", &dns_conf.log_syslog),
	CONF_INT_BASE("log-file-mode", &dns_conf.log_file_mode, 0, 511, 8),
	CONF_YESNO("audit-enable", &dns_conf.audit_enable),
	CONF_YESNO("audit-SOA", &dns_conf.audit_log_SOA),
	CONF_CUSTOM("audit-file", _config_option_parser_filepath, (char *)&dns_conf.audit_file),
	CONF_INT_BASE("audit-file-mode", &dns_conf.audit_file_mode, 0, 511, 8),
	CONF_SIZE("audit-size", &dns_conf.audit_size, 0, 1024 * 1024 * 1024),
	CONF_INT("audit-num", &dns_conf.audit_num, 0, 1024),
	CONF_YESNO("audit-console", &dns_conf.audit_console),
	CONF_YESNO("audit-syslog", &dns_conf.audit_syslog),
	CONF_YESNO("acl-enable", &dns_conf.acl_enable),
	CONF_INT_FUNC("rr-ttl", _dns_conf_group_int, group_member(dns_rr_ttl), 0, CONF_INT_MAX),
	CONF_INT_FUNC("rr-ttl-min", _dns_conf_group_int, group_member(dns_rr_ttl_min), 0, CONF_INT_MAX),
	CONF_INT_FUNC("rr-ttl-max", _dns_conf_group_int, group_member(dns_rr_ttl_max), 0, CONF_INT_MAX),
	CONF_INT_FUNC("rr-ttl-reply-max", _dns_conf_group_int, group_member(dns_rr_ttl_reply_max), 0, CONF_INT_MAX),
	CONF_INT_FUNC("local-ttl", _dns_conf_group_int, group_member(dns_local_ttl), 0, CONF_INT_MAX),
	CONF_INT_FUNC("max-reply-ip-num", _dns_conf_group_int, group_member(dns_max_reply_ip_num), 1, CONF_INT_MAX),
	CONF_INT("max-query-limit", &dns_conf.max_query_limit, 0, CONF_INT_MAX),
	CONF_ENUM_FUNC("response-mode", _dns_conf_group_enum, group_member(dns_response_mode),
				   &dns_conf_response_mode_enum),
	CONF_YESNO_FUNC("force-AAAA-SOA", _dns_conf_group_yesno, group_member(force_AAAA_SOA)),
	CONF_YESNO_FUNC("force-no-CNAME", _dns_conf_group_yesno, group_member(dns_force_no_cname)),
	CONF_CUSTOM("force-qtype-SOA", _config_qtype_soa, NULL),
	CONF_CUSTOM("blacklist-ip", _config_blacklist_ip, NULL),
	CONF_CUSTOM("whitelist-ip", _config_whitelist_ip, NULL),
	CONF_CUSTOM("ip-alias", _config_ip_alias, NULL),
	CONF_CUSTOM("ip-rules", _config_ip_rules, NULL),
	CONF_CUSTOM("ip-set", _config_ip_set, NULL),
	CONF_CUSTOM("bogus-nxdomain", _config_bogus_nxdomain, NULL),
	CONF_CUSTOM("ignore-ip", _config_ip_ignore, NULL),
	CONF_CUSTOM("edns-client-subnet", _conf_edns_client_subnet, NULL),
	CONF_CUSTOM("domain-rules", _config_domain_rules, NULL),
	CONF_CUSTOM("domain-set", _config_domain_set, NULL),
	CONF_CUSTOM("ddns-domain", _config_ddns_domain, NULL),
	CONF_CUSTOM("local-domain", _config_local_domain, NULL),
	CONF_CUSTOM("dnsmasq-lease-file", _conf_dhcp_lease_dnsmasq_file, NULL),
	CONF_CUSTOM("odhcpd-lease-file", _conf_dhcp_lease_odhcpd_file, NULL),
	CONF_CUSTOM("hosts-file", _config_hosts_file, NULL),
	CONF_CUSTOM("group-begin", _config_group_begin, NULL),
	CONF_CUSTOM("group-end", _config_group_end, NULL),
	CONF_CUSTOM("group-match", _config_group_match, NULL),
	CONF_CUSTOM("client-rules", _config_client_rules, NULL),
	CONF_STRING("ca-file", (char *)&dns_conf.ca_file, DNS_MAX_PATH),
	CONF_STRING("ca-path", (char *)&dns_conf.ca_path, DNS_MAX_PATH),
	CONF_STRING("user", (char *)&dns_conf.user, sizeof(dns_conf.user)),
	CONF_YESNO("debug-save-fail-packet", &dns_conf.dns_save_fail_packet),
	CONF_YESNO("no-pidfile", &dns_conf.dns_no_pidfile),
	CONF_YESNO("no-daemon", &dns_conf.dns_no_daemon),
	CONF_YESNO("restart-on-crash", &dns_conf.dns_restart_on_crash),
	CONF_SIZE("socket-buff-size", &dns_conf.dns_socket_buff_size, 0, 1024 * 1024 * 8),
	CONF_CUSTOM("plugin", _config_plugin, NULL),
	CONF_STRING("resolv-file", (char *)&dns_conf.dns_resolv_file, sizeof(dns_conf.dns_resolv_file)),
	CONF_STRING("debug-save-fail-packet-dir", (char *)&dns_conf.dns_save_fail_packet_dir,
				sizeof(dns_conf.dns_save_fail_packet_dir)),
	CONF_CUSTOM("conf-file", config_additional_file, NULL),
	CONF_END(),
};

const struct config_item *smartdns_config_item(void)
{
	return _config_item;
}

static int _conf_value_handler(const char *key, const char *value)
{
	if (strstr(key, ".") == NULL) {
		return -1;
	}

#ifdef BUILD_STATIC
	return -1;
#endif

	return _config_plugin_conf_add(key, value);
}

int _conf_printf(const char *key, const char *value, const char *file, int lineno, int ret)
{
	switch (ret) {
	case CONF_RET_ERR:
	case CONF_RET_WARN:
	case CONF_RET_BADCONF:
		tlog(TLOG_WARN, "process config failed at '%s:%d'.", file, lineno);
		return -1;
		break;
	case CONF_RET_NOENT:
		if (_conf_value_handler(key, value) == 0) {
			return 0;
		}

		tlog(TLOG_WARN, "unsupported config at '%s:%d'.", file, lineno);
		return 0;
		break;
	default:
		break;
	}

	return 0;
}

const char *dns_conf_get_cache_dir(void)
{
	if (dns_conf.cache_file[0] == '\0') {
		return SMARTDNS_CACHE_FILE;
	}

	return dns_conf.cache_file;
}

const char *dns_conf_get_data_dir(void)
{
	if (dns_conf.data_dir[0] == '\0') {
		return SMARTDNS_DATA_DIR;
	}

	return dns_conf.data_dir;
}

static int _dns_server_load_conf_init(void)
{
	dns_conf.client_rule.rule = New_Radix();
	if (dns_conf.client_rule.rule == NULL) {
		tlog(TLOG_WARN, "init client rule radix tree failed.");
		return -1;
	}
	hash_init(dns_conf.client_rule.mac);

	conf_file_table_init();
	_config_rule_group_init();
	_config_ipset_init();
	_config_group_table_init();
	_config_host_table_init();
	_config_ptr_table_init();
	_config_domain_set_name_table_init();
	_config_ip_set_name_table_init();
	_config_plugin_table_init();

	if (_config_current_group_push_default() != 0) {
		tlog(TLOG_ERROR, "init default group failed.");
		return -1;
	}

	return 0;
}

void dns_server_load_exit(void)
{
	_config_rule_group_destroy();
	_config_client_rule_destroy();
	_config_ipset_table_destroy();
	_config_nftset_table_destroy();
	_config_group_table_destroy();
	_config_ptr_table_destroy(0);
	_config_host_table_destroy(0);
	_config_proxy_table_destroy();
	_config_plugin_table_destroy();
	_config_plugin_table_conf_destroy();

	dns_conf.server_num = 0;
	dns_server_bind_destroy();

	if (dns_conf.log_syslog == 1 || dns_conf.audit_syslog == 1) {
		closelog();
	}

	memset(&dns_conf, 0, sizeof(dns_conf));
}

static void _dns_conf_default_value_init(void)
{
	DOMAIN_CHECK_TYPE tcp_check_type = DOMAIN_CHECK_TCP;
	if (dns_has_raw_cap) {
		/* use tcp-syn as default if have raw socket capability */
		tcp_check_type = DOMAIN_CHECK_TCP_SYN;
	}

	dns_conf.max_query_limit = DNS_MAX_QUERY_LIMIT;
	dns_conf.tcp_idle_time = 120;
	dns_conf.local_ptr_enable = 1;
	dns_conf.audit_size = 1024 * 1024;
	dns_conf.cache_checkpoint_time = DNS_DEFAULT_CHECKPOINT_TIME;
	dns_conf.cache_persist = 2;
	dns_conf.log_num = 8;
	dns_conf.log_size = 1024 * 128;
	dns_conf.log_level = TLOG_ERROR;
	dns_conf.log_color_mode = 1;
	dns_conf.audit_num = 2;
	dns_conf.audit_file_mode = 0640;
	dns_conf.audit_size = 1024 * 128;
	dns_conf.resolv_hostname = 1;
	dns_conf.cachesize = -1;
	dns_conf.cache_max_memsize = -1;
	dns_conf.bind_cert_generate = -1;

	dns_conf.default_check_orders.orders[0].type = DOMAIN_CHECK_ICMP;
	dns_conf.default_check_orders.orders[0].tcp_port = 0;
	dns_conf.default_check_orders.orders[1].type = tcp_check_type;
	dns_conf.default_check_orders.orders[1].tcp_port = 80;
	dns_conf.default_check_orders.orders[2].type = tcp_check_type;
	dns_conf.default_check_orders.orders[2].tcp_port = 443;
	dns_conf.default_response_mode = DNS_RESPONSE_MODE_FIRST_PING_IP;
}

static int _dns_conf_load_pre(void)
{
	_dns_conf_default_value_init();

	if (_dns_server_load_conf_init() != 0) {
		goto errout;
	}

	_dns_ping_cap_check();

	safe_strncpy(dns_conf.dns_save_fail_packet_dir, SMARTDNS_DEBUG_DIR, sizeof(dns_conf.dns_save_fail_packet_dir));

	return 0;

errout:
	return -1;
}

static void _dns_conf_auto_set_cache_size(void)
{
	uint64_t memsize = get_system_mem_size();
	if (dns_conf.cachesize >= 0) {
		return;
	}

	if (memsize <= 16 * 1024 * 1024) {
		dns_conf.cachesize = 4096; /* 2MB memory */
	} else if (memsize <= 32 * 1024 * 1024) {
		dns_conf.cachesize = 16384; /* 8MB memory*/
	} else if (memsize <= 64 * 1024 * 1024) {
		dns_conf.cachesize = 32768; /* 16MB memory*/
	} else if (memsize <= 128 * 1024 * 1024) {
		dns_conf.cachesize = 65536; /* 32MB memory*/
	} else if (memsize <= 256 * 1024 * 1024) {
		dns_conf.cachesize = 131072; /* 64MB memory*/
	} else if (memsize <= 512LL * 1024 * 1024) {
		dns_conf.cachesize = 196608; /* 96MB memory*/
	} else if (memsize <= 1024LL * 1024 * 1024) {
		dns_conf.cachesize = 262144; /* 128MB memory*/
	} else if (memsize <= 2048LL * 1024 * 1024) {
		dns_conf.cachesize = 393216; /* 192MB memory*/
	} else if (memsize <= 4096LL * 1024 * 1024) {
		dns_conf.cachesize = 524288; /* 256MB memory*/
	} else {
		dns_conf.cachesize = 1048576; /* 512MB memory*/
	}
}

/* Translate only lossless legacy RR declarations into one runtime service. The
 * complete configuration is validated before any declaration is changed. */
struct pool_compat_plan {
	int leader;
	unsigned int count;
	char ips[64][DNS_MAX_IPLEN];
};

static int _pool_group_contains(const struct dns_server_groups *g, const struct dns_servers *s)
{
	for (int i = 0; i < g->server_num; i++) if (g->servers[i] == s) return 1;
	return 0;
}

static int _pool_same_group_sets(const struct dns_servers *a, const struct dns_servers *b)
{
	struct dns_server_groups *g;
	unsigned long bucket;
	hash_for_each(dns_group_table.group, bucket, g, node) {
		if (_pool_group_contains(g, a) != _pool_group_contains(g, b)) return 0;
	}
	return 1;
}

static int _pool_is_bootstrap(const struct dns_servers *s)
{
	struct dns_server_groups *g;
	unsigned long bucket;
	hash_for_each(dns_group_table.group, bucket, g, node)
		if (!strcmp(g->group_name, "bootstrap-dns") && _pool_group_contains(g, s)) return 1;
	return 0;
}

static int _pool_same_legacy_semantics(const struct dns_servers *a, const struct dns_servers *b)
{
	return !strcasecmp(a->authority, b->authority) && a->port == b->port && a->type == b->type &&
		a->result_flag == b->result_flag && a->server_flag == b->server_flag && a->ttl == b->ttl &&
		a->set_mark == b->set_mark && a->drop_packet_latency_ms == b->drop_packet_latency_ms &&
		a->tcp_keepalive == b->tcp_keepalive && a->max_query_rate == b->max_query_rate &&
		a->query_burst == b->query_burst && a->max_upstream_connections == b->max_upstream_connections &&
		a->fallback == b->fallback && a->subnet_all_query_types == b->subnet_all_query_types &&
		a->skip_check_cert == b->skip_check_cert && !strcmp(a->spki, b->spki) &&
		!strcmp(a->hostname, b->hostname) && !strcmp(a->httphost, b->httphost) &&
		!strcmp(a->tls_host_verify, b->tls_host_verify) && !strcmp(a->path, b->path) &&
		!strcmp(a->proxyname, b->proxyname) && !strcmp(a->ifname, b->ifname) && !strcmp(a->alpn, b->alpn) &&
		a->ipv4_ecs.enable == b->ipv4_ecs.enable && a->ipv4_ecs.subnet == b->ipv4_ecs.subnet &&
		!strcmp(a->ipv4_ecs.ip, b->ipv4_ecs.ip) && a->ipv6_ecs.enable == b->ipv6_ecs.enable &&
		a->ipv6_ecs.subnet == b->ipv6_ecs.subnet && !strcmp(a->ipv6_ecs.ip, b->ipv6_ecs.ip);
}

static int _pool_legacy_numeric(const char *text, char *normalized, size_t size)
{
	struct in_addr a4;
	struct in6_addr a6;
	if (inet_pton(AF_INET, text, &a4) != 1) {
		if (inet_pton(AF_INET6, text, &a6) != 1) return -1;
		if (!IN6_IS_ADDR_V4MAPPED(&a6)) {
			if (IN6_IS_ADDR_UNSPECIFIED(&a6) || IN6_IS_ADDR_MULTICAST(&a6)) return -1;
			return inet_ntop(AF_INET6, &a6, normalized, size) ? 0 : -1;
		}
		memcpy(&a4, &a6.s6_addr[12], sizeof(a4));
	}
	uint32_t ip = ntohl(a4.s_addr);
	if (!ip || IN_MULTICAST(ip) || ip == INADDR_BROADCAST) return -1;
	return inet_ntop(AF_INET, &a4, normalized, size) ? 0 : -1;
}

static int _dns_conf_normalize_pool_compat(void)
{
	int has_legacy = 0, ret = -1;
	for (int i = 0; i < dns_conf.server_num; i++)
		if (dns_conf.servers[i].upstream_round_robin && !dns_conf.servers[i].pool_compat_skip) has_legacy = 1;
	if (!has_legacy) return 0;
	struct pool_compat_plan *plans = calloc((size_t)dns_conf.server_num, sizeof(*plans));
	if (!plans) return -1;
	for (int i = 0; i < dns_conf.server_num; i++) plans[i].leader = -1;
	for (int i = 0; i < dns_conf.server_num; i++) {
		struct dns_servers *s = &dns_conf.servers[i];
		if (!s->upstream_round_robin || s->pool_compat_skip) continue;
		char ip[DNS_MAX_IPLEN];
		if (!s->quota_group[0] || !s->authority[0] || check_is_ipaddr(s->authority) == 0 ||
			s->upstream_ip_pool || s->proxyname[0] || s->type == DNS_SERVER_MDNS || _pool_is_bootstrap(s) ||
			s->max_concurrent_queries || _pool_legacy_numeric(s->server, ip, sizeof(ip))) {
			tlog(TLOG_ERROR, "%s:%u: legacy RR %s requires explicit migration: use domain authority, static numeric host-ip, no proxy/bootstrap/mDNS or per-endpoint concurrency", s->source_file, s->source_line, s->quota_group);
			goto out;
		}
		int leader = i;
		for (int j = 0; j < dns_conf.server_num; j++) {
			struct dns_servers *other = &dns_conf.servers[j];
			if (j == i || strcmp(s->quota_group, other->quota_group)) continue;
			if (!other->upstream_round_robin || other->upstream_ip_pool ||
				!_pool_same_legacy_semantics(s, other) || !_pool_same_group_sets(s, other)) {
				tlog(TLOG_ERROR, "%s:%u: legacy RR quota group %s differs from %s:%u and cannot be losslessly converted; split services explicitly and retain intended shared quota", s->source_file, s->source_line, s->quota_group, other->source_file, other->source_line);
				goto out;
			}
			if (j < leader) leader = j;
		}
		plans[i].leader = leader;
		struct pool_compat_plan *plan = &plans[leader];
		unsigned int at;
		for (at = 0; at < plan->count; at++) if (!strcmp(plan->ips[at], ip)) break;
		if (at == plan->count) {
			if (at == 64) goto out;
			safe_strncpy(plan->ips[at], ip, sizeof(plan->ips[at])); plan->count++;
		}
	}
	/* Commit: retain original array entries so all existing group pointers remain
	 * stable. Only the first entry is instantiated; identical group sets were
	 * required above, so skipping the others cannot change routing membership. */
	for (int i = 0; i < dns_conf.server_num; i++) {
		if (plans[i].leader < 0) continue;
		struct dns_servers *s = &dns_conf.servers[i];
		if (plans[i].leader != i) { s->pool_compat_skip = 1; continue; }
		s->upstream_ip_pool = 1; s->upstream_round_robin = 0;
		s->pool_ip_count = plans[i].count;
		s->max_upstream_backends = plans[i].count > s->max_upstream_connections ? plans[i].count : s->max_upstream_connections;
		memcpy(s->pool_ips, plans[i].ips, sizeof(s->pool_ips));
		safe_strncpy(s->server, s->authority, sizeof(s->server));
		char address_list[64 * DNS_MAX_IPLEN] = {0};
		size_t used = 0;
		for (unsigned int at = 0; at < s->pool_ip_count; at++) {
			int written = snprintf(address_list + used, sizeof(address_list) - used, "%s%s", at ? "," : "", s->pool_ips[at]);
			if (written < 0 || (size_t)written >= sizeof(address_list) - used) break;
			used += (size_t)written;
		}
		tlog(TLOG_WARN, "%s:%u: legacy RR %s normalized in memory to one service %s; preserve common authority/security/routing options and replace RR/address options with: -upstream-ip-pool -host-ip %s -max-upstream-backends %u -max-upstream-connections %u; actual-send RR and service-v1 counters now apply; configuration file unchanged",
			s->source_file, s->source_line, s->quota_group, s->authority, address_list,
			s->max_upstream_backends, s->max_upstream_connections);
	}
	ret = 0;
out:
	free(plans);
	return ret;
}

#ifdef TEST
int dns_conf_pool_normalize_for_test(void);
int dns_conf_pool_normalize_for_test(void) { return _dns_conf_normalize_pool_compat(); }
#endif

/* Pool discovery never falls back through the ordinary/default resolver graph. */
static int _dns_conf_verify_pool_bootstrap(void)
{
	int needs_bootstrap = 0, numeric_bootstrap = 0;
	struct dns_server_groups *group;
	unsigned long bucket;
	for (int i = 0; i < dns_conf.server_num; i++)
		if (dns_conf.servers[i].upstream_ip_pool && !dns_conf.servers[i].pool_ip_count)
			needs_bootstrap = 1;
	if (!needs_bootstrap) return 0;
	hash_for_each(dns_group_table.group, bucket, group, node) {
		if (strcmp(group->group_name, "bootstrap-dns")) continue;
		for (int i = 0; i < group->server_num; i++) {
			struct dns_servers *s = group->servers[i];
            if (!s || s->upstream_ip_pool || s->proxyname[0] || s->type == DNS_SERVER_MDNS ||
                check_is_ipaddr(s->server) != 0) {
                tlog(TLOG_ERROR, "automatic upstream-ip-pool requires every bootstrap-dns declaration to be an explicit numeric non-proxy non-pool target");
                return -1;
            }
            numeric_bootstrap = 1;
		}
	}
	if (!dns_conf_exist_bootstrap_dns || !numeric_bootstrap) {
		tlog(TLOG_ERROR, "automatic upstream-ip-pool requires an explicit numeric non-pool bootstrap-dns server");
		return -1;
	}
	return 0;
}

static int _dns_conf_load_post(void)
{
	_config_current_group_pop_to_default();
	_config_setup_smartdns_domain();
	_dns_conf_speed_check_mode_verify();

	_dns_conf_auto_set_cache_size();

	_dns_conf_setup_mdns();

	if (dns_conf.dns_resolv_file[0] == '\0') {
		safe_strncpy(dns_conf.dns_resolv_file, DNS_RESOLV_FILE, sizeof(dns_conf.dns_resolv_file));
	}

	_dns_conf_group_post();
	if (_config_any_verify() != 0) return -1;
	if (_dns_conf_normalize_pool_compat() != 0) return -1;
	if (_dns_conf_verify_pool_bootstrap() != 0) return -1;

	_dns_conf_dns64_post();

	_config_domain_set_name_table_destroy();

	_config_ip_set_name_table_destroy();

	_config_update_bootstrap_dns_rule();

	_config_add_default_server_if_needed();

	_config_file_hash_table_destroy();

	_config_current_group_pop_all();

	if (dns_conf.log_syslog == 0 && dns_conf.audit_syslog == 0) {
		closelog();
	}

	return 0;
}

int dns_server_load_conf(const char *file)
{
	int ret = 0;
	ret = _dns_conf_load_pre();
	if (ret != 0) {
		return ret;
	}

	openlog("smartdns", LOG_CONS, LOG_USER);
	ret = load_conf(file, _config_item, _conf_printf);
	if (ret != 0) {
		closelog();
		return ret;
	}

	ret = _dns_conf_load_post();
	return ret;
}
