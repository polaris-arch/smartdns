/* Bounded ANY coordination: transparent probes, finite fallback, and explicit
 * strict address completion. Ordinary A/AAAA clients never enter the coordinator. */
#include "any.h"
#include "address_child.h"
#include "context.h"
#include "request.h"
#include "server_http2.h"
#include "ipset_nftset.h"
#include "smartdns/dns_any.h"
#include "smartdns/dns_client.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define ANY_ACTIVE_MAX 128
#define ANY_WAITERS_MAX 32
#define ANY_CACHE_MAX 256
#define ANY_CLIENT_MAX 128
#define ANY_CLIENT_OPERATIONS 8
#define ANY_CLIENT_WAITERS 32

static unsigned int wire_u16(const unsigned char *p) { return ((unsigned int)p[0] << 8) | p[1]; }

/* The generic decoder deliberately discards unknown options, COOKIE and
 * PADDING. Attest the original wire before using it as a cache/view origin. */
void _dns_server_any_wire_context(struct dns_request *request, const unsigned char *wire, int len)
{
	if (request->qtype != DNS_T_ANY && request->qtype != DNS_T_A && request->qtype != DNS_T_AAAA) return;
	if (len < 12 || len > DNS_IN_PACKSIZE || (wire_u16(wire + 2) & ~(0x0100 | 0x0020 | 0x0010)) ||
		wire_u16(wire + 4) != 1 || wire_u16(wire + 6) || wire_u16(wire + 8)) goto unsupported;
	int pos = 12;
	while (pos < len) {
		unsigned int label = wire[pos++];
		if (!label) break;
		if ((label & 0xc0) == 0xc0) {
			if (pos >= len) goto unsupported;
			pos++;
			break; /* dns_decode has already validated the compressed name. */
		}
		if (label > 63 || label > (unsigned int)(len - pos)) goto unsupported;
		pos += label;
	}
	if (pos + 4 > len) goto unsupported;
	pos += 4;
	unsigned int additional = wire_u16(wire + 10);
	if (!additional) {
		if (pos != len) goto unsupported;
		return;
	}
	if (additional != 1 || pos + 11 > len || wire[pos] || wire_u16(wire + pos + 1) != DNS_T_OPT ||
		wire[pos + 5] || wire[pos + 6] || (wire[pos + 7] & 0x7f) || wire[pos + 8]) goto unsupported;
	int end = pos + 11 + wire_u16(wire + pos + 9);
	pos += 11;
	if (end != len) goto unsupported;
	if (pos < end) request->any_unknown_context = 1;
	if (dns_any_hop_options(wire + pos, end - pos, 0)) goto unsupported;
	return;
unsupported:
	request->any_unknown_context = request->any_unsupported_context = 1;
}

struct any_key {
	char domain[DNS_MAX_CNAME_LEN];
	char route[DNS_GROUP_NAME_LEN];
	char rule_group[DNS_GROUP_NAME_LEN];
	const struct dns_conf_group *conf;
	uint32_t server_flags;
	unsigned short qtype;
	struct dns_any_config config;
};
struct any_operation;
struct any_child {
	struct any_operation *owner;
	int type, started, ended, has_result, reported, policy_negative;
	unsigned long received;
	int len;
	unsigned char *data;
};
struct any_operation {
	atomic_t refs;
	pthread_mutex_t lock;
	struct any_key key;
	struct dns_query_budget *budget;
	struct dns_request *waiters[ANY_WAITERS_MAX];
	int waiter_clients[ANY_WAITERS_MAX];
	int owner_client;
	int waiter_count, terminal, table_slot, active, next, completed, expanded, shareable;
	int final_len;
	unsigned long finished;
	unsigned char final_wire[DNS_IN_PACKSIZE];
	struct any_child children[DNS_ANY_MAX_TYPES + 1];
	/* Payloads share the operation lifetime; unused child slots own no buffer. */
	unsigned char child_wire[];
};
struct any_cache {
	struct any_key key;
	int len;
	unsigned long received, touched;
	uint32_t lifetime;
	unsigned char data[DNS_IN_PACKSIZE];
};
struct any_client {
	unsigned char address[16];
	unsigned int scope;
	int family, operations, waiters;
};
static pthread_mutex_t any_lock = PTHREAD_MUTEX_INITIALIZER;
static struct any_client clients[ANY_CLIENT_MAX];
static struct any_operation *operations[ANY_ACTIVE_MAX];
static atomic_t any_active;
static atomic_t any_allocated;
static struct any_cache cache[ANY_CACHE_MAX];
static int cache_limit(void)
{
	/* The configuration loader resolves automatic (-1) sizing before use.
	 * An explicitly disabled global cache also disables completed ANY results. */
	if (dns_conf.cachesize <= 0) return 0;
	return dns_conf.cachesize < ANY_CACHE_MAX ? dns_conf.cachesize : ANY_CACHE_MAX;
}

/* All client counters are protected by any_lock. Source ports and ECS do not
 * create a new identity. An IPv4-mapped address shares the IPv4 counter. */
static int client_reserve_waiter(struct dns_request *request)
{
	struct any_client identity = {0};
	int empty = -1;
	if (request->addr.sa_family == AF_INET) {
		identity.family = AF_INET;
		memcpy(identity.address, &request->in.sin_addr, 4);
	} else if (request->addr.sa_family == AF_INET6) {
		if (IN6_IS_ADDR_V4MAPPED(&request->in6.sin6_addr)) {
			identity.family = AF_INET;
			memcpy(identity.address, &request->in6.sin6_addr.s6_addr[12], 4);
		} else {
			identity.family = AF_INET6; identity.scope = request->in6.sin6_scope_id;
			memcpy(identity.address, &request->in6.sin6_addr, 16);
		}
	} else return -1;
	for (int i = 0; i < ANY_CLIENT_MAX; i++) {
		if (clients[i].family == 0) { if (empty < 0) empty = i; continue; }
		if (clients[i].family != identity.family || clients[i].scope != identity.scope ||
			memcmp(clients[i].address, identity.address, sizeof(identity.address))) continue;
		if (clients[i].waiters >= ANY_CLIENT_WAITERS) return -1;
		clients[i].waiters++; return i;
	}
	if (empty >= 0) { clients[empty] = identity; clients[empty].waiters = 1; }
	return empty;
}

static void client_release(int index, int operation)
{
	if (index < 0) return;
	pthread_mutex_lock(&any_lock);
	if (operation) clients[index].operations--; else clients[index].waiters--;
	if (!clients[index].operations && !clients[index].waiters) memset(&clients[index], 0, sizeof(clients[index]));
	pthread_mutex_unlock(&any_lock);
}

static void operation_get(struct any_operation *op) { atomic_inc(&op->refs); }
static void operation_put(struct any_operation *op)
{
	if (atomic_dec_return(&op->refs) != 0) return;
	dns_query_budget_put(op->budget);
	client_release(op->owner_client, 1);
	pthread_mutex_destroy(&op->lock);
	atomic_dec(&any_allocated);
	free(op);
}

static int same_key(const struct any_key *a, const struct any_key *b)
{
	return a->conf == b->conf && a->server_flags == b->server_flags && a->qtype == b->qtype &&
		!strcmp(a->domain, b->domain) && !strcmp(a->route, b->route) &&
		!strcmp(a->rule_group, b->rule_group) && !memcmp(&a->config, &b->config, sizeof(a->config));
}

static uint32_t elapsed(unsigned long start)
{
	unsigned long millis = get_tick_count() - start;
	unsigned long delta = millis / 1000 + (millis % 1000 != 0);
	return delta > UINT32_MAX ? UINT32_MAX : delta;
}

/* This is deliberately stricter than the legacy A/AAAA cache key. Unsupported
 * context stays transparent in legacy modes and fails in explicit address mode;
 * it never receives guessed shared/synthesized data. */
int _dns_server_any_plain_context(struct dns_request *request, const char *route)
{
	struct dns_conf_ipset_nftset no_ipset = {0};
	if (!route) route = DNS_SERVER_GROUP_DEFAULT;
	if (memcmp(&request->conf->ipset_nftset, &no_ipset, sizeof(no_ipset))) return 0;
	if (_dns_server_get_bind_ipset_context(request)) return 0;
	/* Address-mode completeness cannot be replaced by a policy-generated
	 * negative for the parent ANY question before either family is observed. */
	if (request->qtype == DNS_T_ANY && request->conf->any.aggregate == DNS_ANY_ADDRESS && request->conf->soa_table &&
		(request->conf->soa_table[DNS_T_ANY / 8] & (1 << (DNS_T_ANY % 8)))) return 0;
	for (int i = 0; i < dns_conf.server_num; i++) if (dns_conf.servers[i].result_flag) return 0;
	if (request->server_flags & BIND_FLAG_NO_CACHE) return 0;
	if (request->qclass != DNS_C_IN || request->edns0_do || request->any_do || request->any_cd || request->any_ad ||
		!request->any_rd || request->any_unknown_context || request->has_ecs || request->prefetch ||
		request->is_mdns_lookup || request->has_cname || request->parent_request || request->no_cache ||
		request->conf->ipv4_ecs.enable || request->conf->ipv6_ecs.enable || request->conf->dns_dns64.prefix_len ||
		request->conf->dns_force_no_cname || dns_client_group_has_ecs(route)) return 0;
	if ((request->conf->address_rule.ipv4 && request->conf->address_rule.ipv4->head) ||
		(request->conf->address_rule.ipv6 && request->conf->address_rule.ipv6->head)) return 0;
	for (int i = 0; i < DOMAIN_RULE_MAX; i++) {
		if (i == DOMAIN_RULE_NAMESERVER || i == DOMAIN_RULE_GROUP || i == DOMAIN_RULE_CHECKSPEED ||
			i == DOMAIN_RULE_RESPONSE_MODE || i == DOMAIN_RULE_TTL) continue;
		if (request->domain_rule.rules[i]) return 0;
	}
	return 1;
}

/* Resolving through native policy is distinct from proving that a legacy
 * cache entry or another client's operation is safe to reuse. AD on a query
 * only advertises client capability; synthesized replies still clear AD. */
int _dns_server_native_address_context(struct dns_request *request, const char *route)
{
	return request->qclass == DNS_C_IN && request->any_rd &&
		!request->edns0_do && !request->any_do && !request->any_cd &&
		!request->any_unsupported_context && !request->has_ecs && !request->is_mdns_lookup &&
		!request->conf->dns_dns64.prefix_len &&
		!request->conf->ipv4_ecs.enable && !request->conf->ipv6_ecs.enable &&
		!dns_client_group_has_ecs(route ? route : DNS_SERVER_GROUP_DEFAULT);
}

int _dns_server_any_address_context(struct dns_request *request, const char *route)
{
	return !request->prefetch && _dns_server_native_address_context(request, route);
}

/* Validate aliases before suppressing them. Suppression must not hide a
 * disagreement between the two upstream canonical names. */
int _dns_server_any_flatten_addresses(const char *domain, int qtype, unsigned char *wire, int len)
{
	unsigned char packet_buf[DNS_PACKSIZE], output_buf[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buf;
	struct dns_packet *output = (struct dns_packet *)output_buf;
	if (dns_decode(packet, sizeof(packet_buf), wire, len)) return -1;
	struct dns_head head = packet->head;
	if (dns_packet_init(output, sizeof(output_buf), &head) ||
		dns_add_domain(output, domain, qtype, DNS_C_IN)) return -1;
	int count = 0, alias_ttl = INT_MAX;
	struct dns_rrs *rr = dns_get_rrs_start(packet, DNS_RRS_AN, &count);
	for (int i = 0; rr && i < count; i++, rr = dns_get_rrs_next(packet, rr)) {
		char owner[DNS_MAX_CNAME_LEN], target[DNS_MAX_CNAME_LEN];
		int ttl;
		if (rr->type == DNS_T_CNAME) {
			if (dns_get_CNAME(rr, owner, sizeof(owner), &ttl, target, sizeof(target))) return -1;
			if (ttl < alias_ttl) alias_ttl = ttl;
		}
	}
	rr = dns_get_rrs_start(packet, DNS_RRS_AN, &count);
	for (int i = 0; rr && i < count; i++, rr = dns_get_rrs_next(packet, rr)) {
		char owner[DNS_MAX_CNAME_LEN];
		unsigned char address[DNS_RR_AAAA_LEN];
		int ttl, ret;
		if (rr->type == DNS_T_CNAME) continue;
		if (rr->type != DNS_T_A && rr->type != DNS_T_AAAA) return -1;
		ret = rr->type == DNS_T_A ? dns_get_A(rr, owner, sizeof(owner), &ttl, address) :
			dns_get_AAAA(rr, owner, sizeof(owner), &ttl, address);
		if (ret) return -1;
		if (ttl > alias_ttl) ttl = alias_ttl;
		ret = rr->type == DNS_T_A ? dns_add_A(output, DNS_RRS_AN, domain, ttl, address) :
			dns_add_AAAA(output, DNS_RRS_AN, domain, ttl, address);
		if (ret) return -1;
	}
	rr = dns_get_rrs_start(packet, DNS_RRS_NS, &count);
	for (int i = 0; rr && i < count; i++, rr = dns_get_rrs_next(packet, rr)) {
		char owner[DNS_MAX_CNAME_LEN];
		struct dns_soa soa;
		int ttl;
		if (rr->type != DNS_T_SOA || dns_get_SOA(rr, owner, sizeof(owner), &ttl, &soa) ||
			dns_add_SOA(output, DNS_RRS_NS, domain, ttl, &soa)) return -1;
	}
	return dns_encode(wire, DNS_IN_PACKSIZE, output);
}

static void reply(struct dns_request *request, const unsigned char *data, int len, int cached)
{
	unsigned char wire[DNS_IN_PACKSIZE], packet_buf[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buf;
	struct dns_server_post_context context;
	if (atomic_read(&request->notified)) return;
	if (len <= 0 || len > (int)sizeof(wire)) {
		len = dns_any_empty_response(request->domain, DNS_RC_SERVFAIL, 0, wire, sizeof(wire));
	} else if (request->conn && request->conn->type == DNS_CONN_TYPE_UDP_SERVER && len > request->any_udp_size) {
		/* A question-only TC packet is a safe whole-RR truncation for even unknown
		 * compressed RDATA. Keep the complete snapshot cached for TCP retry. */
		len = dns_any_empty_response(request->domain, data[3] & 15, 1, wire, sizeof(wire));
	} else memcpy(wire, data, len);
	if (len < 0 || dns_decode(packet, sizeof(packet_buf), wire, len)) return;
	request->rcode = packet->head.rcode;
	request->is_cache_reply = cached;
	_dns_server_post_context_init_from(&context, request, packet, wire, len);
	context.do_cache = 0; context.do_audit = 1; context.do_reply = 1;
	context.do_ipset = 0; context.reply_ttl = -1;
	_dns_server_reply_passthrough(&context);
}

/* Cache is bounded, private to exact ANY context, and never uses serve-stale or
 * TTL floors. Child entries are not imported from the unsafe legacy cache key. */
static void cache_result(const struct any_key *key, unsigned char *data, int len)
{
	int limit = cache_limit();
	if (limit == 0) return;
	uint32_t lifetime = 0;
	unsigned char packet_buf[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buf;
	int option_count = 0;
	if (len <= 0 || dns_decode(packet, sizeof(packet_buf), data, len) || dns_get_OPT_option(packet)) return;
	dns_get_rrs_start(packet, DNS_RRS_OPT, &option_count);
	if (option_count) return; /* unsolicited ECS/cookie/unknown context is not cached */
	if (len < 12 || (data[2] & 2) || ((data[3] & 15) != DNS_RC_NOERROR && (data[3] & 15) != DNS_RC_NXDOMAIN) ||
		dns_any_wire_age(data, len, 0, &lifetime) || lifetime == 0) return;
	pthread_mutex_lock(&any_lock);
	int slot = 0;
	for (int i = 0; i < limit; i++) {
		if (cache[i].len == 0 || same_key(&cache[i].key, key)) { slot = i; break; }
		if (cache[i].touched < cache[slot].touched) slot = i;
	}
	cache[slot].key = *key; cache[slot].len = len; cache[slot].lifetime = lifetime;
	cache[slot].received = cache[slot].touched = get_tick_count();
	memcpy(cache[slot].data, data, len);
	pthread_mutex_unlock(&any_lock);
}

static int cache_lookup(const struct any_key *key, unsigned char *wire)
{
	int len = 0;
	pthread_mutex_lock(&any_lock);
	for (int i = 0; i < cache_limit(); i++) {
		if (!cache[i].len || !same_key(&cache[i].key, key)) continue;
		if ((get_tick_count() - cache[i].received) / 1000 >= cache[i].lifetime) { cache[i].len = 0; break; }
		len = cache[i].len; memcpy(wire, cache[i].data, len);
		if (dns_any_wire_age(wire, len, elapsed(cache[i].received), NULL)) len = 0;
		cache[i].touched = get_tick_count(); break;
	}
	pthread_mutex_unlock(&any_lock);
	return len;
}

/* Caller holds op->lock and a temporary/callback reference. */
static void finish(struct any_operation *op, unsigned char *wire, int len)
{
	if (op->terminal) return;
	op->terminal = 1;
	op->final_len = len; op->finished = get_tick_count();
	if (len > 0) memcpy(op->final_wire, wire, len);
	dns_query_budget_cancel(op->budget);
	if (len > 0 && op->key.config.aggregate != DNS_ANY_ADDRESS) cache_result(&op->key, wire, len);
	pthread_mutex_lock(&any_lock);
	if (op->table_slot >= 0 && operations[op->table_slot] == op) {
		operations[op->table_slot] = NULL; atomic_dec(&any_active);
	}
	op->table_slot = -1;
	pthread_mutex_unlock(&any_lock);
	for (int i = 0; i < op->waiter_count; i++) {
		struct dns_request *request = op->waiters[i];
		op->waiters[i] = NULL;
		client_release(op->waiter_clients[i], 0);
		reply(request, wire, len, 0);
		_dns_server_request_release_complete(request, 0);
	}
	op->waiter_count = 0;
	operation_put(op); /* table membership */
}

static void finish_aggregate(struct any_operation *op)
{
	unsigned char wire[DNS_IN_PACKSIZE];
	struct dns_any_input input[DNS_ANY_MAX_TYPES] = {{0}};
	int count = 0;
	for (int i = 0; i < op->key.config.type_count; i++) {
		struct any_child *child = &op->children[i + 1];
		/* A native policy may deliberately suppress a family. It is not an
		 * upstream absence claim and must not constrain the other alias chain.
		 * Missing/error children are still retained and fail the strict join. */
		if (op->key.config.aggregate == DNS_ANY_ADDRESS && child->policy_negative) continue;
		input[count].qtype = child->type;
		if (child->has_result) {
			input[count].data = child->data; input[count].len = child->len; input[count].age = elapsed(child->received);
		} else tlog(TLOG_DEBUG, "ANY aggregate has no result for configured type %d", child->type);
		count++;
	}
	if (!count) {
		/* Both families were explicitly blocked by native policy. Return its
		 * coherent SOA response rather than converting the block to SERVFAIL. */
		for (int i = 1; i <= op->key.config.type_count; i++) {
			struct any_child *child = &op->children[i];
			input[count++] = (struct dns_any_input){child->data, child->len, child->type, elapsed(child->received)};
		}
	}
	int len = dns_any_merge(op->key.domain, input, count, op->key.config.partial, wire, sizeof(wire));
	if (len > 0 && op->key.config.aggregate == DNS_ANY_ADDRESS && op->key.conf->dns_force_no_cname)
		len = _dns_server_any_flatten_addresses(op->key.domain, DNS_T_ANY, wire, len);
	if (len < 0) {
		tlog(TLOG_DEBUG, "ANY aggregate failed validation or has no usable configured result");
		len = dns_any_empty_response(op->key.domain, DNS_RC_SERVFAIL, 0, wire, sizeof(wire));
	}
	else if (op->key.config.aggregate != DNS_ANY_ADDRESS) {
		/* Only coherent, validated child packets seed the private typed cache. */
		for (int i = 1; i <= op->key.config.type_count; i++) {
			struct any_child *child = &op->children[i];
			if (!child->has_result) continue;
			struct any_key key = op->key;
			unsigned char aged[DNS_IN_PACKSIZE];
			key.qtype = child->type; memcpy(aged, child->data, child->len);
			struct dns_any_input single = {child->data, child->len, child->type, elapsed(child->received)};
			unsigned char validated[DNS_IN_PACKSIZE];
			if (dns_any_merge(op->key.domain, &single, 1, 0, validated, sizeof(validated)) >= 0 &&
				!dns_any_wire_age(aged, child->len, elapsed(child->received), NULL)) cache_result(&key, aged, child->len);
		}
	}
	finish(op, wire, len);
}

/* A failed default-mode probe is only a fallback result while other upstream
 * replies can still arrive. Keep one bounded packet, then return it when the
 * client query ends or the shared deadline expires. */
static void finish_probe(struct any_operation *op)
{
	struct any_child *probe = &op->children[0];
	if (probe->has_result && !op->key.config.aggregate) {
		unsigned char wire[DNS_IN_PACKSIZE];
		memcpy(wire, probe->data, probe->len);
		if (!dns_any_wire_age(wire, probe->len, elapsed(probe->received), NULL)) {
			finish(op, wire, probe->len);
			return;
		}
	}
	finish(op, NULL, -1);
}

static void schedule(struct any_operation *op);
static int child_callback(const char *domain, dns_result_type rtype, struct dns_server_info *server_info,
						  struct dns_packet *packet, unsigned char *wire, int len, void *user_ptr)
{
	struct any_child *child = user_ptr;
	struct any_operation *op = child->owner;
	int action = DNS_CLIENT_ACTION_OK;
	pthread_mutex_lock(&op->lock);
	if (!op->terminal && op->budget && dns_query_budget_remaining_ms(op->budget) == 0) {
		if (op->expanded) finish_aggregate(op); else finish_probe(op);
	}
	int probe = child == &op->children[0];
	if (rtype == DNS_QUERY_RESULT && probe && !op->key.config.aggregate && !op->terminal)
		action = DNS_CLIENT_ACTION_MAY_RETRY;
	if (rtype == DNS_QUERY_RESULT && !op->terminal && (!child->has_result || (probe && !op->key.config.aggregate)) &&
		len >= 12 && len <= DNS_IN_PACKSIZE) {
		/* The client already validates question/source association. Copy before the
		 * callback returns; transport receive buffers are not owned by us. */
		uint32_t ttl;
		char question_name[DNS_MAX_CNAME_LEN];
		int question_count = 0, qtype = 0, qclass = 0;
		struct dns_rrs *question = dns_get_rrs_start(packet, DNS_RRS_QD, &question_count);
		if (packet->head.opcode == DNS_OP_QUERY && question_count == 1 && question &&
			!dns_get_domain(question, question_name, sizeof(question_name), &qtype, &qclass) &&
			qtype == child->type && qclass == DNS_C_IN && !strcasecmp(question_name, op->key.domain) &&
			dns_any_wire_age(wire, len, 0, &ttl) == 0) {
			int success = packet->head.rcode == DNS_RC_NOERROR || packet->head.rcode == DNS_RC_NXDOMAIN;
			if (success) action = DNS_CLIENT_ACTION_OK;
			/* Preserve the first failure, but never let it mask a healthy sibling.
			 * Aggregate probes use a single upstream and retain their old trigger. */
			if (!child->has_result || success) {
				memcpy(child->data, wire, len); child->len = len;
				child->received = get_tick_count(); child->has_result = 1;
			}
			if (probe && (success || (op->key.config.aggregate &&
				packet->head.rcode != DNS_RC_REFUSED && packet->head.rcode != DNS_RC_NOTIMP)))
				finish(op, child->data, child->len);
		}
	}
	int release = 0, wake = 0;
	if (rtype == DNS_QUERY_END && !child->ended) {
		child->ended = 1; op->active--; release = 1;
		if (!op->terminal) {
			if (child == &op->children[0]) {
				if (child->has_result && op->key.config.aggregate &&
					((child->data[3] & 15) == DNS_RC_REFUSED || (child->data[3] & 15) == DNS_RC_NOTIMP)) op->expanded = 1;
				else finish_probe(op);
			} else op->completed++;
			/* Continue on the server thread, never recursively under client
			 * teardown/transport locks or after a full idle timer interval. */
			wake = !op->terminal;
		}
	}
	pthread_mutex_unlock(&op->lock);
	if (wake) _dns_server_wakeup_thread();
	if (release) operation_put(op); /* client callback lifetime through END */
	return action;
}

static void launch(struct any_operation *op, int index)
{
	struct any_child *child = &op->children[index];
	struct dns_query_options options = {0};
	options.conf_group_name = op->key.rule_group;
	if (op->budget) {
		options.enable_flag = DNS_QUEY_OPTION_BUDGET;
		if (op->key.config.aggregate) options.enable_flag |= DNS_QUEY_OPTION_SINGLE_UPSTREAM;
		options.budget = op->budget;
	}
	child->started = 1;
	if (index != 0) {
		struct any_key key = op->key;
		key.qtype = child->type;
		child->len = cache_lookup(&key, child->data);
		if (child->len > 0) {
			child->has_result = child->ended = 1; child->received = get_tick_count(); op->completed++;
			return;
		}
	}
	if (op->budget && dns_query_budget_exhausted(op->budget)) {
		child->ended = 1; if (index != 0) op->completed++;
		return;
	}
	op->active++;
	operation_get(op);
	/* Client callbacks may run synchronously and under transport locks. Do not
	 * hold the coordinator lock while entering client admission/send code. */
	pthread_mutex_unlock(&op->lock);
	int result = dns_client_query(op->key.domain, child->type, child_callback, child, op->key.route, &options);
	pthread_mutex_lock(&op->lock);
	if (result != 0 && !child->ended) {
		child->ended = 1; op->active--;
		if (index != 0) op->completed++;
		operation_put(op);
	}
}

/* Result and request destruction are distinct: ping/native callbacks may still
 * own a child after its finalized answer has been observed. */
static void address_callback(void *arg, enum dns_address_child_result result,
                             const unsigned char *wire, int len, int final_release)
{
	struct any_child *child = arg;
	struct any_operation *op = child->owner;
	int release = 0, wake = 0;
	pthread_mutex_lock(&op->lock);
	if (!final_release && !child->reported) {
		child->reported = 1; op->completed++;
		if (!op->terminal && (result == DNS_ADDRESS_CHILD_POSITIVE ||
			result == DNS_ADDRESS_CHILD_NODATA || result == DNS_ADDRESS_CHILD_NXDOMAIN ||
			result == DNS_ADDRESS_CHILD_POLICY_NODATA) &&
			wire && len >= 12 && len <= DNS_IN_PACKSIZE) {
			memcpy(child->data, wire, len); child->len = len;
			child->received = get_tick_count(); child->has_result = 1;
			child->policy_negative = result == DNS_ADDRESS_CHILD_POLICY_NODATA;
		}
		wake = !op->terminal;
	}
	if (final_release && !child->ended) {
		child->ended = 1; op->active--; release = 1;
		if (!child->reported) { child->reported = 1; op->completed++; }
		wake = !op->terminal;
	}
	pthread_mutex_unlock(&op->lock);
	if (wake) _dns_server_wakeup_thread();
	if (release) operation_put(op);
}

static void schedule_address(struct any_operation *op)
{
	if (!op->expanded) {
		/* Reserve BOTH callback lifetimes before a synchronous cache completion
		 * is possible. Keep the parent alive across both unlocked admissions. */
		struct dns_request *parent = op->waiters[0];
		_dns_server_request_get(parent);
		op->expanded = 1; op->next = 2;
		for (int i = 1; i <= 2; i++) {
			op->children[i].started = 1; op->active++; operation_get(op);
		}
		pthread_mutex_unlock(&op->lock);
		for (int i = 1; i <= 2; i++) {
			struct any_child *child = &op->children[i];
			if (_dns_server_address_child_start(parent, child->type, op->budget,
				address_callback, child) != 0)
				address_callback(child, DNS_ADDRESS_CHILD_FAILURE, NULL, 0, 1);
		}
		_dns_server_request_release_complete(parent, 0);
		pthread_mutex_lock(&op->lock);
	}
	if (!op->terminal && op->completed == 2) finish_aggregate(op);
}

static void schedule(struct any_operation *op)
{
	if (op->terminal) return;
	if (op->key.config.aggregate == DNS_ANY_ADDRESS) { schedule_address(op); return; }
	if (!op->children[0].started) {
		launch(op, 0);
		if (op->children[0].ended && !op->expanded && !op->terminal) finish_probe(op);
		return;
	}
	if (!op->expanded) return;
	while (!op->terminal && op->active < op->key.config.concurrency && op->next < op->key.config.type_count &&
		dns_query_budget_remaining_ms(op->budget) > 0) {
		int index = ++op->next;
		launch(op, index);
	}
	if (!op->terminal && ((op->next == op->key.config.type_count && op->active == 0) ||
		(dns_query_budget_exhausted(op->budget) && op->active == 0))) finish_aggregate(op);
}

int _dns_server_process_any(struct dns_request *request, const char *group_name)
{
	struct any_key key = {0};
	unsigned char cached[DNS_IN_PACKSIZE];
	int cached_len = 0, free_slot = -1, client_index = -1;
	struct any_operation *op = NULL;
	struct dns_query_budget *budget = NULL;
	const char *route = group_name ? group_name : DNS_SERVER_GROUP_DEFAULT;
	if (request->qtype != DNS_T_ANY) return -1;
	int plain = _dns_server_any_plain_context(request, route);
	if (request->conf->any.aggregate == DNS_ANY_ADDRESS ?
		!_dns_server_any_address_context(request, route) : !plain) {
		if (request->conf->any.aggregate != DNS_ANY_ADDRESS) return -1;
		reply(request, NULL, -1, 0); return 0;
	}
	safe_strncpy(key.domain, request->domain, sizeof(key.domain));
	safe_strncpy(key.route, route, sizeof(key.route));
	safe_strncpy(key.rule_group, request->dns_group_name, sizeof(key.rule_group));
	key.conf = request->conf; key.server_flags = request->server_flags; key.config = request->conf->any;
	key.qtype = DNS_T_ANY;
	if (key.config.aggregate == DNS_ANY_ADDRESS) {
		/* Legacy finite-RR options do not change the address contract or split
		 * otherwise equivalent singleflight keys. */
		memset(key.config.types, 0, sizeof(key.config.types));
		key.config.types[0] = DNS_T_A; key.config.types[1] = DNS_T_AAAA;
		key.config.type_count = 2; key.config.concurrency = 2; key.config.partial = 0;
	} else cached_len = cache_lookup(&key, cached);
	if (!cached_len) {
		/* The ordinary-policy helper takes the client server-list lock. Never
		 * call it with any_lock/op->lock held: receive callbacks take those
		 * coordinator locks from the client side. An unused candidate is put
		 * after lookup when this request joins an existing operation. */
		if (key.config.aggregate) {
			unsigned long spent = get_tick_count() - request->send_tick;
			unsigned int remaining = spent >= DNS_REQUEST_MAX_TIMEOUT ? 0 : DNS_REQUEST_MAX_TIMEOUT - spent;
			if (remaining > (unsigned int)key.config.timeout_ms) remaining = key.config.timeout_ms;
			if (remaining) budget = dns_query_budget_new(key.config.max_attempts, remaining);
		} else budget = dns_client_query_budget_new(route);
	}
	pthread_mutex_lock(&any_lock);
	if (!cached_len) client_index = client_reserve_waiter(request);
	if (!cached_len && client_index >= 0) {
		for (int i = 0; i < ANY_ACTIVE_MAX; i++) {
			if (!operations[i]) { if (free_slot < 0) free_slot = i; continue; }
			/* Non-plain native policy can depend on client identity. Do not
			 * coalesce it under a legacy key that does not attest that context. */
			if (plain && operations[i]->shareable && same_key(&operations[i]->key, &key)) {
				op = operations[i]; operation_get(op); break;
			}
		}
		if (!op && budget && free_slot >= 0 && atomic_read(&any_allocated) < ANY_ACTIVE_MAX &&
			clients[client_index].operations < ANY_CLIENT_OPERATIONS) {
			/* Keep stable child indices and a single allocation/free. Address mode
			 * never probes child 0; passthrough never launches typed children. */
			int first = key.config.aggregate == DNS_ANY_ADDRESS ? 1 : 0;
			int last = key.config.aggregate ? key.config.type_count : 0;
			if (key.config.type_count >= 0 && key.config.type_count <= DNS_ANY_MAX_TYPES && last >= first) {
				size_t count = (size_t)(last - first + 1);
				if (count <= (SIZE_MAX - sizeof(*op)) / DNS_IN_PACKSIZE)
					op = calloc(1, sizeof(*op) + count * DNS_IN_PACKSIZE);
			}
			if (op) {
				atomic_inc(&any_allocated);
				pthread_mutexattr_t attr;
				pthread_mutexattr_init(&attr); pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
				pthread_mutex_init(&op->lock, &attr); pthread_mutexattr_destroy(&attr);
				atomic_set(&op->refs, 2); /* table plus this call */
				op->key = key; op->table_slot = free_slot; op->shareable = plain;
				op->budget = budget; budget = NULL;
				for (int j = 0; j <= key.config.type_count; j++) {
					op->children[j].owner = op;
					op->children[j].type = j ? key.config.types[j - 1] : DNS_T_ANY;
				}
				for (int j = first; j <= last; j++)
					op->children[j].data = op->child_wire + (size_t)(j - first) * DNS_IN_PACKSIZE;
				op->owner_client = client_index; clients[client_index].operations++;
				operations[free_slot] = op; atomic_inc(&any_active);
			}
		}
	}
	pthread_mutex_unlock(&any_lock);
	dns_query_budget_put(budget);
	if (cached_len) { reply(request, cached, cached_len, 1); return 0; }
	if (!op) {
		client_release(client_index, 0);
		/* Passthrough coordination is an optional cache/coalescing optimization.
		 * Its resource caps must not reject ordinary native ANY requests. */
		if (!key.config.aggregate) return -1;
		reply(request, NULL, -1, 0); return 0;
	}
	pthread_mutex_lock(&op->lock);
	if (op->terminal) {
		client_release(client_index, 0);
		unsigned char wire[DNS_IN_PACKSIZE];
		int len = op->final_len;
		if (len > 0) {
			memcpy(wire, op->final_wire, len);
			if (dns_any_wire_age(wire, len, elapsed(op->finished), NULL)) len = -1;
		}
		reply(request, wire, len, 0);
	} else if (op->waiter_count >= ANY_WAITERS_MAX) {
		client_release(client_index, 0);
		if (!key.config.aggregate) {
			pthread_mutex_unlock(&op->lock);
			operation_put(op);
			return -1;
		}
		reply(request, NULL, -1, 0);
	}
	else {
		_dns_server_request_get(request);
		op->waiter_clients[op->waiter_count] = client_index;
		op->waiters[op->waiter_count++] = request;
		/* Keep the existing event loop at its active-request cadence, including
		 * while a probe or admission cooldown consumes the parent deadline. */
		pthread_mutex_lock(&server.request_list_lock);
		if (list_empty(&request->list)) list_add_tail(&request->list, &server.request_list);
		pthread_mutex_unlock(&server.request_list_lock);
		_dns_server_wakeup_thread();
		schedule(op);
	}
	pthread_mutex_unlock(&op->lock);
	operation_put(op);
	return 0;
}

void _dns_server_any_period(void)
{
	if (atomic_read(&any_active) == 0) return;
	struct any_operation *snapshot[ANY_ACTIVE_MAX];
	int count = 0;
	pthread_mutex_lock(&any_lock);
	for (int i = 0; i < ANY_ACTIVE_MAX; i++) if (operations[i]) {
		snapshot[count++] = operations[i]; operation_get(operations[i]);
	}
	pthread_mutex_unlock(&any_lock);
	for (int i = 0; i < count; i++) {
		struct any_operation *op = snapshot[i];
		pthread_mutex_lock(&op->lock);
		if (!op->terminal && op->budget && dns_query_budget_remaining_ms(op->budget) == 0) {
			if (op->expanded) finish_aggregate(op); else finish_probe(op);
		} else if (!op->terminal) schedule(op);
		pthread_mutex_unlock(&op->lock); operation_put(op);
	}
}

void _dns_server_any_destroy(void)
{
	/* Client shutdown runs first and retires all callback references. */
	struct any_operation *snapshot[ANY_ACTIVE_MAX];
	int count = 0;
	pthread_mutex_lock(&any_lock);
	for (int i = 0; i < ANY_ACTIVE_MAX; i++) if (operations[i]) {
		snapshot[count++] = operations[i]; operation_get(operations[i]);
	}
	memset(cache, 0, sizeof(cache));
	pthread_mutex_unlock(&any_lock);
	for (int i = 0; i < count; i++) {
		pthread_mutex_lock(&snapshot[i]->lock);
		finish(snapshot[i], NULL, -1);
		pthread_mutex_unlock(&snapshot[i]->lock); operation_put(snapshot[i]);
	}
}

static void cancel_waiters(struct dns_server_conn_head *conn, int reset_only)
{
	if (atomic_read(&any_active) == 0) return;
	struct any_operation *snapshot[ANY_ACTIVE_MAX];
	int count = 0;
	pthread_mutex_lock(&any_lock);
	for (int i = 0; i < ANY_ACTIVE_MAX; i++) if (operations[i]) {
		snapshot[count++] = operations[i]; operation_get(operations[i]);
	}
	pthread_mutex_unlock(&any_lock);
	for (int i = 0; i < count; i++) {
		struct any_operation *op = snapshot[i];
		pthread_mutex_lock(&op->lock);
		for (int j = 0; j < op->waiter_count; ) {
			struct dns_request *request = op->waiters[j];
			struct dns_server_conn_head *owner = request->conn;
			struct dns_server_conn_http2_stream *stream_conn = NULL;
			if (owner && owner->type == DNS_CONN_TYPE_HTTP2_STREAM) {
				stream_conn = (struct dns_server_conn_http2_stream *)owner;
				owner = &stream_conn->tls_client->tcp.head;
			}
			if ((owner != conn && request->conn != conn) ||
				(reset_only && (!stream_conn || !http2_stream_is_reset(stream_conn->stream)))) { j++; continue; }
			/* Drop only this connection's interest; surviving waiters retain the
			 * shared operation. Prevent deletion from synthesizing a late reply. */
			atomic_set(&request->notified, 1);
			client_release(op->waiter_clients[j], 0);
			memmove(&op->waiter_clients[j], &op->waiter_clients[j + 1], (op->waiter_count - j - 1) * sizeof(op->waiter_clients[0]));
			memmove(&op->waiters[j], &op->waiters[j + 1], (op->waiter_count - j - 1) * sizeof(op->waiters[0]));
			op->waiters[--op->waiter_count] = NULL;
			_dns_server_request_release_complete(request, 0);
		}
		if (!op->terminal && op->waiter_count == 0) finish(op, NULL, -1);
		pthread_mutex_unlock(&op->lock); operation_put(op);
	}
}

void _dns_server_any_cancel_connection(struct dns_server_conn_head *conn)
{
	cancel_waiters(conn, 0);
}

void _dns_server_any_cancel_http2_resets(struct dns_server_conn_tls_client *conn)
{
	/* Called after HTTP/2 polling, outside the HTTP/2 context mutex. A consumed
	 * request's END_STREAM is ordinary and does not mean the client canceled. */
	cancel_waiters(&conn->tcp.head, 1);
}
