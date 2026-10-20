/* Bounded ANY cache/singleflight and explicit finite typed fallback.
 * Ordinary A/AAAA never enter this module. */
#include "any.h"
#include "context.h"
#include "request.h"
#include "server_http2.h"
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
	int type, started, ended, has_result;
	unsigned long received;
	int len;
	unsigned char data[DNS_IN_PACKSIZE];
};
struct any_operation {
	atomic_t refs;
	pthread_mutex_t lock;
	struct any_key key;
	struct dns_query_budget *budget;
	struct dns_request *waiters[ANY_WAITERS_MAX];
	int waiter_clients[ANY_WAITERS_MAX];
	int owner_client;
	int waiter_count, terminal, table_slot, active, next, completed, expanded;
	int final_len;
	unsigned long finished;
	unsigned char final_wire[DNS_IN_PACKSIZE];
	struct any_child children[DNS_ANY_MAX_TYPES + 1];
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
 * context stays transparent; it never receives guessed shared/synthesized data. */
static int eligible(struct dns_request *request, const char *route)
{
	struct dns_conf_ipset_nftset no_ipset = {0};
	if (memcmp(&request->conf->ipset_nftset, &no_ipset, sizeof(no_ipset))) return 0;
	for (int i = 0; i < dns_conf.server_num; i++) if (dns_conf.servers[i].result_flag) return 0;
	if (request->server_flags & BIND_FLAG_NO_CACHE) return 0;
	if (request->qclass != DNS_C_IN || request->any_do || request->any_cd || request->any_ad ||
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
	if (len > 0) cache_result(&op->key, wire, len);
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
	for (int i = 0; i < op->key.config.type_count; i++) {
		struct any_child *child = &op->children[i + 1];
		input[i].qtype = child->type;
		if (child->has_result) {
			input[i].data = child->data; input[i].len = child->len; input[i].age = elapsed(child->received);
		} else tlog(TLOG_DEBUG, "ANY aggregate has no result for configured type %d", child->type);
	}
	int len = dns_any_merge(op->key.domain, input, op->key.config.type_count, op->key.config.partial, wire, sizeof(wire));
	if (len < 0) {
		tlog(TLOG_DEBUG, "ANY aggregate failed validation or has no usable configured result");
		len = dns_any_empty_response(op->key.domain, DNS_RC_SERVFAIL, 0, wire, sizeof(wire));
	}
	else {
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

static void schedule(struct any_operation *op)
{
	if (op->terminal) return;
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
	if (request->qtype != DNS_T_ANY || !eligible(request, route)) return -1;
	safe_strncpy(key.domain, request->domain, sizeof(key.domain));
	safe_strncpy(key.route, route, sizeof(key.route));
	safe_strncpy(key.rule_group, request->dns_group_name, sizeof(key.rule_group));
	key.conf = request->conf; key.server_flags = request->server_flags; key.config = request->conf->any;
	key.qtype = DNS_T_ANY;
	cached_len = cache_lookup(&key, cached);
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
			if (same_key(&operations[i]->key, &key)) { op = operations[i]; operation_get(op); break; }
		}
		if (!op && budget && free_slot >= 0 && atomic_read(&any_allocated) < ANY_ACTIVE_MAX &&
			clients[client_index].operations < ANY_CLIENT_OPERATIONS) {
			op = calloc(1, sizeof(*op));
			if (op) {
				atomic_inc(&any_allocated);
				pthread_mutexattr_t attr;
				pthread_mutexattr_init(&attr); pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
				pthread_mutex_init(&op->lock, &attr); pthread_mutexattr_destroy(&attr);
				atomic_set(&op->refs, 2); /* table plus this call */
				op->key = key; op->table_slot = free_slot;
				op->budget = budget; budget = NULL;
				for (int j = 0; j <= key.config.type_count; j++) {
					op->children[j].owner = op;
					op->children[j].type = j ? key.config.types[j - 1] : DNS_T_ANY;
				}
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
