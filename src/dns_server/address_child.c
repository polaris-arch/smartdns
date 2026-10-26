/* Bounded adapter for two independent ordinary A/AAAA requests. This is not the
 * public dns_result API and does not use the single CNAME parent/child slot. */
#include "address_child.h"
#include "any.h"
#include "dns_server.h"
#include "request.h"
#include "rules.h"
#include "ipset_nftset.h"
#include "smartdns/dns_any.h"
#include "smartdns/dns_client.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define ADDRESS_EVIDENCE_MAX 8
struct dns_address_evidence {
	int len;
	enum dns_address_child_result result;
	unsigned long received;
	unsigned char data[DNS_IN_PACKSIZE];
};

struct dns_address_child_state {
	pthread_mutex_t lock;
	dns_address_child_callback callback;
	void *arg;
	int reported, policy, evidence_overflow, upstream_seen, cache_positive, local_result, rebased;
	enum dns_address_child_result result;
	int evidence_count;
	struct dns_address_evidence evidence[ADDRESS_EVIDENCE_MAX];
};

/* A small fixed-size proof set, distinct from address-child observer custody.
 * Native selection can combine addresses from multiple positive upstreams.
 * It must not launder TC or Additional-only data into a trusted cache entry. */
struct dns_address_cache_origin {
	pthread_mutex_t lock;
	int invalid, seen, count;
	unsigned char addresses[DNS_ANY_MAX_RECORDS][DNS_RR_AAAA_LEN];
};

/* The native cache already keys the domain, family, rule-group name and bind
 * flags. Domain rules are immutable within a configuration lifetime and are
 * resolved from that domain and effective rule group. Attest the additional
 * effective group object and selected upstream route, without a lossy hash or
 * client-address key that fragments identical policies. Client rules resolve
 * into the group and bind flags before this hook. Config reload is a restart;
 * disk-loaded cache entries deliberately have no process-local attestation.
 * Registry exhaustion only disables reuse. IDs are never recycled. */
#define ADDRESS_CACHE_MAX_VIEWS 1024
static struct {
	const struct dns_conf_group *conf;
	const struct nftset_ipset_rules *bind_sets;
	unsigned int flags;
	unsigned int token;
	char route[DNS_GROUP_NAME_LEN];
} cache_views[ADDRESS_CACHE_MAX_VIEWS];
static unsigned int cache_view_count;
static unsigned int cache_view_sequence;
static pthread_mutex_t cache_view_lock = PTHREAD_MUTEX_INITIALIZER;

void _dns_server_address_cache_views_reset(void)
{
	/* Called before a new server lifetime, never during live resolution.
	 * Discard borrowed configuration identities, without recycling tokens. */
	pthread_mutex_lock(&cache_view_lock);
	cache_view_count = 0;
	pthread_mutex_unlock(&cache_view_lock);
}

static int same_name(const char *a, const char *b)
{
	return a == b || (a && b && !strcmp(a, b));
}

static int same_ipsets(const struct dns_ipset_rule *a, const struct dns_ipset_rule *b)
{
	while (a && b) {
		if (!same_name(a->ipsetname, b->ipsetname)) return 0;
		a = a->next; b = b->next;
	}
	return a == b;
}

static int same_nftsets(const struct dns_nftset_rule *a, const struct dns_nftset_rule *b)
{
	while (a && b) {
		if (!same_name(a->familyname,b->familyname) || !same_name(a->nfttablename,b->nfttablename) ||
			!same_name(a->nftsetname,b->nftsetname)) return 0;
		a = a->next; b = b->next;
	}
	return a == b;
}

static int same_bind_sets(const struct nftset_ipset_rules *a, const struct nftset_ipset_rules *b)
{
	return a == b || (a && b && same_ipsets(a->ipset,b->ipset) &&
		same_ipsets(a->ipset_ip,b->ipset_ip) && same_ipsets(a->ipset_ip6,b->ipset_ip6) &&
		same_nftsets(a->nftset_ip,b->nftset_ip) && same_nftsets(a->nftset_ip6,b->nftset_ip6));
}

unsigned int _dns_server_address_cache_view(struct dns_request *request, const char *route)
{
	if (request->conf->any.aggregate != DNS_ANY_ADDRESS || dns_conf.cachesize <= 0 ||
		(request->qtype != DNS_T_A && request->qtype != DNS_T_AAAA) ||
		request->no_cache || (request->server_flags & BIND_FLAG_NO_CACHE) ||
		request->parent_request || request->domain_rule.rules[DOMAIN_RULE_CNAME] ||
		!_dns_server_native_address_context(request, route)) return 0;
	if (!route) route = DNS_SERVER_GROUP_DEFAULT;
	const struct nftset_ipset_rules *bind_sets = _dns_server_get_bind_ipset_context(request);
	unsigned int i, view = 0;
	pthread_mutex_lock(&cache_view_lock);
	for (i = 0; i < cache_view_count; i++)
		if (cache_views[i].conf == request->conf && same_bind_sets(cache_views[i].bind_sets,bind_sets) &&
			cache_views[i].flags == request->server_flags &&
			!strcmp(cache_views[i].route, route)) break;
	if (i == cache_view_count && i < ADDRESS_CACHE_MAX_VIEWS && cache_view_sequence < (UINT_MAX >> 2)) {
		cache_views[i].conf = request->conf;
		cache_views[i].bind_sets = bind_sets;
		cache_views[i].flags = request->server_flags;
		cache_views[i].token = (++cache_view_sequence << 2) | DNS_CACHE_ORIGIN_NATIVE_VIEW;
		safe_strncpy(cache_views[i].route, route, sizeof(cache_views[i].route));
		cache_view_count++;
	}
	if (i < cache_view_count) view = cache_views[i].token;
	pthread_mutex_unlock(&cache_view_lock);
	return view;
}

static uint32_t age_seconds(unsigned long received)
{
	unsigned long ms = get_tick_count() - received;
	unsigned long age = ms / 1000;
	return age > UINT32_MAX ? UINT32_MAX : age;
}

/* dns_any_merge validates the correlated question, complete supported RDATA,
 * coherent CNAME ownership and zone-enclosing SOA. Its normalized question is
 * uncompressed; restore the typed question before retaining that evidence. */
static int restore_question_type(unsigned char *wire, int len, dns_type_t qtype)
{
	int off = 12;
	while (off < len && wire[off]) {
		int size = wire[off];
		if (size > 63 || off + size + 1 >= len) return -1;
		off += size + 1;
	}
	if (++off + 4 > len) return -1;
	wire[off] = qtype >> 8;
	wire[off + 1] = qtype;
	return 0;
}

static int normalize(struct dns_request *request, const struct dns_any_input *input, int count,
					 unsigned char *wire, enum dns_address_child_result *result)
{
	int len = dns_any_merge(request->domain, input, count, 0, wire, DNS_IN_PACKSIZE);
	if (len < 0 || restore_question_type(wire, len, request->qtype)) return -1;
	*result = (wire[3] & 15) == DNS_RC_NXDOMAIN ? DNS_ADDRESS_CHILD_NXDOMAIN :
		(wire[8] || wire[9]) ? DNS_ADDRESS_CHILD_NODATA : DNS_ADDRESS_CHILD_POSITIVE;
	return len;
}

static int normalize_one(struct dns_request *request, const unsigned char *wire, int len,
						 unsigned char *out, enum dns_address_child_result *result)
{
	struct dns_any_input input = { .data = wire, .len = len, .qtype = request->qtype, .age = 0 };
	return normalize(request, &input, 1, out, result);
}

static int cache_origin_addresses(struct dns_request *request, const unsigned char *wire, int len,
								  unsigned char addresses[DNS_ANY_MAX_RECORDS][DNS_RR_AAAA_LEN])
{
	if (len < 12 || (wire[3] & 0x10)) return -1;
	int direct = dns_any_plain_addresses(request->domain, request->qtype, wire, len, addresses);
	if (direct > 0) return direct;
	unsigned char normalized[DNS_IN_PACKSIZE];
	enum dns_address_child_result result;
	int size = normalize_one(request, wire, len, normalized, &result);
	if (size < 0 || result != DNS_ADDRESS_CHILD_POSITIVE) return -1;
	if (request->conf->dns_force_no_cname)
		size = _dns_server_any_flatten_addresses(request->domain, request->qtype, normalized, size);
	if (size < 0) return -1;
	/* A visible native CNAME shortcut has no retained complete chain. Keep
	 * resolving that family independently instead of guessing provenance. */
	return dns_any_plain_addresses(request->domain, request->qtype, normalized, size, addresses);
}

void _dns_server_address_cache_prepare(struct dns_request *request)
{
	if (!request->cache_origin_view || request->cache_origin || dns_conf.cachesize <= 0) return;
	request->cache_origin = calloc(1, sizeof(*request->cache_origin));
	if (request->cache_origin && pthread_mutex_init(&request->cache_origin->lock, NULL)) {
		free(request->cache_origin);
		request->cache_origin = NULL;
	}
	/* Allocation failure only disables address reuse, never ordinary lookup. */
}

void _dns_server_address_cache_upstream(struct dns_request *request, const unsigned char *wire, int len)
{
	struct dns_address_cache_origin *origin = request->cache_origin;
	unsigned char addresses[DNS_ANY_MAX_RECORDS][DNS_RR_AAAA_LEN];
	if (!origin) return;
	int count = cache_origin_addresses(request, wire, len, addresses);
	pthread_mutex_lock(&origin->lock);
	origin->seen = 1;
	/* A failed/truncated peer does not discredit a different complete source.
	 * Every finalized selected address must still occur in a complete proof. */
	for (int i = 0; !origin->invalid && i < count; i++) {
		int found = 0;
		for (int j = 0; j < origin->count; j++)
			if (!memcmp(addresses[i], origin->addresses[j], DNS_RR_AAAA_LEN)) { found = 1; break; }
		if (found) continue;
		if (origin->count == DNS_ANY_MAX_RECORDS) { origin->invalid = 1; break; }
		memcpy(origin->addresses[origin->count++], addresses[i], DNS_RR_AAAA_LEN);
	}
	pthread_mutex_unlock(&origin->lock);
}

int _dns_server_address_cache_proven(struct dns_request *request, const unsigned char *wire, int len)
{
	struct dns_address_cache_origin *origin = request->cache_origin;
	unsigned char addresses[DNS_ANY_MAX_RECORDS][DNS_RR_AAAA_LEN];
	if (!origin) return 0;
	int count = cache_origin_addresses(request, wire, len, addresses);
	if (count < 1) return 0;
	pthread_mutex_lock(&origin->lock);
	int proven = origin->seen && !origin->invalid;
	for (int i = 0; proven && i < count; i++) {
		int found = 0;
		for (int j = 0; j < origin->count; j++)
			if (!memcmp(addresses[i], origin->addresses[j], DNS_RR_AAAA_LEN)) { found = 1; break; }
		if (!found) proven = 0;
	}
	pthread_mutex_unlock(&origin->lock);
	return proven;
}

static struct dns_address_child_state *state_new(void)
{
	struct dns_address_child_state *state = calloc(1, sizeof(*state));
	if (!state) return NULL;
	pthread_mutex_init(&state->lock, NULL);
	state->result = DNS_ADDRESS_CHILD_FAILURE;
	return state;
}

static void copy_context(struct dns_request *child, const struct dns_request *parent)
{
	/* Preserve the resolved client context without retaining its connection:
	 * an internal typed child must never write a separate client response. */
	memcpy(&child->in6, &parent->in6, sizeof(child->in6));
	child->addr_len = parent->addr_len;
	child->ss_family = parent->ss_family;
	child->localaddr = parent->localaddr;
	memcpy(child->mac, parent->mac, sizeof(child->mac));
	child->no_cache = parent->no_cache;
	child->no_ipalias = parent->no_ipalias;
	child->no_serve_expired = parent->no_serve_expired;
	child->inherited_bind_sets = _dns_server_get_bind_ipset_context(parent);
	child->has_ecs = parent->has_ecs;
	child->ecs = parent->ecs;
	child->edns0_do = parent->edns0_do;
	child->any_do = parent->any_do;
	child->any_cd = parent->any_cd;
	child->any_ad = parent->any_ad;
	child->any_rd = parent->any_rd;
	child->any_unknown_context = parent->any_unknown_context;
	child->any_unsupported_context = parent->any_unsupported_context;
}

int _dns_server_address_child_inherit(struct dns_request *child, const struct dns_request *parent)
{
	if (parent->address_child) {
		child->address_child = state_new();
		if (!child->address_child) return -1;
		copy_context(child, parent);
		child->prefetch_flags |= PREFETCH_FLAGS_NO_DUALSTACK | PREFETCH_FLAGS_NOPREFETCH;
	}
	if (parent->query_budget) {
		child->query_budget = parent->query_budget;
		dns_query_budget_get(child->query_budget);
	}
	return 0;
}

int _dns_server_address_child_start(const struct dns_request *parent, dns_type_t qtype,
								  struct dns_query_budget *budget, dns_address_child_callback callback, void *arg)
{
	struct dns_request *request;
	struct dns_address_child_state *state;
	if (!parent || !budget || !callback || (qtype != DNS_T_A && qtype != DNS_T_AAAA)) return -1;
	state = state_new();
	if (!state) return -1;
	request = _dns_server_new_request();
	if (!request) {
		pthread_mutex_destroy(&state->lock);
		free(state);
		return -1;
	}
	state->callback = callback;
	state->arg = arg;
	request->address_child = state;
	request->query_budget = budget;
	dns_query_budget_get(budget);
	request->server_flags = parent->server_flags;
	request->conf = parent->conf;
	safe_strncpy(request->dns_group_name, parent->dns_group_name, sizeof(request->dns_group_name));
	safe_strncpy(request->domain, parent->domain, sizeof(request->domain));
	request->qtype = qtype;
	request->qclass = parent->qclass;
	/* Cache admission below is independently fresh-only; retain the normal
	 * reply-TTL policy instead of changing it via no_serve_expired. */
	copy_context(request, parent);
	request->prefetch_flags = PREFETCH_FLAGS_NO_DUALSTACK | PREFETCH_FLAGS_NOPREFETCH;
    request->prefetch_origin_flags = parent->prefetch_origin_flags;
    request->prefetch_queue_wait_ms = parent->prefetch_queue_wait_ms;
	/* No connection and no parent_request: neither child can reply directly or
	 * overwrite a sibling. Native references retain it after this launch ref. */
	int ret = _dns_server_do_query(request, 0);
	_dns_server_request_release_complete(request, ret != 0);
	return 0;
}

int _dns_server_address_child_check_context(struct dns_request *request, const char *route)
{
	struct dns_address_child_state *state = request->address_child;
	if (!state) return 0;
	request->cache_origin_view = _dns_server_address_cache_view(request, route);
	if (!_dns_server_any_address_context(request, route)) {
		state->policy = 1;
		return -1;
	}
	return 0;
}

int _dns_server_address_child_cache_allowed(struct dns_request *request)
{
	return request->address_child && request->cache_origin_view && !request->no_cache;
}

/* Called only at native local-address / explicit SOA policy decisions, never
 * by transport errors, negative caches or synthesized timeout fallbacks. */
void _dns_server_address_child_local_result(struct dns_request *request)
{
	struct dns_address_child_state *state = request->address_child;
	if (!state) return;
	pthread_mutex_lock(&state->lock);
	state->local_result = 1;
	pthread_mutex_unlock(&state->lock);
}

void _dns_server_address_child_upstream(struct dns_request *request, const unsigned char *wire, int len)
{
	struct dns_address_child_state *state = request->address_child;
	unsigned char normalized[DNS_IN_PACKSIZE], combined[DNS_IN_PACKSIZE];
	enum dns_address_child_result result;
	if (!state) return;
	pthread_mutex_lock(&state->lock);
	state->upstream_seen = 1;
	pthread_mutex_unlock(&state->lock);
	int size = normalize_one(request, wire, len, normalized, &result);
	if (size < 0) return; /* failures/truncation never establish negative proof */
	pthread_mutex_lock(&state->lock);
	for (int i = 0; i < state->evidence_count; i++) {
		struct dns_address_evidence *proof = &state->evidence[i];
		struct dns_any_input input[2] = {
			{proof->data, proof->len, request->qtype, age_seconds(proof->received)},
			{normalized, size, request->qtype, 0},
		};
		enum dns_address_child_result merged_result;
		int merged = normalize(request, input, 2, combined, &merged_result);
		if (merged < 0) continue;
		memcpy(proof->data, combined, merged);
		proof->len = merged; proof->result = merged_result; proof->received = get_tick_count();
		pthread_mutex_unlock(&state->lock);
		return;
	}
	if (state->evidence_count == ADDRESS_EVIDENCE_MAX) state->evidence_overflow = 1;
	else {
		struct dns_address_evidence *proof = &state->evidence[state->evidence_count++];
		memcpy(proof->data, normalized, size);
		proof->len = size; proof->result = result; proof->received = get_tick_count();
	}
	pthread_mutex_unlock(&state->lock);
}

/* A native configured alias is trusted policy, but the target's upstream
 * evidence must keep its original full chain and negative authority. */
static int rebase_evidence(struct dns_request *request, struct dns_request *from,
						   const struct dns_address_evidence *source, struct dns_address_evidence *dest)
{
	unsigned char wire[DNS_IN_PACKSIZE], packet_buf[DNS_PACKSIZE], output_buf[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buf;
	struct dns_packet *output = (struct dns_packet *)output_buf;
	memcpy(wire, source->data, source->len);
	if (request->qtype != from->qtype ||
		dns_any_wire_age(wire, source->len, age_seconds(source->received), NULL) ||
		dns_decode(packet, sizeof(packet_buf), wire, source->len)) return -1;
	struct dns_head head = packet->head;
	if (dns_packet_init(output, sizeof(output_buf), &head) ||
		dns_add_domain(output, request->domain, request->qtype, request->qclass) ||
		dns_add_CNAME(output, DNS_RRS_AN, request->domain,
			_dns_server_get_conf_ttl(request, from->ip_ttl), from->domain)) return -1;
	int count = 0;
	struct dns_rrs *rr = dns_get_rrs_start(packet, DNS_RRS_AN, &count);
	for (int i = 0; rr && i < count; i++, rr = dns_get_rrs_next(packet, rr)) {
		char owner[DNS_MAX_CNAME_LEN], target[DNS_MAX_CNAME_LEN];
		unsigned char address[DNS_RR_AAAA_LEN];
		int ttl, ret;
		if (rr->type == DNS_T_CNAME) {
			if (dns_get_CNAME(rr, owner, sizeof(owner), &ttl, target, sizeof(target)) ||
				dns_add_CNAME(output, DNS_RRS_AN, owner, ttl, target)) return -1;
			continue;
		}
		if (rr->type != request->qtype) return -1;
		ret = rr->type == DNS_T_A ? dns_get_A(rr, owner, sizeof(owner), &ttl, address) :
			dns_get_AAAA(rr, owner, sizeof(owner), &ttl, address);
		if (ret) return -1;
		ret = rr->type == DNS_T_A ? dns_add_A(output, DNS_RRS_AN, owner, ttl, address) :
			dns_add_AAAA(output, DNS_RRS_AN, owner, ttl, address);
		if (ret) return -1;
	}
	rr = dns_get_rrs_start(packet, DNS_RRS_NS, &count);
	for (int i = 0; rr && i < count; i++, rr = dns_get_rrs_next(packet, rr)) {
		char owner[DNS_MAX_CNAME_LEN];
		struct dns_soa soa;
		int ttl;
		if (rr->type != DNS_T_SOA || dns_get_SOA(rr, owner, sizeof(owner), &ttl, &soa) ||
			dns_add_SOA(output, DNS_RRS_NS, owner, ttl, &soa)) return -1;
	}
	int len = dns_encode(wire, sizeof(wire), output);
	if (len < 0) return -1;
	len = normalize_one(request, wire, len, dest->data, &dest->result);
	if (len <= 0) { dest->len = 0; return -1; }
	dest->len = len;
	dest->received = get_tick_count();
	return dest->len > 0 ? 0 : -1;
}

void _dns_server_address_child_copy(struct dns_request *request, struct dns_request *from)
{
	struct dns_address_child_state *dest = request->address_child, *source = from->address_child;
	if (!dest || !source) return;
	/* Existing nested CNAME custody is a one-way child -> parent relation. */
	pthread_mutex_lock(&source->lock);
	pthread_mutex_lock(&dest->lock);
	dest->policy |= source->policy;
	dest->evidence_overflow |= source->evidence_overflow;
	dest->upstream_seen |= source->upstream_seen;
	dest->local_result |= source->local_result;
	if (source->evidence_count) {
		int rebase = strcasecmp(request->domain, from->domain) != 0;
		struct dns_cname_rule *alias = _dns_server_get_dns_rule(request, DOMAIN_RULE_CNAME);
		if (rebase && (!alias || strcasecmp(alias->cname, from->domain))) dest->policy = 1;
		else {
			dest->evidence_count = source->evidence_count;
			for (int i = 0; i < source->evidence_count; i++) {
				if (rebase) {
     if (rebase_evidence(request, from, &source->evidence[i], &dest->evidence[i])) dest->policy = 1;
     dest->rebased = 1;
				} else dest->evidence[i] = source->evidence[i];
			}
		}
	} else if (source->cache_positive) {
		/* A local alias cannot import an unattested cached target as wire proof. */
		dest->policy = 1;
	}
	pthread_mutex_unlock(&dest->lock);
	pthread_mutex_unlock(&source->lock);
}

int _dns_server_address_child_cache_positive(struct dns_request *request, unsigned char *wire, int *len, int ttl_cap)
{
	unsigned char normalized[DNS_IN_PACKSIZE];
	unsigned char packet_buf[DNS_PACKSIZE], output_buf[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buf;
	struct dns_packet *output = (struct dns_packet *)output_buf;
	enum dns_address_child_result result;
	if (!request->address_child) return 0;
	/* The caller already checked the atomic plain-origin cache snapshot.
	 * Also validate its actual packet. Negatives, including locally forced
	 * SOA, still cannot be imported as upstream absence evidence. */
	if (*len < 12 || ttl_cap <= 0 || (wire[3] & 0x30)) return -1;
	int normalized_len = normalize_one(request, wire, *len, normalized, &result);
	if (normalized_len < 0 ||
		result != DNS_ADDRESS_CHILD_POSITIVE) return -1;
	if (dns_decode(packet, sizeof(packet_buf), normalized, normalized_len)) return -1;
	struct dns_head head = packet->head;
	if (dns_packet_init(output, sizeof(output_buf), &head) ||
		dns_add_domain(output, request->domain, request->qtype, request->qclass)) return -1;
	int count = 0;
	struct dns_rrs *rr = dns_get_rrs_start(packet, DNS_RRS_AN, &count);
	for (int i = 0; rr && i < count; i++, rr = dns_get_rrs_next(packet, rr)) {
		/* A legacy cached CNAME might be a shortcut over several original
		 * aliases. Its provenance is unavailable, so refetch this family. */
		if (rr->type == DNS_T_CNAME) return -1;
		char owner[DNS_MAX_CNAME_LEN];
		unsigned char address[DNS_RR_AAAA_LEN];
		int ttl, ret;
		ret = request->qtype == DNS_T_A ? dns_get_A(rr, owner, sizeof(owner), &ttl, address) :
			dns_get_AAAA(rr, owner, sizeof(owner), &ttl, address);
		if (ret) return -1;
		if (ttl > ttl_cap) ttl = ttl_cap;
		ret = request->qtype == DNS_T_A ? dns_add_A(output, DNS_RRS_AN, owner, ttl, address) :
			dns_add_AAAA(output, DNS_RRS_AN, owner, ttl, address);
		if (ret) return -1;
	}
	*len = dns_encode(wire, DNS_IN_PACKSIZE, output);
	if (*len < 0) return -1;
	pthread_mutex_lock(&request->address_child->lock);
	request->address_child->cache_positive = 1;
	pthread_mutex_unlock(&request->address_child->lock);
	return 0;
}

static int terminal_name(struct dns_packet *packet, const char *domain, char *terminal, int *cname_ttl)
{
	safe_strncpy(terminal, domain, DNS_MAX_CNAME_LEN);
	*cname_ttl = INT_MAX;
	for (int depth = 0; depth <= DNS_ANY_MAX_ALIAS; depth++) {
		int count = 0, found = 0;
		struct dns_rrs *rr = dns_get_rrs_start(packet, DNS_RRS_AN, &count);
		for (int i = 0; rr && i < count; i++, rr = dns_get_rrs_next(packet, rr)) {
			char owner[DNS_MAX_CNAME_LEN], target[DNS_MAX_CNAME_LEN];
			int ttl;
			if (rr->type != DNS_T_CNAME) continue;
			if (dns_get_CNAME(rr, owner, sizeof(owner), &ttl, target, sizeof(target))) return -1;
			if (strcasecmp(owner, terminal)) continue;
			if (depth == DNS_ANY_MAX_ALIAS) return -1;
			safe_strncpy(terminal, target, DNS_MAX_CNAME_LEN);
			if (ttl < *cname_ttl) *cname_ttl = ttl;
			found = 1;
			break;
		}
		if (!found) return 0;
	}
	return -1;
}

static int same_soa(const struct dns_soa *a, const struct dns_soa *b)
{
	return !strcasecmp(a->mname, b->mname) && !strcasecmp(a->rname, b->rname) &&
		a->serial == b->serial && a->refresh == b->refresh && a->retry == b->retry &&
		a->expire == b->expire && a->minimum == b->minimum;
}

static int copy_cnames(struct dns_packet *dest, struct dns_packet *evidence, int reply_ttl)
{
	int count = 0;
	struct dns_rrs *rr = dns_get_rrs_start(evidence, DNS_RRS_AN, &count);
	for (int i = 0; rr && i < count; i++, rr = dns_get_rrs_next(evidence, rr)) {
		char owner[DNS_MAX_CNAME_LEN], target[DNS_MAX_CNAME_LEN];
		int ttl;
		if (rr->type != DNS_T_CNAME) continue;
		if (dns_get_CNAME(rr, owner, sizeof(owner), &ttl, target, sizeof(target))) return -1;
		if (ttl > reply_ttl) ttl = reply_ttl;
		if (dns_add_CNAME(dest, DNS_RRS_AN, owner, ttl, target)) return -1;
	}
	return 0;
}

static int address_in_evidence(struct dns_packet *evidence, dns_type_t qtype, const char *owner,
							  const unsigned char *address)
{
	int count = 0;
	struct dns_rrs *rr = dns_get_rrs_start(evidence, DNS_RRS_AN, &count);
	for (int i = 0; rr && i < count; i++, rr = dns_get_rrs_next(evidence, rr)) {
		char name[DNS_MAX_CNAME_LEN];
		unsigned char value[DNS_RR_AAAA_LEN];
		int ttl, ret;
		if (rr->type != qtype) continue;
		ret = qtype == DNS_T_A ? dns_get_A(rr, name, sizeof(name), &ttl, value) :
			dns_get_AAAA(rr, name, sizeof(name), &ttl, value);
		if (!ret && !strcasecmp(owner, name) &&
			!memcmp(address, value, qtype == DNS_T_A ? DNS_RR_A_LEN : DNS_RR_AAAA_LEN)) return 1;
	}
	return 0;
}

static int chain_contains(struct dns_packet *packet, const char *name, const char *domain)
{
	if (!strcasecmp(name, domain)) return 1;
	int count = 0;
	struct dns_rrs *rr = dns_get_rrs_start(packet, DNS_RRS_AN, &count);
	for (int i = 0; rr && i < count; i++, rr = dns_get_rrs_next(packet, rr)) {
		char owner[DNS_MAX_CNAME_LEN], target[DNS_MAX_CNAME_LEN];
		int ttl;
		if (rr->type == DNS_T_CNAME &&
			!dns_get_CNAME(rr, owner, sizeof(owner), &ttl, target, sizeof(target)) &&
			(!strcasecmp(owner, name) || !strcasecmp(target, name))) return 1;
	}
	return 0;
}

/* Native speed selection may collapse CNAMEs and rewrite SOA owners. Retain
 * the ordinary selected addresses and finalized address TTLs, but reconstruct
 * their proven full chain / original negative SOA, never raw unselected IPs. */
static int preserve_evidence(struct dns_request *request, const unsigned char *wire, int len,
							 unsigned char *out, enum dns_address_child_result *result, const struct dns_address_evidence *proof)
{
	struct dns_address_child_state *state = request->address_child;
	unsigned char native_wire[DNS_IN_PACKSIZE], evidence_wire[DNS_IN_PACKSIZE];
	unsigned char native_buf[DNS_PACKSIZE], evidence_buf[DNS_PACKSIZE], output_buf[DNS_PACKSIZE];
	struct dns_packet *native = (struct dns_packet *)native_buf;
	struct dns_packet *evidence = (struct dns_packet *)evidence_buf;
	struct dns_packet *output = (struct dns_packet *)output_buf;
	char native_terminal[DNS_MAX_CNAME_LEN], evidence_terminal[DNS_MAX_CNAME_LEN];
	int native_cname_ttl, evidence_cname_ttl;
	int native_len = normalize_one(request, wire, len, native_wire, result);
	if (native_len < 0) return -1;
	if (!proof) {
		if (state->upstream_seen) return -1;
		if (!state->cache_positive || *result != DNS_ADDRESS_CHILD_POSITIVE) {
			*result = DNS_ADDRESS_CHILD_POLICY;
			return -1;
		}
		memcpy(out, wire, len);
		return len;
	}
	if (*result != proof->result) return -1;
	memcpy(evidence_wire, proof->data, proof->len);
	if (dns_any_wire_age(evidence_wire, proof->len, age_seconds(proof->received), NULL) ||
		dns_decode(native, sizeof(native_buf), native_wire, native_len) ||
		dns_decode(evidence, sizeof(evidence_buf), evidence_wire, proof->len) ||
		terminal_name(native, request->domain, native_terminal, &native_cname_ttl) ||
		terminal_name(evidence, request->domain, evidence_terminal, &evidence_cname_ttl)) return -1;
	/* Native configured-CNAME callbacks may collapse the target's subsequent
	 * aliases too. Only map a selected address through the proven chain. */
	int flattened = (request->conf->dns_force_no_cname && !strcasecmp(native_terminal, request->domain)) ||
		(state->rebased && chain_contains(evidence, native_terminal, request->domain));
	if (!flattened && strcasecmp(native_terminal, evidence_terminal)) return -1;
	struct dns_head head = native->head;
	head.id = request->id;
	head.aa = head.ad = head.cd = 0;
	if (dns_packet_init(output, sizeof(output_buf), &head) ||
		dns_add_domain(output, request->domain, request->qtype, request->qclass) ||
		copy_cnames(output, evidence, native_cname_ttl)) return -1;
	int count = 0;
	if (*result == DNS_ADDRESS_CHILD_POSITIVE) {
		struct dns_rrs *rr = dns_get_rrs_start(native, DNS_RRS_AN, &count);
		for (int i = 0; rr && i < count; i++, rr = dns_get_rrs_next(native, rr)) {
			char owner[DNS_MAX_CNAME_LEN];
			unsigned char address[DNS_RR_AAAA_LEN];
			int ttl, ret;
			if (rr->type != request->qtype) continue;
			ret = request->qtype == DNS_T_A ? dns_get_A(rr, owner, sizeof(owner), &ttl, address) :
				dns_get_AAAA(rr, owner, sizeof(owner), &ttl, address);
			const char *proven_owner = flattened ? evidence_terminal : owner;
			if (ret || !address_in_evidence(evidence, request->qtype, proven_owner, address)) return -1;
			ret = request->qtype == DNS_T_A ? dns_add_A(output, DNS_RRS_AN, proven_owner, ttl, address) :
				dns_add_AAAA(output, DNS_RRS_AN, proven_owner, ttl, address);
			if (ret) return -1;
		}
	} else {
		struct dns_soa native_soa = {0}, source_soa = {0};
		char native_owner[DNS_MAX_CNAME_LEN], source_owner[DNS_MAX_CNAME_LEN];
		int native_ttl = 0, source_ttl = 0;
		struct dns_rrs *nr = dns_get_rrs_start(native, DNS_RRS_NS, &count);
		if (!nr || count != 1 || nr->type != DNS_T_SOA ||
			dns_get_SOA(nr, native_owner, sizeof(native_owner), &native_ttl, &native_soa)) return -1;
		struct dns_rrs *sr = dns_get_rrs_start(evidence, DNS_RRS_NS, &count);
		if (!sr || count != 1 || sr->type != DNS_T_SOA ||
			dns_get_SOA(sr, source_owner, sizeof(source_owner), &source_ttl, &source_soa) ||
			!same_soa(&native_soa, &source_soa)) return -1;
		if (source_ttl > native_ttl) source_ttl = native_ttl;
		if (dns_add_SOA(output, DNS_RRS_NS, source_owner, source_ttl, &source_soa)) return -1;
	}
	return dns_encode(out, DNS_IN_PACKSIZE, output);
}

static int flattened_positive(struct dns_request *request, const unsigned char *wire, int len,
                              unsigned char *out, enum dns_address_child_result *result)
{
	struct dns_address_child_state *state = request->address_child;
	unsigned char native_wire[DNS_IN_PACKSIZE], native_buf[DNS_PACKSIZE], output_buf[DNS_PACKSIZE];
	struct dns_packet *native = (struct dns_packet *)native_buf, *output = (struct dns_packet *)output_buf;
	int size = normalize_one(request, wire, len, native_wire, result);
	if (size < 0 || *result != DNS_ADDRESS_CHILD_POSITIVE || dns_decode(native, sizeof(native_buf), native_wire, size)) return -1;
	struct dns_head head = native->head;
	if (dns_packet_init(output, sizeof(output_buf), &head) ||
		dns_add_domain(output, request->domain, request->qtype, request->qclass)) return -1;
	int count = 0;
	struct dns_rrs *rr = dns_get_rrs_start(native, DNS_RRS_AN, &count);
	for (int i = 0; rr && i < count; i++, rr = dns_get_rrs_next(native, rr)) {
		char owner[DNS_MAX_CNAME_LEN]; unsigned char address[DNS_RR_AAAA_LEN]; int ttl;
		if (rr->type != request->qtype) return -1;
		int ret = rr->type == DNS_T_A ? dns_get_A(rr, owner, sizeof(owner), &ttl, address) :
			dns_get_AAAA(rr, owner, sizeof(owner), &ttl, address);
		if (ret || strcasecmp(owner, request->domain)) return -1;
		int proven = 0, alias_bound = INT_MAX;
		for (int j = 0; j < state->evidence_count; j++) {
			const struct dns_address_evidence *proof = &state->evidence[j];
			unsigned char evidence_wire[DNS_IN_PACKSIZE], evidence_buf[DNS_PACKSIZE];
			struct dns_packet *evidence = (struct dns_packet *)evidence_buf;
			char terminal[DNS_MAX_CNAME_LEN]; int cname_ttl;
			if (proof->result != DNS_ADDRESS_CHILD_POSITIVE) continue;
			memcpy(evidence_wire, proof->data, proof->len);
			if (dns_any_wire_age(evidence_wire, proof->len, age_seconds(proof->received), NULL) ||
				dns_decode(evidence, sizeof(evidence_buf), evidence_wire, proof->len) ||
				terminal_name(evidence, request->domain, terminal, &cname_ttl) ||
				!address_in_evidence(evidence, request->qtype, terminal, address)) continue;
			proven = 1;
			if (cname_ttl < alias_bound) alias_bound = cname_ttl;
		}
		if (!proven) return -1;
		if (ttl > alias_bound) ttl = alias_bound;
		ret = rr->type == DNS_T_A ? dns_add_A(output, DNS_RRS_AN, request->domain, ttl, address) :
			dns_add_AAAA(output, DNS_RRS_AN, request->domain, ttl, address);
		if (ret) return -1;
	}
	return dns_encode(out, DNS_IN_PACKSIZE, output);
}

void _dns_server_address_child_post(struct dns_server_post_context *context)
{
	struct dns_request *request = context->request;
	struct dns_address_child_state *state = request->address_child;
	unsigned char wire[DNS_IN_PACKSIZE];
	int len = -1;
	enum dns_address_child_result result = DNS_ADDRESS_CHILD_FAILURE;
	if (!state || !state->callback || !context->do_reply) return;
	pthread_mutex_lock(&state->lock);
	if (state->reported) {
		pthread_mutex_unlock(&state->lock);
		return;
	}
	state->reported = 1;
	if (state->policy) result = DNS_ADDRESS_CHILD_POLICY;
	else if (state->local_result) {
		len = normalize_one(request, context->inpacket, context->inpacket_len, wire, &result);
		if (len < 0) result = DNS_ADDRESS_CHILD_FAILURE;
		else if (result == DNS_ADDRESS_CHILD_NODATA) result = DNS_ADDRESS_CHILD_POLICY_NODATA;
	}
	else if (context->do_force_soa || request->force_soa ||
		request->dualstack_selection_force_soa) result = DNS_ADDRESS_CHILD_POLICY;
	else if (!state->evidence_overflow) {
		if (request->conf->dns_force_no_cname)
			len = flattened_positive(request, context->inpacket, context->inpacket_len, wire, &result);
		for (int i = 0; len < 0 && i < (state->evidence_count ? state->evidence_count : 1); i++) {
			len = preserve_evidence(request, context->inpacket, context->inpacket_len, wire, &result,
				state->evidence_count ? &state->evidence[i] : NULL);
		}
		if (len > 0 && request->conf->dns_force_no_cname)
			len = _dns_server_any_flatten_addresses(request->domain, request->qtype, wire, len);
		if (len < 0 && result != DNS_ADDRESS_CHILD_POLICY) result = DNS_ADDRESS_CHILD_FAILURE;
	}
	state->result = result;
	pthread_mutex_unlock(&state->lock);
	state->callback(state->arg, result, len > 0 ? wire : NULL, len > 0 ? len : 0, 0);
}

void _dns_server_address_child_release(struct dns_request *request)
{
	struct dns_address_child_state *state = request->address_child;
	if (request->cache_origin) {
		pthread_mutex_destroy(&request->cache_origin->lock);
		free(request->cache_origin);
		request->cache_origin = NULL;
	}
	if (request->query_budget) {
		dns_query_budget_put(request->query_budget);
		request->query_budget = NULL;
	}
	if (!state) return;
	if (state->callback) {
		if (!state->reported) {
			state->result = state->policy ? DNS_ADDRESS_CHILD_POLICY : DNS_ADDRESS_CHILD_FAILURE;
			state->callback(state->arg, state->result, NULL, 0, 0);
		}
		/* Last callback: the operation may free its slot and itself here. */
		state->callback(state->arg, state->result, NULL, 0, 1);
	}
	pthread_mutex_destroy(&state->lock);
	free(state);
	request->address_child = NULL;
}
