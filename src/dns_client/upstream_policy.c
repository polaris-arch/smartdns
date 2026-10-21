#define _GNU_SOURCE
#include "upstream_policy.h"
#include "group.h"
#include "client_socket.h"
#include "client_http3_control.h"
#include "conn_stream.h"
#include "server_info.h"
#include "smartdns/util.h"
#include "smartdns/dns_any.h"
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct dns_query_budget {
	pthread_mutex_t lock;
	unsigned int refs, used, limit;
	unsigned long deadline;
	int cancelled;
};

struct dns_upstream_policy {
	struct dns_upstream_policy *next;
	pthread_mutex_t lock;
    pthread_mutex_t dispatch_lock;
    struct client_dns_server_flags *rr_flags;
    dns_server_type_t rr_type;
    uint64_t rr_cursor, rr_last_id;
    unsigned int connections;
	char name[DNS_MAX_CNAME_LEN];
	unsigned int refs, rate, burst, failures;
	uint64_t tokens; /* millitokens: refill is rate * elapsed milliseconds */
	unsigned long updated, cooldown, last_error, last_warning;
	uint64_t backpressure_count;
	uint64_t recovery_epoch;
	unsigned int recovering, recovery_active;
};
static pthread_mutex_t policy_registry_lock = PTHREAD_MUTEX_INITIALIZER;
static struct dns_upstream_policy *policies;

struct dns_query_attempt {
	struct dns_query_attempt *next;
	struct dns_server_info *server;
	unsigned int sends, generation;
	unsigned long sent_tick;
	int active, wire_started, wire_reserved, replied;
    uint64_t admitted_epoch;
	uint64_t recovery_epoch;
	int recovery_held;
};

static unsigned long tick_add(unsigned long now, uint64_t delay)
{
	return delay > ULONG_MAX - now ? ULONG_MAX : now + (unsigned long)delay;
}

struct dns_query_budget *dns_query_budget_new(unsigned int max_attempts, unsigned int timeout_ms)
{
	if (!max_attempts || !timeout_ms) return NULL;
	struct dns_query_budget *b = calloc(1, sizeof(*b));
	if (!b) return NULL;
	pthread_mutex_init(&b->lock, NULL);
	b->refs = 1;
	b->limit = max_attempts;
	b->deadline = tick_add(get_tick_count(), timeout_ms);
	return b;
}
void dns_query_budget_get(struct dns_query_budget *b)
{
	if (!b) return;
	pthread_mutex_lock(&b->lock); b->refs++; pthread_mutex_unlock(&b->lock);
}
void dns_query_budget_put(struct dns_query_budget *b)
{
	if (!b) return;
	pthread_mutex_lock(&b->lock);
	int last = --b->refs == 0;
	pthread_mutex_unlock(&b->lock);
	if (last) { pthread_mutex_destroy(&b->lock); free(b); }
}
void dns_query_budget_cancel(struct dns_query_budget *b)
{
	if (!b) return;
	pthread_mutex_lock(&b->lock); b->cancelled = 1; pthread_mutex_unlock(&b->lock);
}
unsigned int dns_query_budget_remaining_ms(struct dns_query_budget *b)
{
	if (!b) return UINT_MAX;
	unsigned long now = get_tick_count();
	pthread_mutex_lock(&b->lock);
	unsigned long left = !b->cancelled && b->deadline > now ? b->deadline - now : 0;
	pthread_mutex_unlock(&b->lock);
	return left > UINT_MAX ? UINT_MAX : (unsigned int)left;
}
int dns_query_budget_exhausted(struct dns_query_budget *b)
{
	if (!b) return 0;
	pthread_mutex_lock(&b->lock);
	int done = b->cancelled || b->used >= b->limit || get_tick_count() >= b->deadline;
	pthread_mutex_unlock(&b->lock);
	return done;
}
int _dns_query_budget_take(struct dns_query_budget *b)
{
	if (!b) return 0;
	pthread_mutex_lock(&b->lock);
	int done = b->cancelled || b->used >= b->limit || get_tick_count() >= b->deadline;
	if (!done) b->used++;
	pthread_mutex_unlock(&b->lock);
	return done ? -1 : 0;
}

int _dns_policy_attach(struct dns_server_info *s)
{
    if (s->flags.upstream_round_robin) {
        if (!s->flags.quota_group[0]) return -1;
        if (!s->flags.max_upstream_connections) s->flags.max_upstream_connections = 2;
        if (s->flags.max_upstream_connections > 4) return -1;
    } else if (s->flags.max_upstream_connections) return -1;
    if (s->flags.max_query_rate && !s->flags.query_burst) s->flags.query_burst = 1;
	struct dns_upstream_policy *p;
	pthread_mutex_lock(&policy_registry_lock);
	for (p = policies; p; p = p->next) {
		if (!s->flags.quota_group[0] || strcmp(p->name, s->flags.quota_group)) continue;
		if (p->rate != s->flags.max_query_rate || p->burst != s->flags.query_burst ||
            !!p->rr_flags != !!s->flags.upstream_round_robin ||
            (s->flags.upstream_round_robin && (p->rr_type != s->type ||
             memcmp(p->rr_flags, &s->flags, sizeof(s->flags))))) {
			pthread_mutex_unlock(&policy_registry_lock); return -1;
		}
		p->refs++; s->policy = p; s->rr_member_id = ++p->rr_last_id;
		pthread_mutex_unlock(&policy_registry_lock); return 0;
	}
	p = calloc(1, sizeof(*p));
	if (!p) { pthread_mutex_unlock(&policy_registry_lock); return -1; }
	pthread_mutex_init(&p->lock, NULL);
    pthread_mutex_init(&p->dispatch_lock, NULL);
    if (s->flags.upstream_round_robin) {
        p->rr_flags = malloc(sizeof(*p->rr_flags));
        if (!p->rr_flags) {
            pthread_mutex_destroy(&p->dispatch_lock); pthread_mutex_destroy(&p->lock);
            free(p); pthread_mutex_unlock(&policy_registry_lock); return -1;
        }
        *p->rr_flags = s->flags;
    }
    p->rr_type = s->type;
    s->rr_member_id = ++p->rr_last_id;
	safe_strncpy(p->name, s->flags.quota_group, sizeof(p->name));
	p->refs = 1; p->rate = s->flags.max_query_rate; p->burst = s->flags.query_burst;
	p->tokens = (uint64_t)p->burst * 1000; p->updated = get_tick_count();
	p->next = policies; policies = p; s->policy = p;
	pthread_mutex_unlock(&policy_registry_lock);
	return 0;
}
/* Caller holds server->lock. Reserve before creating any physical transport,
 * including a connecting/handshaking one; release only after actual teardown. */
int _dns_policy_connection_acquire(struct dns_server_info *s)
{
    struct dns_upstream_policy *p = s->policy;
    if (!p || !s->flags.upstream_round_robin || s->policy_connection_held) return 0;
    pthread_mutex_lock(&p->lock);
    int full = p->connections >= p->rr_flags->max_upstream_connections;
    if (!full) { p->connections++; s->policy_connection_held = 1; }
    pthread_mutex_unlock(&p->lock);
    return full ? -1 : 0;
}
void _dns_policy_connection_release(struct dns_server_info *s)
{
    struct dns_upstream_policy *p = s->policy;
    if (!p || !s->policy_connection_held) return;
    pthread_mutex_lock(&p->lock);
    if (p->connections) p->connections--;
    s->policy_connection_held = 0;
    pthread_mutex_unlock(&p->lock);
}
void _dns_policy_detach(struct dns_server_info *s)
{
	struct dns_upstream_policy *p = s->policy;
	if (!p) return;
    _dns_policy_connection_release(s);
	pthread_mutex_lock(&policy_registry_lock);
	if (--p->refs == 0) {
		struct dns_upstream_policy **link = &policies;
		while (*link && *link != p) link = &(*link)->next;
		if (*link) *link = p->next;
		pthread_mutex_destroy(&p->dispatch_lock); pthread_mutex_destroy(&p->lock); free(p->rr_flags); free(p);
	}
	s->policy = NULL;
	pthread_mutex_unlock(&policy_registry_lock);
}

/* Parse a server minimum, not a DNS cache TTL. Saturate very large delays. */
int _dns_policy_retry_after_ms(const char *value, time_t now, uint64_t *delay)
{
	if (!value || !*value) return -1;
	while (*value == ' ' || *value == '\t') value++;
	if (*value >= '0' && *value <= '9') {
		uint64_t seconds = 0;
		const char *p = value;
		for (; *p >= '0' && *p <= '9'; p++) {
			unsigned int d = *p - '0';
			seconds = seconds > (UINT64_MAX - d) / 10 ? UINT64_MAX : seconds * 10 + d;
		}
		while (*p == ' ' || *p == '\t') p++;
		if (*p) return -1;
		*delay = seconds > UINT64_MAX / 1000 ? UINT64_MAX : seconds * 1000;
		return 0;
	}
    /* HTTP-date recipients accept IMF-fixdate and both obsolete wire forms.
     * Convert once to a monotonic cooldown; later wall-clock jumps cannot shorten it. */
    static const char *formats[] = {"%a, %d %b %Y %H:%M:%S GMT",
        "%A, %d-%b-%y %H:%M:%S GMT", "%a %b %e %H:%M:%S %Y"};
    for (unsigned i = 0; i < sizeof(formats) / sizeof(formats[0]); i++) {
        struct tm date = {0};
        char *end = strptime(value, formats[i], &date);
        if (!end) continue;
        while (*end == ' ' || *end == '\t') end++;
        if (*end) continue;
        if (i == 1) {
            struct tm current;
            if (!gmtime_r(&now, &current)) return -1;
            int year = current.tm_year + 1900;
            date.tm_year = (year / 100) * 100 + (date.tm_year + 1900) % 100 - 1900;
            if (date.tm_year > current.tm_year + 50) date.tm_year -= 100;
        }
        struct tm expected = date, normalized;
        time_t target = timegm(&date);
        if (target == (time_t)-1 || !gmtime_r(&target, &normalized)) continue;
        if (normalized.tm_year != expected.tm_year || normalized.tm_mon != expected.tm_mon ||
            normalized.tm_mday != expected.tm_mday || normalized.tm_hour != expected.tm_hour ||
            normalized.tm_min != expected.tm_min || normalized.tm_sec != expected.tm_sec) continue;
        uint64_t seconds = target > now ? (uint64_t)target - (uint64_t)now : 0;
        *delay = seconds > UINT64_MAX / 1000 ? UINT64_MAX : seconds * 1000;
        return 0;
    }
    return -1;
}
void _dns_policy_http_error(struct dns_server_info *s, int status, const char *value)
{
	if ((status != 429 && status != 503) || !s->policy) return;
	unsigned long now = get_tick_count();
	uint64_t delay = 0;
	int valid = _dns_policy_retry_after_ms(value, time(NULL), &delay) == 0;
	struct dns_upstream_policy *p = s->policy;
	pthread_mutex_lock(&p->lock);
    if (now >= p->last_error && now - p->last_error >= 60000) p->failures = 0;
    p->last_error = now;
    /* Old in-flight replies cannot reopen a newer backpressure epoch. */
    if (++p->recovery_epoch == 0) p->recovery_epoch++;
    p->recovering = 1;
    p->recovery_active = 0;
	if (p->failures < 6) p->failures++;
	/* 0.5..30s local backoff, with bounded jitter. No spin on Retry-After: 0. */
	uint64_t local = 250ULL << p->failures;
	if (local > 30000) local = 30000;
	local += ((now ^ (uintptr_t)p) % 251);
	if (!valid) delay = local;
	else if (delay < 100) delay = 100;
	unsigned long until = tick_add(now, delay);
	if (until > p->cooldown) p->cooldown = until;
    if (p->backpressure_count != UINT64_MAX) p->backpressure_count++;
    int warn = !p->last_warning || (now >= p->last_warning && now - p->last_warning >= 30000);
    uint64_t count = p->backpressure_count;
    if (warn) p->last_warning = now ? now : 1;
    pthread_mutex_unlock(&p->lock);
    if (warn) tlog(TLOG_WARN, "upstream backpressure status=%d events=%llu cooldown_ms=%llu endpoint=%s:%d",
                  status, (unsigned long long)count, (unsigned long long)delay, s->ip, s->port);
}

static int same_destination(struct dns_server_info *a, struct dns_server_info *b)
{
	return a->type == b->type && a->ai_addrlen == b->ai_addrlen &&
		memcmp(&a->addr, &b->addr, a->ai_addrlen) == 0;
}
static struct dns_query_attempt *find_attempt(struct dns_query_struct *q, struct dns_server_info *s)
{
	struct dns_query_attempt *a;
	for (a = q->attempts; a; a = a->next) if (same_destination(a->server, s) &&
        (!(s->flags.upstream_round_robin || a->server->flags.upstream_round_robin) || a->server->policy == s->policy)) return a;
	return NULL;
}
/* A recovery lease serializes probes, not normal traffic or a provider QPS.
 * Caller holds the policy lock; attempts retain their epoch after retirement
 * so a validated reply can complete recovery without a dangling owner pointer. */
static int recovery_available(struct dns_upstream_policy *p, struct dns_query_attempt *a)
{
    return !p->recovering || !p->recovery_active ||
        (a && a->recovery_held && a->recovery_epoch == p->recovery_epoch);
}
static void recovery_claim(struct dns_upstream_policy *p, struct dns_query_attempt *a)
{
    if (!p->recovering || (a->recovery_held && a->recovery_epoch == p->recovery_epoch)) return;
    a->recovery_epoch = p->recovery_epoch;
    a->recovery_held = 1;
    p->recovery_active++;
}
static void recovery_release(struct dns_query_attempt *a)
{
    if (!a->recovery_held) return;
    struct dns_upstream_policy *p = a->server->policy;
    pthread_mutex_lock(&p->lock);
    if (a->recovery_epoch == p->recovery_epoch && p->recovery_active) p->recovery_active--;
    a->recovery_held = 0;
    pthread_mutex_unlock(&p->lock);
}
int _dns_attempt_begin(struct dns_query_struct *q, struct dns_server_info *s)
{
    unsigned long now = get_tick_count();
    int ret = DNS_ADMIT_WAIT, policy_locked = 0;
    struct dns_upstream_policy *p = s->policy;
    pthread_mutex_lock(&s->lock);
    pthread_mutex_lock(&q->lock);
    struct dns_query_attempt *a = find_attempt(q, s);
    if (s->type == DNS_SERVER_HTTP3 && _dns_http3_is_draining(s)) goto out;
    if (q->terminal || (a && (a->sends >= DNS_QUERY_RETRY || a->replied)) || dns_query_budget_exhausted(q->budget)) {
        ret = DNS_ADMIT_DONE; goto out;
    }
    if (s->flags.upstream_round_robin) {
        struct dns_query_attempt *other;
        for (other = q->attempts; other; other = other->next)
            if (other->active && other->server->policy == p) goto out;
    }
    if ((a && a->active) || (s->flags.max_concurrent_queries && s->active_attempts >= s->flags.max_concurrent_queries)) goto out;
    if (a && a->server != s) {
        dns_client_server_info_get(s);
        dns_client_server_info_release(a->server);
        a->server = s;
    }
    int stream_transport = s->type == DNS_SERVER_HTTPS || s->type == DNS_SERVER_HTTP3 || s->type == DNS_SERVER_QUIC ||
        s->type == DNS_SERVER_TCP || s->type == DNS_SERVER_TLS;
    if (p) {
        pthread_mutex_lock(&p->lock); policy_locked = 1;
        if (now < p->cooldown || !recovery_available(p, a)) goto out;
        if (p->rate) {
            uint64_t cap = (uint64_t)p->burst * 1000;
            unsigned long elapsed = now >= p->updated ? now - p->updated : 0;
            uint64_t refill = elapsed > cap / p->rate ? cap : (uint64_t)elapsed * p->rate;
            p->tokens = refill >= cap - p->tokens ? cap : p->tokens + refill;
            p->updated = now;
            if (p->tokens < 1000) goto out;
        }
    }
    if (!a) {
        a = calloc(1, sizeof(*a));
        if (!a) { ret = DNS_ADMIT_DONE; goto out; }
        dns_client_server_info_get(s); a->server = s;
        a->next = q->attempts; q->attempts = a;
    }
    if (!stream_transport) {
        if (_dns_query_budget_take(q->budget)) { ret = DNS_ADMIT_DONE; goto out; }
        if (p) {
            if (p->rate) p->tokens -= 1000;
            recovery_claim(p, a);
        }
        a->sends++;
    }
    if (p && s->flags.upstream_round_robin) {
        /* Reserve the single recovery probe in RR order, before handshake.
         * Old buffered owners cannot steal a newer recovery epoch. */
        recovery_claim(p, a);
        a->admitted_epoch = p->recovery_epoch;
    }
    a->wire_started = !stream_transport; a->wire_reserved = !stream_transport;
    a->generation++; a->active = 1; a->sent_tick = stream_transport ? 0 : now;
    s->active_attempts++;
    atomic_inc(&q->dns_request_sent);
    ret = DNS_ADMIT_OK;
out:
    if (policy_locked) pthread_mutex_unlock(&p->lock);
    pthread_mutex_unlock(&q->lock);
    pthread_mutex_unlock(&s->lock);
    return ret;
}
/* The cursor advances on accepted dispatch, even if setup/send later fails or
 * cancellation wins. Never roll it back across another concurrent selection.
 * A recovered/new member simply enters future cycles, without catch-up credit. */
struct dns_server_info *_dns_policy_rr_begin(struct dns_query_struct *q,
    struct dns_server_info **servers, unsigned int count, struct dns_server_info *service,
    int (*eligible)(struct dns_server_info *, void *), void *context)
{
    struct dns_upstream_policy *p = service->policy;
    struct dns_server_info *chosen = NULL;
    pthread_mutex_lock(&p->dispatch_lock);
    pthread_mutex_lock(&p->lock);
    unsigned long now = get_tick_count();
    uint64_t refill = 0;
    if (p->rate && now >= p->updated) {
        uint64_t cap = (uint64_t)p->burst * 1000;
        unsigned long elapsed = now - p->updated;
        refill = elapsed > cap / p->rate ? cap : (uint64_t)elapsed * p->rate;
    }
    int blocked = now < p->cooldown || (p->recovering && p->recovery_active) ||
        (p->rate && p->tokens + refill < 1000);
    pthread_mutex_unlock(&p->lock);
    if (blocked || dns_query_budget_exhausted(q->budget)) goto done;
    uint64_t cursor = p->rr_cursor, first_tried = 0;
    for (unsigned int tried = 0; tried < count; tried++) {
        struct dns_server_info *next = NULL, *first = NULL;
        for (unsigned int i = 0; i < count; i++) {
            struct dns_server_info *s = servers[i];
            if (s->policy != p) continue;
            if (!first || s->rr_member_id < first->rr_member_id) first = s;
            if (s->rr_member_id > cursor && (!next || s->rr_member_id < next->rr_member_id)) next = s;
        }
        if (!next) next = first;
        if (!next) break;
        if (next->rr_member_id == first_tried) break;
        if (!first_tried) first_tried = next->rr_member_id;
        cursor = next->rr_member_id;
        if (eligible && !eligible(next, context)) continue;
        pthread_mutex_lock(&next->lock);
        int held = next->policy_connection_held;
        int capacity = _dns_policy_connection_acquire(next) == 0;
        pthread_mutex_unlock(&next->lock);
        if (!capacity) {
            /* A service may have more addresses than physical slots. Rotate
             * only truly idle sockets; never evict a handshake or in-flight
             * stream just to satisfy RR. Actual close returns the slot. */
            for (unsigned int i = 0; i < count && !capacity; i++) {
                struct dns_server_info *old = servers[i];
                if (old == next || old->policy != p) continue;
                pthread_mutex_lock(&old->lock);
                if (old->policy_connection_held && old->fd >= 0 &&
                    old->status == DNS_SERVER_STATUS_CONNECTED && !old->active_attempts &&
                    !old->process_depth && !old->send_buff.len && !old->http2_write_owner &&
                    list_empty(&old->conn_stream_list)) _dns_client_close_socket(old);
                pthread_mutex_unlock(&old->lock);
                pthread_mutex_lock(&next->lock);
                capacity = _dns_policy_connection_acquire(next) == 0;
                pthread_mutex_unlock(&next->lock);
            }
        }
        if (!capacity) continue;
        if (_dns_attempt_begin(q, next) != DNS_ADMIT_OK) {
            pthread_mutex_lock(&next->lock);
            if (!held && next->fd < 0 && !next->active_attempts) _dns_policy_connection_release(next);
            pthread_mutex_unlock(&next->lock);
            continue;
        }
        p->rr_cursor = cursor;
        chosen = next;
        break;
    }
done:
    pthread_mutex_unlock(&p->dispatch_lock);
    return chosen;
}

/* First request bytes, separately from pre-socket admission. Buffered handshakes
 * cannot accumulate tokens and then release an unbounded burst. */
int _dns_attempt_wire_begin(struct dns_query_struct *q, struct dns_server_info *s, unsigned int generation)
{
    if (!q) return DNS_ADMIT_DONE;
    int ret = DNS_ADMIT_WAIT;
    unsigned long now = get_tick_count();
    pthread_mutex_lock(&s->lock);
    pthread_mutex_lock(&q->lock);
    struct dns_query_attempt *a = find_attempt(q, s);
    if (!a || !a->active || a->generation != generation || q->terminal) { ret = DNS_ADMIT_DONE; goto out; }
    /* Cancellation/deadline also gates continuation; spent send capacity alone
     * does not forbid finishing the already-reserved request. */
    if (!dns_query_budget_remaining_ms(q->budget)) { ret = DNS_ADMIT_DONE; goto out; }
    if (a->wire_started) { ret = DNS_ADMIT_OK; goto out; }
    struct dns_upstream_policy *p = s->policy;
    pthread_mutex_lock(&p->lock);
    if (s->flags.upstream_round_robin && a->admitted_epoch != p->recovery_epoch) {
        ret = DNS_ADMIT_DONE; goto policy_out;
    }
    if (now < p->cooldown || !recovery_available(p, a)) goto policy_out;
    if (p->rate) {
        uint64_t cap = (uint64_t)p->burst * 1000;
        unsigned long elapsed = now >= p->updated ? now - p->updated : 0;
        uint64_t refill = elapsed > cap / p->rate ? cap : (uint64_t)elapsed * p->rate;
        p->tokens = refill >= cap - p->tokens ? cap : p->tokens + refill;
        p->updated = now;
        if (p->tokens < 1000) goto policy_out;
    }
    if (!a->wire_reserved) {
        if (a->sends >= DNS_QUERY_RETRY || _dns_query_budget_take(q->budget)) { ret = DNS_ADMIT_DONE; goto policy_out; }
        a->sends++; a->wire_reserved = 1;
    }
    /* An unsuccessful write may have uncertain effects: never refund its token
     * or attempt. Until positive progress, every retry needs fresh pacing. */
    if (p->rate) p->tokens -= 1000;
    recovery_claim(p, a);
    ret = DNS_ADMIT_OK;
policy_out:
    pthread_mutex_unlock(&p->lock);
out:
    pthread_mutex_unlock(&q->lock);
    pthread_mutex_unlock(&s->lock);
    return ret;
}

int _dns_attempt_live(struct dns_query_struct *q, struct dns_server_info *s, unsigned int generation)
{
    if (!q) return 0;
    pthread_mutex_lock(&q->lock);
    struct dns_query_attempt *a = find_attempt(q, s);
    int live = a && a->active && a->generation == generation && !q->terminal &&
               dns_query_budget_remaining_ms(q->budget);
    pthread_mutex_unlock(&q->lock);
    return live;
}

void _dns_attempt_replied(struct dns_query_struct *q, struct dns_server_info *s)
{
    pthread_mutex_lock(&q->lock);
    struct dns_query_attempt *a = find_attempt(q, s);
    if (a) {
        a->replied = 1;
        struct dns_upstream_policy *p = a->server->policy;
        pthread_mutex_lock(&p->lock);
        /* UDP/mDNS retries reuse the DNS SID: a late pre-backpressure packet
         * can match a newer attempt. Only the first datagram send can prove
         * recovery; retried replies still complete the query and retire its
         * lease normally. A fresh query or stream probe can reopen the policy. */
        int unambiguous = (a->server->type != DNS_SERVER_UDP && a->server->type != DNS_SERVER_MDNS) ||
                          a->sends == 1;
        if (a->wire_started && unambiguous && a->recovery_epoch == p->recovery_epoch) p->recovering = 0;
        pthread_mutex_unlock(&p->lock);
    }
    pthread_mutex_unlock(&q->lock);
}

int _dns_attempt_retire(struct dns_query_struct *q, struct dns_server_info *s, unsigned int generation)
{
	int retired = 0;
	pthread_mutex_lock(&s->lock);
	pthread_mutex_lock(&q->lock);
	struct dns_query_attempt *a = find_attempt(q, s);
	if (a && a->active && (!generation || generation == a->generation)) {
		a->active = 0; retired = 1;
		recovery_release(a);
		if (a->server->active_attempts) a->server->active_attempts--;
		atomic_dec(&q->dns_request_sent);
	}
	pthread_mutex_unlock(&q->lock);
	pthread_mutex_unlock(&s->lock);
	return retired;
}
unsigned int _dns_attempt_generation(struct dns_query_struct *q, struct dns_server_info *s)
{
	pthread_mutex_lock(&q->lock);
	struct dns_query_attempt *a = find_attempt(q, s);
	unsigned int gen = a ? a->generation : 0;
	pthread_mutex_unlock(&q->lock); return gen;
}
void _dns_attempt_mark_sent(struct dns_query_struct *q, struct dns_server_info *s, unsigned int generation)
{
	if (!q) return;
	pthread_mutex_lock(&q->lock);
	struct dns_query_attempt *a = find_attempt(q, s);
    if (a && a->active && a->generation == generation && !a->wire_started) {
        a->wire_started = 1; a->sent_tick = get_tick_count();
    }
	pthread_mutex_unlock(&q->lock);
}
void _dns_attempt_mark_buffered(struct dns_query_struct *q, struct dns_server_info *s)
{
	pthread_mutex_lock(&q->lock);
	struct dns_query_attempt *a = find_attempt(q, s);
	if (a && a->active && !a->wire_started) a->sent_tick = 0;
	pthread_mutex_unlock(&q->lock);
}
void _dns_attempt_expire(struct dns_query_struct *q, unsigned long now)
{
    for (;;) {
        struct dns_server_info *server = NULL;
        unsigned int generation = 0;
        pthread_mutex_lock(&q->lock);
        struct dns_query_attempt *a;
        for (a = q->attempts; a; a = a->next) {
            if (a->active && a->sent_tick && now - a->sent_tick >= DNS_QUERY_TIMEOUT) {
                server = a->server; generation = a->generation;
                dns_client_server_info_get(server); break;
            }
        }
        pthread_mutex_unlock(&q->lock);
        if (!server) break;
        if (_dns_attempt_retire(q, server, generation)) {
            if (server->type == DNS_SERVER_TCP || server->type == DNS_SERVER_TLS ||
                (server->type == DNS_SERVER_HTTPS && strncmp(server->alpn_selected, "h2", 2)))
                _dns_client_close_socket(server); /* no late FIFO response may claim a newer attempt */
            else if (server->type == DNS_SERVER_HTTPS || server->type == DNS_SERVER_QUIC || server->type == DNS_SERVER_HTTP3)
                _dns_client_conn_server_streams_free(server, q);
        }
        dns_client_server_info_release(server);
    }
}
void _dns_attempt_free_all(struct dns_query_struct *q)
{
	struct dns_query_attempt *a = q->attempts;
	while (a) {
		struct dns_query_attempt *next = a->next;
		if (a->active || a->recovery_held) {
			pthread_mutex_lock(&a->server->lock);
			if (a->active && a->server->active_attempts) a->server->active_attempts--;
			recovery_release(a);
			pthread_mutex_unlock(&a->server->lock);
		}
		dns_client_server_info_release(a->server); free(a); a = next;
	}
	q->attempts = NULL;
}
int dns_client_group_has_ecs(const char *name)
{
	int unsafe = 0;
	pthread_mutex_lock(&client.server_list_lock);
	struct dns_server_group *groups[2] = {_dns_client_get_dnsserver_group(name), _dns_client_get_group("fallback")};
	if (!groups[0]) unsafe = 1;
	for (int i = 0; i < 2; i++) {
		if (!groups[i]) continue;
		struct dns_server_group_member *member;
		list_for_each_entry(member, &groups[i]->head, list) {
			if (member->server->ecs_ipv4.enable || member->server->ecs_ipv6.enable) unsafe = 1;
		}
	}
	pthread_mutex_unlock(&client.server_list_lock);
	return unsafe;
}

/* RFC 8484 HTTP cache age is independent of Retry-After. Malformed Age makes
 * received DNS data uncacheable, rather than silently extending its lifetime. */
int _dns_http_age(unsigned char *data, int len, const char *value)
{
    if (!value) return 0;
    uint32_t age = 0;
    const char *p = value;
    while (*p == ' ' || *p == '\t') p++;
    if (*p < '0' || *p > '9') age = UINT32_MAX;
    else {
        while (*p >= '0' && *p <= '9') {
            unsigned int digit = *p++ - '0';
            age = age > (UINT32_MAX - digit) / 10 ? UINT32_MAX : age * 10 + digit;
        }
        while (*p == ' ' || *p == '\t') p++;
        if (*p) age = UINT32_MAX;
    }
    return dns_any_wire_age(data, len, age, NULL);
}
