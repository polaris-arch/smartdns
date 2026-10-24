#define _GNU_SOURCE
#include "upstream_observer.h"
#include "upstream_policy.h"
#include "upstream_service.h"
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
	char name[DNS_MAX_CNAME_LEN];
	unsigned int refs, rate, burst, cooldown_ms;
	uint64_t tokens; /* millitokens: refill is rate * elapsed milliseconds */
	unsigned long updated;
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
	int recovery_held, retirement_pending;
    int response_received, outcome_recorded;
    unsigned observed_sent_generation;
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
int dns_query_budget_timed_out(struct dns_query_budget *b)
{
    if (!b) return 0;
    pthread_mutex_lock(&b->lock); int expired = !b->cancelled && get_tick_count() >= b->deadline;
    pthread_mutex_unlock(&b->lock); return expired;
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
    if (s->service) {
        pthread_mutex_lock(&policy_registry_lock);
        s->policy = s->service->policy;
        if (s->policy) s->policy->refs++;
        pthread_mutex_unlock(&policy_registry_lock);
        return s->policy ? 0 : -1;
    }
    /* Old RR syntax must be normalized by configuration before runtime. */
    if (s->flags.upstream_round_robin || s->flags.max_upstream_connections) return -1;
    if (s->flags.max_query_rate && !s->flags.query_burst) s->flags.query_burst = 1;
    unsigned cooldown_ms = s->flags.upstream_cooldown_ms ? s->flags.upstream_cooldown_ms : 1000;
    if (cooldown_ms > 10000) return -1;
	struct dns_upstream_policy *p;
	pthread_mutex_lock(&policy_registry_lock);
	for (p = policies; p; p = p->next) {
		if (!s->flags.quota_group[0] || strcmp(p->name, s->flags.quota_group)) continue;
		if (p->rate != s->flags.max_query_rate || p->burst != s->flags.query_burst || p->cooldown_ms != cooldown_ms) {
			pthread_mutex_unlock(&policy_registry_lock); return -1;
		}
		p->refs++; s->policy = p;
		pthread_mutex_unlock(&policy_registry_lock); return 0;
	}
	p = calloc(1, sizeof(*p));
	if (!p) { pthread_mutex_unlock(&policy_registry_lock); return -1; }
	pthread_mutex_init(&p->lock, NULL);
	safe_strncpy(p->name, s->flags.quota_group, sizeof(p->name));
	p->refs = 1; p->rate = s->flags.max_query_rate; p->burst = s->flags.query_burst;
    p->cooldown_ms = cooldown_ms;
	p->tokens = (uint64_t)p->burst * 1000; p->updated = get_tick_count();
	p->next = policies; policies = p; s->policy = p;
	pthread_mutex_unlock(&policy_registry_lock);
	return 0;
}
/* Caller holds server->lock. Reserve before creating any physical transport,
 * including a connecting/handshaking one; release only after actual teardown. */
int _dns_policy_connection_acquire(struct dns_server_info *s)
{ return s->service ? _dns_service_connection_acquire(s) : 0; }
void _dns_policy_connection_release(struct dns_server_info *s)
{ if (s->service) _dns_service_connection_release(s); }
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
		pthread_mutex_destroy(&p->lock); free(p);
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
void _dns_policy_http_error_query(struct dns_query_struct *q, struct dns_server_info *s, int status, const char *value)
{
	if ((status != 429 && status != 503) || !s->policy) return;
    _dns_service_diagnostic_event(q, s, status == 429 ? DNS_EVENT_HTTP_429 : DNS_EVENT_HTTP_503);
    _dns_service_detail(q, s, status == 429 ? DNS_DETAIL_HTTP_429 : DNS_DETAIL_HTTP_503,
        s->type == DNS_SERVER_HTTP3 ? DNS_PHASE_HTTP3 : DNS_PHASE_HTTP2, status, 0,
        s->flags.upstream_cooldown_ms ? s->flags.upstream_cooldown_ms : 1000);
	unsigned long now = get_tick_count();
	uint64_t delay = 0;
	int valid = _dns_policy_retry_after_ms(value, time(NULL), &delay) == 0;
	struct dns_upstream_policy *p = s->policy;
	pthread_mutex_lock(&p->lock);
    /* Old in-flight replies cannot reopen a newer backpressure epoch. */
    if (++s->policy_recovery_epoch == 0) s->policy_recovery_epoch++;
    s->policy_recovering = 1;
    s->policy_recovery_active = 0;
    if (status == 429) s->policy_http_429++; else s->policy_http_503++;
    struct timespec wall;
    if (clock_gettime(CLOCK_REALTIME, &wall) == 0 && wall.tv_sec >= 0)
        s->policy_last_backpressure_unix_ms = (uint64_t)wall.tv_sec * 1000 + wall.tv_nsec / 1000000;
    /* Fixed local duration; upstream Retry-After is diagnostic evidence only. */
	unsigned long until = tick_add(now, p->cooldown_ms);
	if (until > __atomic_load_n(&s->policy_cooldown, __ATOMIC_RELAXED))
        __atomic_store_n(&s->policy_cooldown, until, __ATOMIC_RELEASE);
    if (s->policy_backpressure_count != UINT64_MAX) s->policy_backpressure_count++;
    int warn = !s->policy_last_warning || (now >= s->policy_last_warning && now - s->policy_last_warning >= 30000);
    uint64_t count = s->policy_backpressure_count;
    if (warn) s->policy_last_warning = now ? now : 1;
    pthread_mutex_unlock(&p->lock);
    _dns_service_transport_changed(s);
    if (warn) tlog(TLOG_WARN, "upstream backpressure status=%d events=%llu cooldown_ms=%u retry_after_valid=%d retry_after_ms=%llu endpoint=%s:%d",
                  status, (unsigned long long)count, p->cooldown_ms, valid, (unsigned long long)delay, s->ip, s->port);
}

void _dns_policy_http_error(struct dns_server_info *s, int status, const char *value)
{ _dns_policy_http_error_query(NULL, s, status, value); }

static int same_destination(struct dns_server_info *a, struct dns_server_info *b)
{
	return a->type == b->type && a->ai_addrlen == b->ai_addrlen &&
		memcmp(&a->addr, &b->addr, a->ai_addrlen) == 0;
}
static struct dns_query_attempt *find_attempt(struct dns_query_struct *q, struct dns_server_info *s)
{
	struct dns_query_attempt *a;
	for (a = q->attempts; a; a = a->next) if (a->server->service == s->service && same_destination(a->server, s)) return a;
	return NULL;
}
/* A recovery lease serializes probes, not normal traffic or a provider QPS.
 * Caller holds the policy lock; attempts retain their epoch after retirement
 * so a validated reply can complete recovery without a dangling owner pointer. */
static int recovery_available(struct dns_server_info *s, struct dns_query_attempt *a)
{
    return !s->policy_recovering || !s->policy_recovery_active ||
        (a && a->recovery_held && a->recovery_epoch == s->policy_recovery_epoch);
}
static void recovery_claim(struct dns_query_attempt *a)
{
    struct dns_server_info *s = a->server;
    if (!s->policy_recovering || (a->recovery_held && a->recovery_epoch == s->policy_recovery_epoch)) return;
    a->recovery_epoch = s->policy_recovery_epoch;
    a->recovery_held = 1;
    s->policy_recovery_active++;
}
static void recovery_release(struct dns_query_attempt *a)
{
    if (!a->recovery_held) return;
    struct dns_upstream_policy *p = a->server->policy;
    pthread_mutex_lock(&p->lock);
    if (a->recovery_epoch == a->server->policy_recovery_epoch && a->server->policy_recovery_active) a->server->policy_recovery_active--;
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
    /* Selection can race idle-slot rotation. Recheck readiness while holding the
     * endpoint lock, before reserving an attempt that would pin a closed socket. */
    if (s->service && s->type != DNS_SERVER_UDP &&
        (!__atomic_load_n(&s->service_protocol_ready, __ATOMIC_ACQUIRE) || s->status != DNS_SERVER_STATUS_CONNECTED)) goto out;
    if (s->type == DNS_SERVER_HTTP3 && _dns_http3_is_draining(s)) goto out;
    if (q->terminal || (a && (a->sends >= DNS_QUERY_RETRY || a->replied)) || dns_query_budget_exhausted(q->budget)) {
        ret = DNS_ADMIT_DONE; goto out;
    }
    if (s->service) {
        struct dns_query_attempt *other;
        for (other = q->attempts; other; other = other->next)
            if (other->active && other->server->service == s->service) goto out;
    }
    if ((a && (a->active || a->retirement_pending)) || (!s->service && s->flags.max_concurrent_queries && s->active_attempts >= s->flags.max_concurrent_queries)) goto out;
    if (a && a->server != s) {
        dns_client_server_info_get(s);
        dns_client_server_info_release(a->server);
        a->server = s;
    }
    int stream_transport = s->service || s->type == DNS_SERVER_HTTPS || s->type == DNS_SERVER_HTTP3 || s->type == DNS_SERVER_QUIC ||
        s->type == DNS_SERVER_TCP || s->type == DNS_SERVER_TLS;
    if (!a) {
        a = calloc(1, sizeof(*a));
        if (!a) { ret = DNS_ADMIT_DONE; goto out; }
        dns_client_server_info_get(s); a->server = s;
        a->next = q->attempts; q->attempts = a;
    }
    if (p) {
        pthread_mutex_lock(&p->lock); policy_locked = 1;
        if (now < s->policy_cooldown || !recovery_available(s, a)) {
            _dns_endpoint_wait_locked(q, s, now < s->policy_cooldown ? DNS_WAIT_COOLDOWN : DNS_WAIT_RECOVERY); goto out;
        }
        if (p->rate) {
            uint64_t cap = (uint64_t)p->burst * 1000;
            unsigned long elapsed = now >= p->updated ? now - p->updated : 0;
            uint64_t refill = elapsed > cap / p->rate ? cap : (uint64_t)elapsed * p->rate;
            p->tokens = refill >= cap - p->tokens ? cap : p->tokens + refill;
            p->updated = now;
            if (p->tokens < 1000) { _dns_endpoint_wait_locked(q, s, DNS_WAIT_RATE); goto out; }
        }
    }
    if (!stream_transport) {
        if (_dns_query_budget_take(q->budget)) { ret = DNS_ADMIT_DONE; goto out; }
        if (p) {
            if (p->rate) p->tokens -= 1000;
            recovery_claim(a);
        }
        a->sends++;
    }
    if (p && s->service) {
        /* Reserve the single recovery probe in RR order, before handshake.
         * Old buffered owners cannot steal a newer recovery epoch. */
        recovery_claim(a);
        a->admitted_epoch = s->policy_recovery_epoch;
    }
    if (s->service) {
        if (s->flags.max_concurrent_queries && __atomic_load_n(&s->service->active_attempts, __ATOMIC_ACQUIRE) >=
            s->flags.max_concurrent_queries) goto out;
        __atomic_add_fetch(&s->service->active_attempts, 1, __ATOMIC_ACQ_REL);
        _dns_service_attempt_active(q, s->service, 1);
    }
    if (stream_transport) _dns_endpoint_wait_locked(q, s, DNS_WAIT_WRITE);
    a->wire_started = !stream_transport; a->wire_reserved = !stream_transport;
    a->response_received = 0; a->outcome_recorded = 0;
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
    if (s->service && a->admitted_epoch != s->policy_recovery_epoch) {
        ret = DNS_ADMIT_DONE; goto policy_out;
    }
    if (now < s->policy_cooldown || !recovery_available(s, a)) {
        _dns_endpoint_wait_locked(q, s, now < s->policy_cooldown ? DNS_WAIT_COOLDOWN : DNS_WAIT_RECOVERY); goto policy_out;
    }
    if (p->rate) {
        uint64_t cap = (uint64_t)p->burst * 1000;
        unsigned long elapsed = now >= p->updated ? now - p->updated : 0;
        uint64_t refill = elapsed > cap / p->rate ? cap : (uint64_t)elapsed * p->rate;
        p->tokens = refill >= cap - p->tokens ? cap : p->tokens + refill;
        p->updated = now;
        if (p->tokens < 1000) { _dns_endpoint_wait_locked(q, s, DNS_WAIT_RATE); goto policy_out; }
    }
    if (!a->wire_reserved) {
        if (a->sends >= DNS_QUERY_RETRY || _dns_query_budget_take(q->budget)) { ret = DNS_ADMIT_DONE; goto policy_out; }
        a->sends++; a->wire_reserved = 1;
    }
    /* An unsuccessful write may have uncertain effects: never refund its token
     * or attempt. Until positive progress, every retry needs fresh pacing. */
    if (p->rate) p->tokens -= 1000;
    recovery_claim(a);
    ret = s->service ? _dns_service_write_begin(q, s, generation) : DNS_ADMIT_OK;
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

void _dns_attempt_response_sample(struct dns_query_struct *q, struct dns_server_info *s)
{
    if (!s->service && !s->diagnostic) return;
    pthread_mutex_lock(&q->lock);
    struct dns_query_attempt *a = find_attempt(q, s);
    if (a && a->wire_started && !a->response_received) {
        a->response_received = 1;
        /* Retransmitted datagrams reuse SID, and generic TCP receive lacks a
         * generation tag too. Exclude all ambiguous retries rather than invent RTT. */
        unsigned long now = get_tick_count();
        if (a->sends == 1 && now >= a->sent_tick) {
            _dns_service_response_time(s, now - a->sent_tick);
            if (s->service) {
                __atomic_add_fetch(&s->service->stats.attempt_rtt_sum_ms, now - a->sent_tick, __ATOMIC_RELAXED);
                __atomic_add_fetch(&s->service->stats.attempt_rtt_samples, 1, __ATOMIC_RELAXED);
            } else _dns_endpoint_rtt_locked(s, now - a->sent_tick, 0);
        } else if (s->service) __atomic_add_fetch(&s->service->stats.attempt_rtt_ambiguous_count, 1, __ATOMIC_RELAXED);
        else _dns_endpoint_rtt_locked(s, 0, 1);
    }
    pthread_mutex_unlock(&q->lock);
}
static void attempt_outcome(struct dns_query_attempt *a, int success)
{
    if (!a->wire_started || a->outcome_recorded ||
        (!a->server->service && a->observed_sent_generation != a->generation)) return;
    a->outcome_recorded = 1;
    if (success) __atomic_add_fetch(&a->server->service_success_count, 1, __ATOMIC_RELAXED);
    else __atomic_add_fetch(&a->server->service_failure_count, 1, __ATOMIC_RELAXED);
}
void _dns_attempt_reply_outcome(struct dns_query_struct *q, struct dns_server_info *s, int accepted)
{
    pthread_mutex_lock(&q->lock);
    struct dns_query_attempt *a = find_attempt(q, s);
    if (a) attempt_outcome(a, accepted);
    pthread_mutex_unlock(&q->lock);
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
        if (a->wire_started && unambiguous && a->recovery_epoch == a->server->policy_recovery_epoch) a->server->policy_recovering = 0;
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
		if (_dns_service_write_pending(q, s, a->generation)) a->retirement_pending = 1;
        else recovery_release(a);
        if (!a->response_received && !a->retirement_pending) attempt_outcome(a, 0);
		if (a->server->active_attempts) a->server->active_attempts--;
        if (s->service) {
            __atomic_sub_fetch(&s->service->active_attempts, 1, __ATOMIC_ACQ_REL);
            _dns_service_attempt_active(q, s->service, -1);
        }
		atomic_dec(&q->dns_request_sent);
	}
	pthread_mutex_unlock(&q->lock);
	pthread_mutex_unlock(&s->lock);
    if (retired && s->service) _dns_service_unsent_retire(q, s, generation);
	return retired;
}
/* Called after service finalization drops all service/turn locks. Query remains
 * pinned by its observation until deferred recovery ownership is discharged. */
void _dns_attempt_finalize_retired(struct dns_query_struct *q, struct dns_server_info *s)
{
    pthread_mutex_lock(&q->lock);
    struct dns_query_attempt *a = find_attempt(q, s);
    if (a && a->retirement_pending) {
        recovery_release(a); a->retirement_pending = 0;
        if (!a->response_received) attempt_outcome(a, 0);
    }
    pthread_mutex_unlock(&q->lock);
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
    if (a && a->generation == generation) {
        if (!a->wire_started) { a->wire_started = 1; a->sent_tick = get_tick_count(); }
        if (a->observed_sent_generation != generation) {
            a->observed_sent_generation = generation;
            _dns_policy_endpoint_sent(s);
            if (!s->service) {
                _dns_endpoint_sent_locked(q, s);
                __atomic_add_fetch(&s->service_attempt_count, 1, __ATOMIC_RELAXED);
            }
        }
    }
	pthread_mutex_unlock(&q->lock);
    _dns_service_write_result(q, s, generation, 1, 0);
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
        unsigned int generation = 0, elapsed = 0, limit = 0, service_deadline = 0;
        pthread_mutex_lock(&q->lock);
        struct dns_query_attempt *a;
        for (a = q->attempts; a; a = a->next) {
            unsigned response_limit = a->server->service && a->server->service->config.response_timeout_ms ? a->server->service->config.response_timeout_ms : DNS_QUERY_TIMEOUT;
            int deadline = a->server->service && q->created_tick && a->server->service->config.query_timeout_ms && now >= q->created_tick &&
                now - q->created_tick >= a->server->service->config.query_timeout_ms;
            if (a->active && (deadline || (a->sent_tick && now - a->sent_tick >= response_limit))) {
                elapsed = deadline ? now - q->created_tick : a->sent_tick ? now - a->sent_tick : now - q->created_tick;
                limit = deadline ? a->server->service->config.query_timeout_ms : response_limit;
                service_deadline = deadline;
                server = a->server; generation = a->generation;
                dns_client_server_info_get(server); break;
            }
        }
        pthread_mutex_unlock(&q->lock);
        if (!server) break;
        if (_dns_attempt_retire(q, server, generation)) {
            if (!service_deadline) _dns_service_diagnostic_event(q, server, DNS_EVENT_ATTEMPT_TIMEOUT);
            _dns_service_detail(q, server, service_deadline ? DNS_DETAIL_QUERY_TIMEOUT : DNS_DETAIL_RESPONSE_TIMEOUT,
                DNS_PHASE_RESPONSE, 0, elapsed, limit);
            if (service_deadline) _dns_service_query_expired(q, server->service);
            else _dns_service_endpoint_failure(server);
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
        if (!a->server->service) attempt_outcome(a, 0);
		if (a->active || a->recovery_held) {
			pthread_mutex_lock(&a->server->lock);
			if (a->active && a->server->active_attempts) {
                a->server->active_attempts--;
                if (a->server->service) __atomic_sub_fetch(&a->server->service->active_attempts, 1, __ATOMIC_ACQ_REL);
            }
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
            if (member->service) { if (_dns_service_has_ecs(member->service)) unsafe = 1; }
            else if (member->server->ecs_ipv4.enable || member->server->ecs_ipv6.enable) unsafe = 1;
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

int _dns_policy_service_init(struct dns_upstream_service *service)
{
    struct dns_server_info temporary = {0};
    temporary.type = service->type;
    temporary.flags = service->flags;
    temporary.flags.max_upstream_connections = 0;
    temporary.flags.upstream_round_robin = 0;
    if (_dns_policy_attach(&temporary)) return -1;
    service->policy = temporary.policy;
    return 0;
}
void _dns_policy_service_release(struct dns_upstream_service *service)
{
    struct dns_server_info temporary = {0};
    temporary.policy = service->policy;
    _dns_policy_detach(&temporary);
    service->policy = NULL;
}
unsigned long _dns_policy_service_wait(struct dns_upstream_service *service, unsigned long now)
{ return _dns_policy_service_wait_reason(service, now, NULL); }
unsigned long _dns_policy_endpoint_cooldown(struct dns_server_info *ep, unsigned long now)
{
    /* Also used under the leaf send-turn lock while policy->lock is held.
     * A published deadline is sufficient; never recursively take the policy
     * mutex or introduce turn -> policy lock ordering here. */
    unsigned long until = __atomic_load_n(&ep->policy_cooldown, __ATOMIC_ACQUIRE);
    return until > now ? until - now : 0;
}
/* Membership -> policy, never policy -> membership/endpoint. A service waits
 * for node recovery only when every selected node is blocked. */
static unsigned long service_node_wait_locked(struct dns_upstream_service *service,
    unsigned long now, unsigned *reason, int include_recovery)
{
    unsigned long minimum = ULONG_MAX; unsigned why = DNS_WAIT_NONE;
    for (unsigned i = 0; i < service->member_count; i++) {
        struct dns_server_info *ep = service->members[i];
        if (__atomic_load_n(&ep->service_revoked, __ATOMIC_ACQUIRE) ||
            __atomic_load_n(&ep->service_draining, __ATOMIC_ACQUIRE) ||
            __atomic_load_n(&ep->service_rotation, __ATOMIC_ACQUIRE)) continue;
        unsigned long wait = ep->policy_cooldown > now ? ep->policy_cooldown - now :
            include_recovery && ep->policy_recovering && ep->policy_recovery_active ? 100 : 0;
        if (wait < minimum) { minimum = wait; why = wait && ep->policy_cooldown > now ? DNS_WAIT_COOLDOWN : DNS_WAIT_RECOVERY; }
    }
    if (reason) *reason = minimum && minimum != ULONG_MAX ? why : DNS_WAIT_NONE;
    return minimum == ULONG_MAX ? 0 : minimum;
}
unsigned long _dns_policy_service_wait_reason(struct dns_upstream_service *service, unsigned long now, unsigned *reason)
{
    struct dns_upstream_policy *p = service->policy;
    pthread_mutex_lock(&service->lock); pthread_mutex_lock(&p->lock);
    unsigned why = DNS_WAIT_NONE;
    unsigned long wait = service_node_wait_locked(service, now, &why, 1);
    if (p->rate) {
        uint64_t elapsed = now >= p->updated ? now - p->updated : 0;
        uint64_t available = p->tokens + (elapsed > 1000 ? 1000 : elapsed) * p->rate;
        unsigned long rate_wait = available < 1000 ? (1000 - available + p->rate - 1) / p->rate : 0;
        if (rate_wait && rate_wait >= wait) { wait = rate_wait; why = DNS_WAIT_RATE; }
    }
    pthread_mutex_unlock(&p->lock); pthread_mutex_unlock(&service->lock);
    if (reason) *reason = why;
    return wait;
}
unsigned long _dns_policy_service_cooldown(struct dns_upstream_service *service, unsigned long now)
{
    pthread_mutex_lock(&service->lock); pthread_mutex_lock(&service->policy->lock);
    unsigned long wait = service_node_wait_locked(service, now, NULL, 0);
    pthread_mutex_unlock(&service->policy->lock); pthread_mutex_unlock(&service->lock);
    return wait;
}

/* Passive counters: no sampling timer, additional connection or probe traffic. */
void _dns_policy_endpoint_sent(struct dns_server_info *ep)
{
    if (!ep->policy) return;
    unsigned long bucket = get_tick_count() / 100;
    pthread_mutex_lock(&ep->policy->lock);
    if (bucket != ep->policy_send_bucket_tick) {
        ep->policy_send_bucket_tick = bucket; ep->policy_send_bucket_count = 0;
    }
    ep->policy_send_bucket_count++;
    if (ep->policy_send_bucket_count > ep->policy_send_peak_100ms) {
        ep->policy_send_peak_100ms = ep->policy_send_bucket_count;
        struct timespec wall;
        if (clock_gettime(CLOCK_REALTIME, &wall) == 0 && wall.tv_sec >= 0)
            ep->policy_send_peak_unix_ms = (uint64_t)wall.tv_sec * 1000 + wall.tv_nsec / 1000000;
    }
    pthread_mutex_unlock(&ep->policy->lock);
}
void _dns_policy_endpoint_activity(struct dns_server_info *ep, struct dns_upstream_endpoint_activity_v1 *out)
{
    out->struct_size = sizeof(*out); out->version = 1;
    if (!ep->policy) return;
    unsigned long now = get_tick_count();
    pthread_mutex_lock(&ep->policy->lock);
    out->http_429 = ep->policy_http_429; out->http_503 = ep->policy_http_503;
    out->cooldown_remaining_ms = ep->policy_cooldown > now ? ep->policy_cooldown - now : 0;
    out->recovery_in_flight = ep->policy_recovery_active;
    out->sends_current_100ms = ep->policy_send_bucket_tick == now / 100 ? ep->policy_send_bucket_count : 0;
    out->sends_peak_100ms = ep->policy_send_peak_100ms; out->peak_unix_ms = ep->policy_send_peak_unix_ms;
    out->last_backpressure_unix_ms = ep->policy_last_backpressure_unix_ms;
    pthread_mutex_unlock(&ep->policy->lock);
}
