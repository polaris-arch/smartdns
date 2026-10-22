/* Bounded RRset discovery for logical upstreams. Legacy pending_server is separate. */
#include "upstream_discovery.h"
#include "smartdns/dns_client.h"
#include "smartdns/util.h"
#include "wake_event.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define DISCOVERY_STALE_MS 60000UL
#define DISCOVERY_GENERATION_MS 5000UL

enum answer_kind { ANSWER_TRANSIENT, ANSWER_POSITIVE, ANSWER_NEGATIVE, ANSWER_REJECTED, ANSWER_FOLLOW };
struct discovery_path {
    char names[DNS_DISCOVERY_CNAME_LIMIT + 1][DNS_MAX_CNAME_LEN];
    unsigned int links;
    unsigned int ttl;
    unsigned long valid_until;
};
struct discovery_answer {
    enum answer_kind kind;
    struct discovery_path path;
    unsigned int count, discovered, rejected, zero_ttl;
    unsigned int ttl, negative_ttl;
    int nxdomain;
    struct dns_discovery_address addresses[DNS_DISCOVERY_FAMILY_LIMIT];
};
struct discovery_family {
    struct discovery_answer staged;
    struct dns_discovery_address addresses[DNS_DISCOVERY_FAMILY_LIMIT];
    unsigned int count;
    unsigned int grace;
    unsigned int done;
    struct discovery_path last_path;
};
struct dns_upstream_discovery {
    unsigned int refs, cancelled, started, active, running, failures;
    unsigned int test_mode;
    unsigned int bootstrap_start[2]; /* persistent per authority AND family */
    uint64_t generation;
    char host[DNS_MAX_CNAME_LEN];
    dns_discovery_callback callback;
    void *user;
    struct discovery_family family[2];
    struct dns_discovery_snapshot last;
    unsigned long refresh_due, generation_deadline, timer_due;
    struct dns_upstream_discovery *timer_next;
    int timer_linked;
};
struct discovery_request {
    struct dns_upstream_discovery *discovery;
    struct discovery_path path;
    struct discovery_answer answer;
    uint64_t generation;
    int family, answered;
};
static struct dns_upstream_discovery *timers;

static unsigned long add_ms(unsigned long now, uint64_t delay)
{
    return delay > ULONG_MAX - now ? ULONG_MAX : now + (unsigned long)delay;
}
static unsigned long minimum_tick(unsigned long a, unsigned long b) { return a < b ? a : b; }
static void discovery_get(struct dns_upstream_discovery *d) { d->refs++; }
static void discovery_put(struct dns_upstream_discovery *d) { if (!--d->refs) free(d); }
static void timer_remove(struct dns_upstream_discovery *d)
{
    if (!d->timer_linked) return;
    struct dns_upstream_discovery **link = &timers;
    while (*link && *link != d) link = &(*link)->timer_next;
    if (*link) *link = d->timer_next;
    d->timer_next = NULL; d->timer_linked = 0;
}
static void timer_set(struct dns_upstream_discovery *d, unsigned long due)
{
    timer_remove(d);
    if (d->cancelled || !d->started || d->test_mode || due == ULONG_MAX) return;
    d->timer_due = due;
    struct dns_upstream_discovery **link = &timers;
    while (*link && (*link)->timer_due <= due) link = &(*link)->timer_next;
    d->timer_next = *link; *link = d; d->timer_linked = 1;
    _dns_client_do_wakeup_event();
}
static int normalize_name(char *out, const char *name)
{
    size_t n = strlen(name);
    if (n && name[n - 1] == '.') n--;
    if (!n || n >= DNS_MAX_CNAME_LEN) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c <= 32 || c >= 127) return -1;
        out[i] = (char)tolower(c);
    }
    out[n] = 0;
    return 0;
}
static int same_name(const char *a, const char *b)
{
    char na[DNS_MAX_CNAME_LEN], nb[DNS_MAX_CNAME_LEN];
    return !normalize_name(na, a) && !normalize_name(nb, b) && !strcmp(na, nb);
}
static int enclosing_zone(const char *zone, const char *name)
{
    if (!strcmp(zone, ".") || !zone[0]) return 1;
    char z[DNS_MAX_CNAME_LEN], n[DNS_MAX_CNAME_LEN];
    if (normalize_name(z, zone) || normalize_name(n, name)) return 0;
    size_t nz = strlen(z), nn = strlen(n);
    return nn >= nz && !strcmp(n + nn - nz, z) && (nn == nz || n[nn - nz - 1] == '.');
}
/* Discovery is address-family neutral, including private/VPN/local upstreams.
 * Exact self-listener address + port + transport recursion is checked by the
 * service owner, which has the necessary configuration; address alone cannot
 * distinguish a legitimate local resolver on another port from a loop. */
int _dns_discovery_address_allowed(int family, const unsigned char *a)
{
    if (!a) return 0;
    if (family == AF_INET6 && IN6_IS_ADDR_V4MAPPED((const struct in6_addr *)a))
        return _dns_discovery_address_allowed(AF_INET, a + 12);
    if (family == AF_INET) {
        static const unsigned char unspecified[4] = {0, 0, 0, 0};
        static const unsigned char broadcast[4] = {255, 255, 255, 255};
        return memcmp(a, unspecified, 4) && memcmp(a, broadcast, 4) &&
            (a[0] & 0xf0) != 0xe0 && !(a[0] == 169 && a[1] == 254);
    }
    if (family == AF_INET6) {
        const struct in6_addr *v6 = (const struct in6_addr *)a;
        return !IN6_IS_ADDR_UNSPECIFIED(v6) && !IN6_IS_ADDR_MULTICAST(v6) && !IN6_IS_ADDR_LINKLOCAL(v6);
    }
    return 0;
}
static int add_path(struct discovery_path *path, const char *name, unsigned ttl, unsigned long now)
{
    char normalized[DNS_MAX_CNAME_LEN];
    if (normalize_name(normalized, name) || path->links >= DNS_DISCOVERY_CNAME_LIMIT) return -1;
    for (unsigned i = 0; i <= path->links; i++) if (same_name(normalized, path->names[i])) return -1;
    path->links++;
    memcpy(path->names[path->links], normalized, strlen(normalized) + 1);
    if (ttl < path->ttl) path->ttl = ttl;
    path->valid_until = minimum_tick(path->valid_until, add_ms(now, (uint64_t)ttl * 1000));
    return 0;
}
static int question_matches(struct dns_packet *packet, const char *name, int qtype)
{
    int count = 0, qt = 0, qc = 0;
    char domain[DNS_MAX_CNAME_LEN];
    struct dns_rrs *rr = dns_get_rrs_start(packet, DNS_RRS_QD, &count);
    return count == 1 && rr && !dns_get_domain(rr, domain, sizeof(domain), &qt, &qc) &&
        qt == qtype && qc == 1 && same_name(domain, name);
}
static int rr_is_in(struct dns_rrs *rr, int expected_type)
{
    char owner[DNS_MAX_CNAME_LEN]; int type = 0, cls = 0;
    return rr->type == expected_type && !dns_get_domain(rr, owner, sizeof(owner), &type, &cls) &&
        type == expected_type && cls == 1;
}
static int negative_proof(struct dns_packet *packet, const char *terminal, unsigned int *negative_ttl)
{
    int count = 0;
    struct dns_rrs *rr = dns_get_rrs_start(packet, DNS_RRS_NS, &count);
    int found = 0;
    unsigned int minimum = UINT_MAX;
    for (int i = 0; i < count && rr; i++, rr = dns_get_rrs_next(packet, rr)) {
        if (!rr_is_in(rr, DNS_T_SOA)) continue;
        struct dns_soa soa;
        char owner[DNS_MAX_CNAME_LEN]; int ttl = 0;
        if (dns_get_SOA(rr, owner, sizeof(owner), &ttl, &soa) || ttl < 0 || !enclosing_zone(owner, terminal)) continue;
        unsigned int n = (unsigned)ttl < soa.minimum ? (unsigned)ttl : soa.minimum;
        if (n < minimum) minimum = n;
        found = 1;
    }
    if (found) *negative_ttl = minimum;
    return found;
}
static void parse_answer(struct discovery_request *request, struct dns_packet *packet,
                         unsigned long now, struct discovery_answer *out)
{
    memset(out, 0, sizeof(*out));
    out->path = request->path;
    out->kind = ANSWER_TRANSIENT;
    int qtype = request->family ? DNS_T_AAAA : DNS_T_A;
    if (!packet || packet->head.tc || packet->head.qr != DNS_OP_IQUERY ||
        !question_matches(packet, request->path.names[request->path.links], qtype) ||
        (packet->head.rcode != DNS_RC_NOERROR && packet->head.rcode != DNS_RC_NXDOMAIN)) return;

    /* Walk only answer-section CNAMEs and only the current owner chain. */
    for (;;) {
        int count = 0, found = 0;
        char target[DNS_MAX_CNAME_LEN] = {0}; unsigned int cname_ttl = UINT_MAX;
        struct dns_rrs *rr = dns_get_rrs_start(packet, DNS_RRS_AN, &count);
        for (int i = 0; i < count && rr; i++, rr = dns_get_rrs_next(packet, rr)) {
            if (!rr_is_in(rr, DNS_T_CNAME)) continue;
            char owner[DNS_MAX_CNAME_LEN], cname[DNS_MAX_CNAME_LEN] = {0}; int ttl = 0;
            if (dns_get_CNAME(rr, owner, sizeof(owner), &ttl, cname, sizeof(cname)) ||
                !same_name(owner, out->path.names[out->path.links])) continue;
            if (!memchr(cname, 0, sizeof(cname))) return;
            if (ttl < 0 || (found && !same_name(target, cname)) || normalize_name(target, cname)) return;
            found = 1;
            if ((unsigned)ttl < cname_ttl) cname_ttl = (unsigned)ttl;
        }
        if (!found) break;
        if (add_path(&out->path, target, cname_ttl, now)) return;
    }
    const char *terminal = out->path.names[out->path.links];
    int count = 0;
    struct dns_rrs *rr = dns_get_rrs_start(packet, DNS_RRS_AN, &count);
    unsigned long expiry_min = ULONG_MAX;
    for (int i = 0; i < count && rr; i++, rr = dns_get_rrs_next(packet, rr)) {
        if (!rr_is_in(rr, qtype)) continue;
        char owner[DNS_MAX_CNAME_LEN]; int ttl = 0;
        unsigned char addr[16] = {0};
        int record_type = 0, record_length = 0;
        void *record = dns_get_rr_nested_start(rr, owner, sizeof(owner), &record_type, &ttl, &record_length);
        if (!record || !same_name(owner, terminal)) continue;
        if (record_type != qtype || record_length != (request->family ? 16 : 4)) {
            out->count = 0; out->kind = ANSWER_TRANSIENT;
            return;
        }
        memcpy(addr, record, (size_t)record_length);
        if (++out->discovered > DNS_DISCOVERY_FAMILY_LIMIT || ttl < 0) {
            out->count = 0; out->kind = ANSWER_TRANSIENT;
            return;
        }
        int family = request->family ? AF_INET6 : AF_INET;
        if (!_dns_discovery_address_allowed(family, addr)) { out->rejected++; continue; }
        if (!ttl || !out->path.ttl || out->path.valid_until <= now) { out->zero_ttl++; continue; }
        if ((unsigned)ttl > out->path.ttl) ttl = (int)out->path.ttl;
        if (family == AF_INET6 && IN6_IS_ADDR_V4MAPPED((const struct in6_addr *)addr)) {
            memmove(addr, addr + 12, 4); memset(addr + 4, 0, 12); family = AF_INET;
        }
        unsigned j;
        for (j = 0; j < out->count; j++)
            if (out->addresses[j].family == family && !memcmp(out->addresses[j].addr, addr, 16)) break;
        if (j == out->count) {
            struct dns_discovery_address *a = &out->addresses[out->count++];
            a->family = family; memcpy(a->addr, addr, sizeof(a->addr));
            if (!inet_ntop(family, addr, a->text, sizeof(a->text))) {
                out->kind = ANSWER_TRANSIENT; out->count = 0;
                return;
            }
        }
        expiry_min = minimum_tick(expiry_min, add_ms(now, (uint64_t)ttl * 1000));
        expiry_min = minimum_tick(expiry_min, out->path.valid_until);
    }
    unsigned negative_ttl = 0;
    int proof = negative_proof(packet, terminal, &negative_ttl);
    if (out->path.valid_until != ULONG_MAX) {
        unsigned long left = out->path.valid_until > now ? (out->path.valid_until - now) / 1000 : 0;
        if (left < negative_ttl) negative_ttl = (unsigned int)left;
    }
    if (packet->head.rcode == DNS_RC_NXDOMAIN) {
        if (!proof || out->discovered) { out->count = 0; return; }
        out->kind = ANSWER_NEGATIVE; out->nxdomain = 1; out->negative_ttl = negative_ttl; return;
    }
    if (out->count) {
        out->kind = ANSWER_POSITIVE;
        out->ttl = (unsigned int)((expiry_min - now) / 1000);
        for (unsigned i = 0; i < out->count; i++) out->addresses[i].valid_until = expiry_min;
    } else if (out->discovered) {
        out->kind = ANSWER_REJECTED; /* zero TTL is noncacheable, not NXDOMAIN */
    } else if (proof) {
        out->kind = ANSWER_NEGATIVE; out->negative_ttl = negative_ttl;
    } else if (out->path.links > request->path.links) out->kind = ANSWER_FOLLOW;
}

static void reschedule(struct dns_upstream_discovery *d, unsigned long now)
{
    if (d->cancelled) return;
    unsigned long due = ULONG_MAX;
    if (d->running) due = d->generation_deadline;
    else if (!d->active) due = d->refresh_due;
    for (int f = 0; f < 2; f++) for (unsigned i = 0; i < d->family[f].count; i++) {
        unsigned long expiry = d->family[f].addresses[i].valid_until;
        if (expiry <= now && d->family[f].grace) expiry = add_ms(expiry, DISCOVERY_STALE_MS);
        if (expiry > now) due = minimum_tick(due, expiry);
    }
    timer_set(d, due);
}
static void publish(struct dns_upstream_discovery *d, unsigned long now, enum dns_discovery_status status)
{
    struct dns_discovery_snapshot snap;
    memset(&snap, 0, sizeof(snap));
    snap.generation = d->generation; snap.status = status; snap.expires = ULONG_MAX;
    for (int f = 0; f < 2; f++) {
        struct discovery_family *family = &d->family[f];
        snap.discovered += family->staged.discovered;
        snap.rejected += family->staged.rejected;
        snap.zero_ttl += family->staged.zero_ttl;
        for (unsigned i = 0; i < family->count;) {
            struct dns_discovery_address a = family->addresses[i];
            unsigned long limit = family->grace ? add_ms(a.valid_until, DISCOVERY_STALE_MS) : a.valid_until;
            if (now >= limit) {
                memmove(&family->addresses[i], &family->addresses[i + 1],
                        (family->count - i - 1) * sizeof(a));
                family->count--; continue;
            }
            i++;
            if (now >= a.valid_until) { snap.stale = 1; a.valid_until = limit; }
            unsigned j;
            for (j = 0; j < snap.count; j++)
                if (snap.addresses[j].family == a.family && !memcmp(snap.addresses[j].addr, a.addr, 16)) break;
            if (j == snap.count) snap.addresses[snap.count++] = a;
            else if (snap.addresses[j].valid_until > a.valid_until) snap.addresses[j].valid_until = a.valid_until;
            snap.expires = minimum_tick(snap.expires, a.valid_until);
        }
    }
    if (snap.stale) snap.status = DNS_DISCOVERY_STALE;
    else if (snap.count && status != DNS_DISCOVERY_INCONSISTENT) snap.status = DNS_DISCOVERY_READY;
    if (!memcmp(&snap, &d->last, sizeof(snap))) return;
    d->last = snap;
    if (!d->cancelled && d->callback) {
        discovery_get(d);
        d->callback(&snap, d->user);
        discovery_put(d);
    }
}
static int contradictory(struct discovery_answer *a, struct discovery_answer *b)
{
    if (a->kind != ANSWER_NEGATIVE || !a->nxdomain || b->kind != ANSWER_POSITIVE) return 0;
    const char *negative = a->path.names[a->path.links];
    for (unsigned i = 0; i <= b->path.links; i++) if (same_name(negative, b->path.names[i])) return 1;
    return 0;
}
static void finish_generation(struct dns_upstream_discovery *d, unsigned long now)
{
    if (!d->running || !d->family[0].done || !d->family[1].done) return;
    d->running = 0;
    int inconsistent = contradictory(&d->family[0].staged, &d->family[1].staged) ||
                       contradictory(&d->family[1].staged, &d->family[0].staged);
    unsigned long interval = 3600000UL;
    int failure = 0, rejected = 0;
    for (int f = 0; f < 2; f++) {
        struct discovery_family *family = &d->family[f];
        struct discovery_answer *a = &family->staged;
        if (inconsistent) { failure = 1; continue; }
        if (a->kind == ANSWER_POSITIVE) {
            memcpy(family->addresses, a->addresses, a->count * sizeof(a->addresses[0]));
            family->count = a->count; family->grace = 0; family->last_path = a->path;
            uint64_t refresh = (uint64_t)a->ttl * 800;
            if (refresh < 1000) refresh = 1000;
            if (refresh < interval) interval = (unsigned long)refresh;
        } else if (a->kind == ANSWER_NEGATIVE || a->kind == ANSWER_REJECTED) {
            family->count = 0; family->grace = 0;
            uint64_t retry = a->kind == ANSWER_NEGATIVE ? (uint64_t)a->negative_ttl * 1000 : 1000;
            if (retry < 1000) retry = 1000;
            if (retry < interval) interval = (unsigned long)retry;
            rejected |= a->kind == ANSWER_REJECTED;
        } else {
            family->grace = 1; failure = 1;
        }
    }
    if (failure) {
        if (d->failures < 7) d->failures++;
        unsigned long backoff = 1000UL << (d->failures - 1);
        if (backoff > 60000) backoff = 60000;
        interval = minimum_tick(interval, backoff);
    } else d->failures = 0;
    d->refresh_due = add_ms(now, interval);
    enum dns_discovery_status status = inconsistent ? DNS_DISCOVERY_INCONSISTENT :
        rejected ? DNS_DISCOVERY_REJECTED : failure ? DNS_DISCOVERY_FAILED : DNS_DISCOVERY_EMPTY;
    publish(d, now, status);
    if (!d->cancelled) reschedule(d, now);
}
static void stage_answer(struct dns_upstream_discovery *d, int f, const struct discovery_answer *answer,
                         unsigned long now)
{
    if (d->cancelled || !d->running || d->family[f].done) return;
    d->family[f].staged = *answer; d->family[f].done = 1;
    if (answer->kind == ANSWER_TRANSIENT) {
        /* The other family may still be walking CNAMEs. A known transient
         * failure already permits this family's bounded stale grace. */
        d->family[f].grace = 1;
        publish(d, now, DNS_DISCOVERY_FAILED);
        if (d->cancelled) return;
    }
    /* A negative/rebinding result revokes immediately, never at negative TTL expiry. */
    if (answer->kind == ANSWER_NEGATIVE || answer->kind == ANSWER_REJECTED) {
        d->family[f].count = 0; d->family[f].grace = 0;
        if (answer->nxdomain) {
            int other = 1 - f;
            const char *terminal = answer->path.names[answer->path.links];
            struct discovery_answer *peer = &d->family[other].staged;
            struct discovery_path *old = &d->family[other].last_path;
            if (!answer->path.links || (d->family[other].done &&
                same_name(terminal, peer->path.names[peer->path.links])) ||
                (d->family[other].count && same_name(terminal, old->names[old->links]))) {
                d->family[other].count = 0; d->family[other].grace = 0;
            }
        }
        publish(d, now, answer->kind == ANSWER_REJECTED ? DNS_DISCOVERY_REJECTED : DNS_DISCOVERY_EMPTY);
    }
    if (!d->cancelled) finish_generation(d, now);
}
static int launch_request(struct dns_upstream_discovery *d, int family, const struct discovery_path *path);
static int discovery_result(const char *domain, dns_result_type type, struct dns_server_info *server,
                            struct dns_packet *packet, unsigned char *raw, int length, void *user)
{
    (void)domain; (void)server; (void)raw; (void)length;
    struct discovery_request *r = user;
    struct dns_upstream_discovery *d = r->discovery;
    unsigned long now = get_tick_count();
    int valid = !d->cancelled && d->running && r->generation == d->generation &&
                now < d->generation_deadline;
    if (type == DNS_QUERY_RESULT && valid && !r->answered) {
        parse_answer(r, packet, now, &r->answer);
        if (r->answer.kind == ANSWER_TRANSIENT) return DNS_CLIENT_ACTION_DROP;
        r->answered = 1;
        if (r->answer.kind != ANSWER_FOLLOW) stage_answer(d, r->family, &r->answer, now);
        return DNS_CLIENT_ACTION_OK;
    }
    if (type != DNS_QUERY_END) return DNS_CLIENT_ACTION_DROP;
    if (d->active) d->active--;
    if (valid && !d->family[r->family].done) {
        if (r->answered && r->answer.kind == ANSWER_FOLLOW) {
            if (launch_request(d, r->family, &r->answer.path)) {
                struct discovery_answer failure = {0}; failure.path = r->path;
                stage_answer(d, r->family, &failure, now);
            }
        } else {
            struct discovery_answer failure = {0}; failure.path = r->path;
            stage_answer(d, r->family, &failure, now);
        }
    }
    if (!d->cancelled) reschedule(d, now);
    free(r); discovery_put(d);
    return DNS_CLIENT_ACTION_OK;
}
static int launch_request(struct dns_upstream_discovery *d, int family, const struct discovery_path *path)
{
    struct discovery_request *r = calloc(1, sizeof(*r));
    if (!r) return -1;
    r->discovery = d; r->family = family; r->path = *path; r->generation = d->generation;
    struct dns_query_options options;
    memset(&options, 0, sizeof(options));
    options.enable_flag = DNS_QUEY_OPTION_SINGLE_UPSTREAM | DNS_QUEY_OPTION_BOOTSTRAP_ONLY | DNS_QUEY_OPTION_BOOTSTRAP_START;
    options.bootstrap_start = d->bootstrap_start[family]++;
    discovery_get(d); d->active++;
    /* The current public client sends no END on an error return. A successful
     * call owns r until END; do not touch r after a successful dispatch. */
    int result = dns_client_query(path->names[path->links], family ? DNS_T_AAAA : DNS_T_A,
                                 discovery_result, r, "bootstrap-dns", &options);
    if (result) {
        d->active--; free(r); discovery_put(d);
        return -1;
    }
    return 0;
}
static void begin_generation(struct dns_upstream_discovery *d, unsigned long now, int issue_queries)
{
    if (d->cancelled || d->running || d->active) return;
    d->generation++; d->running = 1;
    d->generation_deadline = add_ms(now, DISCOVERY_GENERATION_MS);
    struct discovery_path path;
    memset(&path, 0, sizeof(path)); path.ttl = UINT_MAX; path.valid_until = ULONG_MAX;
    memcpy(path.names[0], d->host, strlen(d->host) + 1);
    for (int f = 0; f < 2; f++) {
        memset(&d->family[f].staged, 0, sizeof(d->family[f].staged));
        d->family[f].staged.path = path; d->family[f].done = 0;
    }
    if (issue_queries) {
        for (int f = 0; f < 2 && !d->cancelled; f++) {
            if (launch_request(d, f, &path)) {
                struct discovery_answer failure = {0}; failure.path = path;
                stage_answer(d, f, &failure, now);
            }
        }
    }
    if (!d->cancelled) reschedule(d, now);
}
struct dns_upstream_discovery *_dns_discovery_create(const char *host, dns_discovery_callback callback, void *user)
{
    if (!host || !callback) return NULL;
    struct dns_upstream_discovery *d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    if (normalize_name(d->host, host)) { free(d); return NULL; }
    d->refs = 1; d->callback = callback; d->user = user;
    d->refresh_due = ULONG_MAX; d->last.expires = ULONG_MAX;
    return d;
}
int _dns_discovery_start(struct dns_upstream_discovery *d)
{
    if (!d || d->cancelled) return -1;
    if (d->started) return 0;
    d->started = 1; d->refresh_due = get_tick_count();
    timer_set(d, d->refresh_due);
    return 0;
}
void _dns_discovery_destroy(struct dns_upstream_discovery *d)
{
    if (!d || d->cancelled) return;
    timer_remove(d); d->cancelled = 1; d->callback = NULL; d->user = NULL;
    discovery_put(d);
}
unsigned long _dns_discovery_next_deadline(void) { return timers ? timers->timer_due : ULONG_MAX; }
void _dns_discovery_run_due(unsigned long now)
{
    while (timers && timers->timer_due <= now) {
        struct dns_upstream_discovery *d = timers;
        discovery_get(d); timer_remove(d);
        publish(d, now, d->last.status);
        if (!d->cancelled && d->running && now >= d->generation_deadline) {
            for (int f = 0; f < 2; f++) if (!d->family[f].done) {
                struct discovery_answer failure = {0}; failure.path = d->family[f].staged.path;
                stage_answer(d, f, &failure, now);
                if (d->cancelled) break;
            }
        }
        if (!d->cancelled && !d->running && !d->active && now >= d->refresh_due)
            begin_generation(d, now, 1);
        if (!d->cancelled) reschedule(d, now);
        discovery_put(d);
    }
}
#ifdef TEST
int _dns_discovery_test_begin(struct dns_upstream_discovery *d, unsigned long now)
{
    if (!d || d->running || d->active) return -1;
    d->test_mode = 1; begin_generation(d, now, 0); return 0;
}
int _dns_discovery_test_answer(struct dns_upstream_discovery *d, int qtype, struct dns_packet *packet, unsigned long now)
{
    int f = qtype == DNS_T_AAAA;
    struct discovery_request r;
    memset(&r, 0, sizeof(r)); r.family = f; r.path = d->family[f].staged.path;
    struct discovery_answer answer;
    parse_answer(&r, packet, now, &answer);
    discovery_get(d);
    if (answer.kind == ANSWER_FOLLOW) d->family[f].staged.path = answer.path;
    else stage_answer(d, f, &answer, now);
    discovery_put(d);
    return answer.kind;
}
void _dns_discovery_test_failure(struct dns_upstream_discovery *d, int qtype, unsigned long now)
{
    int f = qtype == DNS_T_AAAA;
    struct discovery_answer failure = {0}; failure.path = d->family[f].staged.path;
    discovery_get(d); stage_answer(d, f, &failure, now); discovery_put(d);
}
void _dns_discovery_test_expire(struct dns_upstream_discovery *d, unsigned long now)
{
    discovery_get(d); publish(d, now, d->last.status); discovery_put(d);
}
void *_dns_discovery_test_hold_request(struct dns_upstream_discovery *d, int qtype)
{
    if (!d || !d->running || d->cancelled) return NULL;
    struct discovery_request *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->discovery = d; r->family = qtype == DNS_T_AAAA;
    r->path = d->family[r->family].staged.path; r->generation = d->generation;
    discovery_get(d); d->active++;
    return r;
}
int _dns_discovery_test_deliver(void *request, int result_type, struct dns_packet *packet)
{
    return discovery_result(NULL, (dns_result_type)result_type, NULL, packet, NULL, 0, request);
}
#endif
