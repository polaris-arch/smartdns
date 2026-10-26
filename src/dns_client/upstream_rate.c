/* Passive per-exit learning, not a claim about a provider's configured quota. */
#include "upstream_rate.h"
#include <string.h>

void _dns_rate_init(struct dns_rate_controller *r, unsigned cap)
{
    memset(r, 0, sizeof(*r)); r->cap = r->probe_cap = cap; r->current = cap < 20 ? cap : 20;
}
void _dns_rate_sent(struct dns_rate_controller *r, uint64_t now)
{
    if (!r->cap) return;
    if (!r->first_sent) r->first_sent = now;
    struct dns_rate_window *w = r->windows + now / 1000 % DNS_RATE_WINDOWS;
    if (w->second != now / 1000) { memset(w, 0, sizeof(*w)); w->second = now / 1000; w->rate = r->current; }
    if (w->rate != r->current) w->rate = 0; /* mixed-control windows are not capacity evidence */
    w->sent++;
}
void _dns_rate_demand(struct dns_rate_controller *r, uint64_t now)
{
    if (!r->cap) return;
    struct dns_rate_window *w = r->windows + now / 1000 % DNS_RATE_WINDOWS;
    if (w->second != now / 1000) { memset(w, 0, sizeof(*w)); w->second = now / 1000; w->rate = r->current; }
    w->demand = 1;
}
static unsigned clean_saturated_windows(struct dns_rate_controller *r, uint64_t now, unsigned *observed)
{
    unsigned clean = 0;
    *observed = r->current;
    for (unsigned i = 0; i < DNS_RATE_WINDOWS; i++) {
        struct dns_rate_window *w = r->windows + i;
        /* Exclude startup/burst and windows with unreturned/censored responses.
         * Delay alone cannot turn outstanding replies into failed samples. */
        if (w->second <= r->first_sent / 1000 + 1 || w->second + 1 >= now / 1000 ||
            w->second + 7 < now / 1000 || w->rate != r->current || w->rejected ||
            !w->demand || w->sent != w->accepted || (uint64_t)w->sent * 100 < (uint64_t)r->current * 95) continue;
        clean++;
        if (w->accepted < *observed) *observed = w->accepted;
    }
    return clean;
}
void _dns_rate_accepted(struct dns_rate_controller *r, uint64_t sent, uint64_t now)
{
    if (!r->cap || !sent) return;
    struct dns_rate_window *w = r->windows + sent / 1000 % DNS_RATE_WINDOWS;
    if (w->second == sent / 1000) w->accepted++;
    unsigned observed;
    if (clean_saturated_windows(r, now, &observed) < 4) return;
    uint64_t since = r->changed > r->first_sent ? r->changed : r->first_sent;
    if (r->last_rejected > since) since = r->last_rejected;
    if (r->last_increase > since) since = r->last_increase;
    if (now < since || now - since < 30000) return;
    r->known_good = observed;
    /* A rejected probe narrows the temporary ceiling. Continue serving at the
     * learned rate; do not produce another 429 every 30 seconds just to learn
     * the same fact. Only queued natural traffic can probe again after 5 min. */
    if (r->probe_after && now >= r->probe_after) { r->probe_cap = r->cap; r->probe_after = 0; }
    if (r->current >= r->probe_cap) return;
    unsigned step = r->current / 10; if (!step) step = 1;
    r->current = step > r->probe_cap - r->current ? r->probe_cap : r->current + step;
    r->changed = r->last_increase = now;
}
int _dns_rate_rejected(struct dns_rate_controller *r, uint64_t sent, uint64_t now)
{
    if (!r->cap) return 0;
    if (sent) {
        struct dns_rate_window *w = r->windows + sent / 1000 % DNS_RATE_WINDOWS;
        if (w->second == sent / 1000) w->rejected++;
    }
    r->last_rejected = now;
    /* One reduction for one sending epoch. Late replies from its old in-flight
     * wave cannot repeatedly halve a rate already reduced by that wave. */
    if (r->changed && (!sent || sent < r->changed)) return 0;
    unsigned upper = r->current > 1 ? r->current - 1 : 1;
    if (upper < r->probe_cap) r->probe_cap = upper;
    r->probe_after = now + 300000;
    unsigned reduced = r->current / 2; if (!reduced) reduced = 1;
    if (r->known_good < r->current && r->known_good > reduced) reduced = r->known_good;
    r->changed = now; r->current = reduced;
    return 1;
}
