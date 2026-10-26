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

#include "prefetch.h"
#include "cache.h"
#include "dns_server.h"
#include "request.h"
#include "rules.h"
#include "smartdns/dns_client.h"
#include "smartdns/lib/hashtable.h"
#include <ctype.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "smartdns/dns_cache.h"

#define REFRESH_QUEUED_MAX 512
#define REFRESH_ACTIVE_MAX 64
#define REFRESH_TTL_MS 30000
enum refresh_state { REFRESH_QUEUED, REFRESH_CHECKING, REFRESH_ACTIVE };
struct refresh_key {
    char domain[DNS_MAX_CNAME_LEN], config_group[DNS_GROUP_NAME_LEN];
    dns_type_t qtype;
    uint32_t server_flags;
    unsigned long ecs_flags;
    struct dns_opt_ecs ecs;
    unsigned semantic_flags;
};
struct refresh_job {
    struct hlist_node hash;
    struct list_head list;
    struct refresh_key key;
    char server_group[DNS_GROUP_NAME_LEN];
    struct dns_server_query_option options;
    unsigned state, priority, origin_flags;
    int prefetch_flags;
    unsigned long queued_at, deadline, check_after;
    uint64_t cache_generation;
};
static DEFINE_HASHTABLE(refresh_jobs, 10);
static LIST_HEAD(refresh_waiting);
static pthread_mutex_t refresh_lock = PTHREAD_MUTEX_INITIALIZER;
static struct dns_refresh_queue_snapshot_v1 refresh_stats;
static int refresh_stopping;
static int refresh_changed, refresh_wake_pending;
static int refresh_group(struct refresh_job *job);
#ifdef TEST
int _dns_prefetch_test_paused;
#endif

static unsigned refresh_origin(int flags)
{
    unsigned source = 0;
    if (flags & PREFETCH_FLAGS_CACHE_HIT) source |= 2;
    if (flags & PREFETCH_FLAGS_EXPIRED) source |= 4;
    return source ? source : 8;
}
static uint32_t refresh_hash(const struct refresh_key *key)
{
    /* The key is zero-initialized before assignment, including its padding. */
    uint32_t hash = 2166136261U;
    const unsigned char *bytes = (const unsigned char *)key;
    for (size_t i = 0; i < sizeof(*key); i++) hash = (hash ^ bytes[i]) * 16777619U;
    return hash;
}
static void refresh_remove_locked(struct refresh_job *job)
{
    hash_del(&job->hash); list_del_init(&job->list);
    if (job->state == REFRESH_ACTIVE) { if (refresh_stats.active) refresh_stats.active--; }
    else if (refresh_stats.queued) refresh_stats.queued--;
}
void _dns_server_prefetch_done(void *ticket)
{
    struct refresh_job *job = ticket;
    if (!job) return;
    pthread_mutex_lock(&refresh_lock); refresh_stats.completed++; refresh_remove_locked(job); pthread_mutex_unlock(&refresh_lock);
    free(job); dns_server_refresh_notify();
}
void dns_server_refresh_notify(void)
{
    int wake = 0;
    pthread_mutex_lock(&refresh_lock);
    if (!refresh_stopping && refresh_stats.queued) {
        refresh_changed = 1;
        if (!refresh_wake_pending) { refresh_wake_pending = 1; wake = 1; }
    }
    pthread_mutex_unlock(&refresh_lock);
    if (wake && server.event_fd > 0) _dns_server_wakeup_thread();
}
unsigned long _dns_server_prefetch_deadline(void)
{
#ifdef TEST
    if (__atomic_load_n(&_dns_prefetch_test_paused, __ATOMIC_ACQUIRE)) return ULONG_MAX;
#endif
    unsigned long earliest = ULONG_MAX;
    pthread_mutex_lock(&refresh_lock);
    struct refresh_job *job;
    list_for_each_entry(job, &refresh_waiting, list) {
        unsigned long due = refresh_stats.active >= REFRESH_ACTIVE_MAX ? job->deadline :
            job->check_after < job->deadline ? job->check_after : job->deadline;
        if (due < earliest) earliest = due;
    }
    if (refresh_changed && refresh_stats.queued && refresh_stats.active < REFRESH_ACTIVE_MAX) earliest = 0;
    pthread_mutex_unlock(&refresh_lock); return earliest;
}
void _dns_server_prefetch_start(void)
{
    pthread_mutex_lock(&refresh_lock); refresh_stopping = refresh_changed = refresh_wake_pending = 0;
    pthread_mutex_unlock(&refresh_lock);
}
void _dns_server_prefetch_stop(void)
{
    pthread_mutex_lock(&refresh_lock); refresh_stopping = 1;
    refresh_changed = refresh_wake_pending = 0;
    struct refresh_job *job, *next;
    list_for_each_entry_safe(job, next, &refresh_waiting, list) {
        refresh_remove_locked(job); refresh_stats.dropped++; free(job);
    }
    pthread_mutex_unlock(&refresh_lock);
    /* Active tickets are owned by their requests and leave the hash on release. */
}
int dns_server_get_refresh_queue_v1(struct dns_refresh_queue_snapshot_v1 *out)
{
    if (!out) return -1;
    unsigned long now = get_tick_count();
    pthread_mutex_lock(&refresh_lock); *out = refresh_stats;
    out->struct_size = sizeof(*out); out->version = 1;
    out->oldest_wait_ms = 0;
    struct refresh_job *job;
    list_for_each_entry(job, &refresh_waiting, list) if (now >= job->queued_at && now - job->queued_at > out->oldest_wait_ms)
        out->oldest_wait_ms = now - job->queued_at;
    out->metadata_bytes = (uint64_t)(out->queued + out->active) * sizeof(*job) + sizeof(refresh_jobs);
    pthread_mutex_unlock(&refresh_lock); return 0;
}

int _dns_server_prefetch_cached(char *domain, dns_type_t qtype, struct dns_server_query_option *options,
    int flags, uint64_t generation)
{
    struct refresh_key key = {0};
    if (!domain || !*domain || strlen(domain) >= sizeof(key.domain)) return -1;
    for (size_t i = 0; domain[i]; i++) key.domain[i] = (char)tolower((unsigned char)domain[i]);
    key.qtype = qtype; key.semantic_flags = flags & (PREFETCH_FLAGS_NO_DUALSTACK | PREFETCH_FLAGS_NOPREFETCH);
    if (options) {
        if (options->dns_group_name && strlen(options->dns_group_name) >= sizeof(key.config_group)) return -1;
        safe_strncpy(key.config_group, options->dns_group_name, sizeof(key.config_group));
        key.server_flags = options->server_flags;
        key.ecs_flags = options->ecs_enable_flag & (DNS_QUEY_OPTION_ECS_DNS | DNS_QUEY_OPTION_EDNS0_DO);
        if (key.ecs_flags & DNS_QUEY_OPTION_ECS_DNS) {
            key.ecs = options->ecs_dns;
            unsigned bits = key.ecs.family == 1 ? 32 : key.ecs.family == 2 ? 128 : 0;
            if (!bits || key.ecs.source_prefix > bits || key.ecs.scope_prefix > bits) return -1;
            unsigned bytes = (key.ecs.source_prefix + 7) / 8;
            if (key.ecs.source_prefix % 8) key.ecs.addr[bytes - 1] &= 0xff << (8 - key.ecs.source_prefix % 8);
            memset(key.ecs.addr + bytes, 0, sizeof(key.ecs.addr) - bytes);
        }
    }
    uint32_t hash = refresh_hash(&key);
    pthread_mutex_lock(&refresh_lock);
    if (refresh_stopping) { refresh_stats.rejected++; pthread_mutex_unlock(&refresh_lock); return -1; }
    struct refresh_job *job;
    hash_for_each_possible(refresh_jobs, job, hash, hash) if (!memcmp(&job->key, &key, sizeof(key))) {
        job->prefetch_flags |= flags; job->origin_flags |= refresh_origin(flags);
        int promoted = job->priority > 1 && flags & (PREFETCH_FLAGS_CACHE_HIT | PREFETCH_FLAGS_EXPIRED);
        if (promoted) { __atomic_store_n(&job->priority, 1, __ATOMIC_RELEASE); job->check_after = 0; }
        refresh_stats.merged++; pthread_mutex_unlock(&refresh_lock);
        if (promoted) dns_server_refresh_notify();
        return 0;
    }
    if (refresh_stopping || refresh_stats.queued >= REFRESH_QUEUED_MAX) {
        refresh_stats.rejected++; pthread_mutex_unlock(&refresh_lock); return -1;
    }
    pthread_mutex_unlock(&refresh_lock);
    job = calloc(1, sizeof(*job));
    if (!job) {
        pthread_mutex_lock(&refresh_lock); refresh_stats.rejected++; pthread_mutex_unlock(&refresh_lock); return -1;
    }
    job->key = key; job->cache_generation = generation; job->prefetch_flags = flags;
    job->origin_flags = refresh_origin(flags);
    job->priority = flags & (PREFETCH_FLAGS_CACHE_HIT | PREFETCH_FLAGS_EXPIRED) ? 1 : 2;
    job->queued_at = get_tick_count(); job->deadline = job->queued_at > ULONG_MAX - REFRESH_TTL_MS ? ULONG_MAX : job->queued_at + REFRESH_TTL_MS;
    job->options.server_flags = key.server_flags; job->options.dns_group_name = job->key.config_group;
    job->options.ecs_enable_flag = key.ecs_flags; job->options.ecs_dns = key.ecs;
    /* Resolve outside the queue mutex. A cache timer can enqueue concurrently
     * with the server thread; rule and policy locks never nest inside it. */
    if (refresh_group(job)) {
        pthread_mutex_lock(&refresh_lock); refresh_stats.rejected++; pthread_mutex_unlock(&refresh_lock); free(job); return -1;
    }
    pthread_mutex_lock(&refresh_lock);
    if (refresh_stopping) {
        refresh_stats.rejected++; pthread_mutex_unlock(&refresh_lock); free(job); return -1;
    }
    struct refresh_job *existing;
    hash_for_each_possible(refresh_jobs, existing, hash, hash) if (!memcmp(&existing->key, &key, sizeof(key))) {
        existing->prefetch_flags |= flags; existing->origin_flags |= refresh_origin(flags);
        int promoted = existing->priority > 1 && flags & (PREFETCH_FLAGS_CACHE_HIT | PREFETCH_FLAGS_EXPIRED);
        if (promoted) { __atomic_store_n(&existing->priority, 1, __ATOMIC_RELEASE); existing->check_after = 0; }
        refresh_stats.merged++; pthread_mutex_unlock(&refresh_lock); free(job);
        if (promoted) dns_server_refresh_notify();
        return 0;
    }
    if (refresh_stopping || refresh_stats.queued >= REFRESH_QUEUED_MAX) {
        refresh_stats.rejected++; pthread_mutex_unlock(&refresh_lock); free(job); return -1;
    }
    hash_add(refresh_jobs, &job->hash, hash); list_add_tail(&job->list, &refresh_waiting);
    refresh_stats.enqueued++; if (++refresh_stats.queued > refresh_stats.peak) refresh_stats.peak = refresh_stats.queued;
    pthread_mutex_unlock(&refresh_lock); dns_server_refresh_notify(); return 0;
}
int _dns_server_prefetch_request(char *domain, dns_type_t qtype, struct dns_server_query_option *options, int flags)
{
    /* Timer/cache callers pass the known generation directly. This compatibility
     * entry has no proven baseline, so it never drops a fresh proactive lookup. */
    return _dns_server_prefetch_cached(domain, qtype, options, flags, 0);
}

static int refresh_group(struct refresh_job *job)
{
    /* Pure rule lookup on a temporary value: no request allocation, registration,
     * callback, socket or network health probe before admission. */
    struct dns_request probe = {0}; const char *group = NULL;
    safe_strncpy(probe.domain, job->key.domain, sizeof(probe.domain)); probe.qtype = job->key.qtype;
    _dns_server_setup_server_query_options(&probe, &job->options);
    if (_dns_server_setup_request_conf_pre(&probe)) return -1;
    _dns_server_get_domain_rule(&probe); _dns_server_setup_dns_group_name(&probe, &group);
    safe_strncpy(job->server_group, group, sizeof(job->server_group)); return 0;
}
static int refresh_is_newer(struct refresh_job *job)
{
    if (!job->cache_generation || job->key.ecs_flags) return 0;
    struct dns_cache_key key = {.domain = job->key.domain, .qtype = job->key.qtype,
        .dns_group_name = job->server_group, .query_flag = job->key.server_flags};
    struct dns_cache *entry = dns_cache_lookup(&key);
    if (!entry) return 0;
    int fresh = dns_cache_get_generation(entry) != job->cache_generation && dns_cache_get_ttl(entry) > 0;
    dns_cache_release(entry); return fresh;
}
static void refresh_run(unsigned long now)
{
    unsigned dispatched = 0;
    pthread_mutex_lock(&refresh_lock);
    if (refresh_changed) {
        struct refresh_job *job;
        list_for_each_entry(job, &refresh_waiting, list) job->check_after = 0;
        refresh_changed = 0;
    }
    refresh_wake_pending = 0;
    pthread_mutex_unlock(&refresh_lock);
    for (unsigned checked = 0; checked < 32 && dispatched < 16; checked++) {
        pthread_mutex_lock(&refresh_lock);
        if (refresh_stopping) { pthread_mutex_unlock(&refresh_lock); return; }
        struct refresh_job *job = NULL, *it;
        list_for_each_entry(it, &refresh_waiting, list) {
            if (it->check_after > now && it->deadline > now) continue;
            if (refresh_stats.active >= REFRESH_ACTIVE_MAX && it->deadline > now) continue;
            if (!job || it->priority < job->priority) job = it;
        }
        if (!job) { pthread_mutex_unlock(&refresh_lock); return; }
        list_del_init(&job->list); job->state = REFRESH_CHECKING;
        pthread_mutex_unlock(&refresh_lock);
        int expired = now >= job->deadline;
        int group_ok = !expired && refresh_group(job) == 0;
        int newer = group_ok && refresh_is_newer(job);
        unsigned wait = group_ok && !newer ? dns_client_background_wait(job->server_group,
            __atomic_load_n(&job->priority, __ATOMIC_ACQUIRE)) : 1000;
        int ready = group_ok && !newer && !wait;
        pthread_mutex_lock(&refresh_lock);
        if (refresh_stopping || expired || !group_ok || newer) {
            if (newer) refresh_stats.skipped_fresh++; else refresh_stats.dropped++;
            refresh_remove_locked(job); pthread_mutex_unlock(&refresh_lock); free(job); continue;
        }
        if (!ready) {
            job->check_after = now + wait; job->state = REFRESH_QUEUED;
            /* Skip the blocked context as a unit; a healthy group behind many
             * waiting names must not incur one readiness check per name. */
            list_for_each_entry(it, &refresh_waiting, list)
                if (it->priority >= job->priority && !strcmp(it->server_group, job->server_group)) it->check_after = now + wait;
            list_add_tail(&job->list, &refresh_waiting); pthread_mutex_unlock(&refresh_lock); continue;
        }
        int flags = job->prefetch_flags; unsigned origin = job->origin_flags;
        refresh_stats.queued--; refresh_stats.active++; refresh_stats.dispatched++;
        job->state = REFRESH_ACTIVE; pthread_mutex_unlock(&refresh_lock); dispatched++;
        struct dns_request *request = _dns_server_new_request();
        if (!request) {
            pthread_mutex_lock(&refresh_lock); refresh_stats.dispatch_errors++; pthread_mutex_unlock(&refresh_lock);
            _dns_server_prefetch_done(job); continue;
        }
        request->prefetch_ticket = job; request->prefetch = 1; request->prefetch_flags = flags;
        request->prefetch_origin_flags = origin;
        request->prefetch_queue_wait_ms = now >= job->queued_at ? now - job->queued_at : 0;
        safe_strncpy(request->domain, job->key.domain, sizeof(request->domain)); request->qtype = job->key.qtype;
        _dns_server_setup_server_query_options(request, &job->options);
        request->query_budget = dns_client_query_budget_new(job->server_group);
        if (request->query_budget) dns_query_budget_shorten(request->query_budget, job->deadline > now ? job->deadline - now : 0);
        int result = request->query_budget ? _dns_server_do_query(request, 0) : -1;
        if (result < 0) { pthread_mutex_lock(&refresh_lock); refresh_stats.dispatch_errors++; pthread_mutex_unlock(&refresh_lock); }
        _dns_server_request_release(request);
    }
}

void _dns_server_prefetch_run(unsigned long now)
{
#ifdef TEST
    if (__atomic_load_n(&_dns_prefetch_test_paused, __ATOMIC_ACQUIRE)) return;
#endif
    refresh_run(now);
}
#ifdef TEST
void _dns_server_prefetch_test_run(unsigned long now) { refresh_run(now); }
#endif

dns_cache_tmout_action_t _dns_server_prefetch_domain(struct dns_conf_group *conf_group, struct dns_cache *dns_cache)
{
	/* If there are still hits, continue pre-fetching */
	struct dns_server_query_option server_query_option;
	int hitnum = dns_cache_hitnum_dec_get(dns_cache);
	if (hitnum <= 0) {
		return DNS_CACHE_TMOUT_ACTION_DEL;
	}

	/* start prefetch domain */
	tlog(TLOG_DEBUG, "prefetch by cache %s, qtype %d, ttl %d, hitnum %d", dns_cache->info.domain, dns_cache->info.qtype,
		 dns_cache->info.ttl, hitnum);
	server_query_option.dns_group_name = dns_cache_get_dns_group_name(dns_cache);
	server_query_option.server_flags = dns_cache_get_query_flag(dns_cache);
	server_query_option.ecs_enable_flag = 0;
	if (_dns_server_prefetch_cached(dns_cache->info.domain, dns_cache->info.qtype, &server_query_option,
									 PREFETCH_FLAGS_NO_DUALSTACK, dns_cache_get_generation(dns_cache)) != 0) {
		tlog(TLOG_ERROR, "prefetch domain %s, qtype %d, failed.", dns_cache->info.domain, dns_cache->info.qtype);
		return DNS_CACHE_TMOUT_ACTION_RETRY;
	}

	return DNS_CACHE_TMOUT_ACTION_OK;
}

dns_cache_tmout_action_t _dns_server_prefetch_expired_domain(struct dns_conf_group *conf_group,
															 struct dns_cache *dns_cache)
{
	time_t ttl = _dns_server_expired_cache_ttl(dns_cache, conf_group->dns_serve_expired_ttl);
	if (ttl <= 1) {
		return DNS_CACHE_TMOUT_ACTION_DEL;
	}

	/* start prefetch domain */
	tlog(TLOG_DEBUG,
		 "expired domain, total %d, prefetch by cache %s, qtype %d, ttl %llu, rcode %d, insert time %llu replace time "
		 "%llu",
		 dns_cache_total_num(), dns_cache->info.domain, dns_cache->info.qtype, (unsigned long long)ttl,
		 dns_cache->info.rcode, (unsigned long long)dns_cache->info.insert_time,
		 (unsigned long long)dns_cache->info.replace_time);

	struct dns_server_query_option server_query_option;
	server_query_option.dns_group_name = dns_cache_get_dns_group_name(dns_cache);
	server_query_option.server_flags = dns_cache_get_query_flag(dns_cache);
	server_query_option.ecs_enable_flag = 0;

	if (_dns_server_prefetch_cached(dns_cache->info.domain, dns_cache->info.qtype, &server_query_option,
									 PREFETCH_FLAGS_EXPIRED, dns_cache_get_generation(dns_cache)) != 0) {
		tlog(TLOG_DEBUG, "prefetch domain %s, qtype %d, failed.", dns_cache->info.domain, dns_cache->info.qtype);
		return DNS_CACHE_TMOUT_ACTION_RETRY;
	}

	return DNS_CACHE_TMOUT_ACTION_OK;
}
