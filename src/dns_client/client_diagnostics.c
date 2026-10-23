/* Bounded client-loop observations; no query names, logs or polling thread.
 * GPL-3.0-or-later. */
#include "upstream_service.h"
#include "smartdns/util.h"
#include "smartdns/tlog.h"
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include <unistd.h>

static struct dns_client_loop_diagnostics_v1 loop;
static pthread_mutex_t sample_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long last_tick;
static uint64_t last_cpu;
static unsigned long ready_window, last_ready_warning;
static unsigned window_polls, ready_reports;

static int thread_cpu(uint64_t *value)
{
#ifdef CLOCK_THREAD_CPUTIME_ID
    struct timespec ts;
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts)) return -1;
    *value = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    return 0;
#else
    return -1;
#endif
}
void _dns_client_loop_diagnostic_start(unsigned long now)
{
    pthread_mutex_lock(&sample_lock);
#define RESET(field) __atomic_store_n(&loop.field, 0, __ATOMIC_RELAXED)
    RESET(iterations); RESET(zero_waits); RESET(zero_wait_no_events);
    RESET(ready_events); RESET(wakeups); RESET(periodic_runs);
#undef RESET
    loop.struct_size = sizeof(loop); loop.version = 1;
#ifdef SYS_gettid
    loop.thread_id = syscall(SYS_gettid);
#endif
    last_tick = now; last_cpu = 0;
    ready_window = now; last_ready_warning = 0; window_polls = ready_reports = 0;
    loop.cpu_clock_available = thread_cpu(&last_cpu) == 0;
    loop.cpu_total_ns = last_cpu; loop.sample_cpu_ns = 0;
    loop.sample_wall_ms = 0; loop.sample_tick_ms = now;
    pthread_mutex_unlock(&sample_lock);
}
void _dns_client_loop_diagnostic_poll(unsigned long now, int timeout, int events)
{
    if (now < ready_window || now - ready_window >= 1000) {
        ready_window = now; window_polls = ready_reports = 0;
    }
    if (++window_polls == 4096 && (!last_ready_warning || now - last_ready_warning >= 30000)) {
        last_ready_warning = now; ready_reports = 4;
    }
    __atomic_add_fetch(&loop.iterations, 1, __ATOMIC_RELAXED);
    if (!timeout) {
        __atomic_add_fetch(&loop.zero_waits, 1, __ATOMIC_RELAXED);
        if (!events) __atomic_add_fetch(&loop.zero_wait_no_events, 1, __ATOMIC_RELAXED);
    }
    if (events > 0) __atomic_add_fetch(&loop.ready_events, events, __ATOMIC_RELAXED);
    if (now < last_tick || now - last_tick < 1000) return;
    uint64_t cpu;
    if (thread_cpu(&cpu)) return;
    pthread_mutex_lock(&sample_lock);
    loop.cpu_total_ns = cpu;
    loop.sample_cpu_ns = cpu >= last_cpu ? cpu - last_cpu : 0;
    loop.sample_wall_ms = now - last_tick; loop.sample_tick_ms = now;
    pthread_mutex_unlock(&sample_lock);
    last_tick = now; last_cpu = cpu;
}
/* Client thread only; caller already holds ep->lock. No per-query data or
 * extra clocks. At most four descriptor samples per 30 seconds. */
void _dns_client_loop_diagnostic_ready(struct dns_server_info *ep, unsigned events, unsigned long now, int eligible)
{
    if (!ready_reports) return;
    ready_reports--;
    tlog(TLOG_WARN, "client epoll burst: polls=%u window_ms=%lu sample fd=%d type=%d alpn=%s endpoint=%s:%d "
         "events=0x%x eligible=%d revoked=%u active_attempts=%u",
         window_polls, now >= ready_window ? now - ready_window : 0, ep->fd, ep->type, ep->alpn_selected,
         ep->ip, ep->port, events, eligible, ep->service_revoked, ep->active_attempts);
}
void _dns_client_loop_diagnostic_wake(void)
{ __atomic_add_fetch(&loop.wakeups, 1, __ATOMIC_RELAXED); }
void _dns_client_loop_diagnostic_period(void)
{ __atomic_add_fetch(&loop.periodic_runs, 1, __ATOMIC_RELAXED); }
int dns_client_get_loop_diagnostics_v1(struct dns_client_loop_diagnostics_v1 *out)
{
    if (!out) return -1;
    pthread_mutex_lock(&sample_lock);
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out); out->version = 1;
    out->thread_id = loop.thread_id; out->cpu_clock_available = loop.cpu_clock_available;
    out->cpu_total_ns = loop.cpu_total_ns; out->sample_cpu_ns = loop.sample_cpu_ns;
    out->sample_wall_ms = loop.sample_wall_ms; out->sample_tick_ms = loop.sample_tick_ms;
    unsigned long now = get_tick_count();
    out->sample_age_ms = now >= loop.sample_tick_ms ? now - loop.sample_tick_ms : 0;
    pthread_mutex_unlock(&sample_lock);
#define COPY(field) out->field = __atomic_load_n(&loop.field, __ATOMIC_RELAXED)
    COPY(iterations); COPY(zero_waits); COPY(zero_wait_no_events);
    COPY(ready_events); COPY(wakeups); COPY(periodic_runs);
#undef COPY
    return 0;
}
