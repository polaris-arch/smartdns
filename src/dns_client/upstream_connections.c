/* Bounded connection warmup, family staggering and protocol keepalive. */
#include "upstream_service.h"
#include "upstream_policy.h"
#include "client_socket.h"
#include "client_http3_control.h"
#include "client_http2.h"
#include "client_tls.h"
#include "smartdns/http2.h"
#include "smartdns/util.h"
#include <limits.h>
#include <string.h>
#include <errno.h>

static void next_due(struct dns_upstream_service *s, unsigned long now, unsigned long due)
{
    if (due <= now) due = now + 50;
    if (due < s->connection_due) s->connection_due = due;
}
static void quic_deadline(struct dns_upstream_service *s, struct dns_server_info *ep, unsigned long now)
{
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
    if (ep->ssl && (ep->type == DNS_SERVER_HTTP3 || ep->type == DNS_SERVER_QUIC)) {
        struct timeval timeout = {0}; int infinite = 1;
        if (SSL_get_event_timeout(ep->ssl, &timeout, &infinite) && !infinite)
            next_due(s, now, now + timeout.tv_sec * 1000UL + (timeout.tv_usec + 999) / 1000);
    }
#endif
}
static void connection_maintain(struct dns_upstream_service *s, struct dns_server_info *ep, unsigned long now)
{
    pthread_mutex_lock(&ep->lock);
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
    if (ep->ssl && (ep->type == DNS_SERVER_HTTP3 || ep->type == DNS_SERVER_QUIC)) {
        struct timeval timeout = {0}; int infinite = 1;
        if (SSL_get_event_timeout(ep->ssl, &timeout, &infinite) && !infinite) {
            unsigned long delay = timeout.tv_sec * 1000UL + (timeout.tv_usec + 999) / 1000;
            if (delay <= 1) {
                _dns_client_process_guard_enter(ep);
                _ssl_do_handevent(ep);
                /* handle_events may consume UDP packets into OpenSSL's buffers.
                 * Drain decoded streams now; the kernel fd may no longer be readable. */
                struct epoll_event event = {.events = EPOLLIN};
                int processed = _dns_client_process_tls(ep, &event, now);
                _dns_client_process_guard_leave(ep);
                if (processed < 0) {
                    if (ep->service_normal_close) _dns_service_detail(NULL, ep, DNS_DETAIL_IDLE_CLOSE, DNS_PHASE_HTTP3, 0, 0, 0);
                    else {
                        _dns_service_detail(NULL, ep, DNS_DETAIL_TRANSPORT_ERROR, ep->service_error_phase, ep->service_error_code, 0, 0);
                        _dns_service_endpoint_failure(ep);
                    }
                    _dns_client_close_socket(ep);
                }
                if (ep->ssl && SSL_get_event_timeout(ep->ssl, &timeout, &infinite) && !infinite)
                    delay = timeout.tv_sec * 1000UL + (timeout.tv_usec + 999) / 1000;
            }
            if (ep->ssl && !infinite) next_due(s, now, now + delay);
        }
    }
#endif
    if (ep->status == DNS_SERVER_STATUS_CONNECTED && !ep->service_protocol_ready) {
        int ready = 1;
        if (ep->type == DNS_SERVER_HTTPS && !strncmp(ep->alpn_selected, "h2", 2)) {
            struct epoll_event event = {.events = EPOLLOUT};
            ready = _dns_client_process_http2(ep, &event, now) < 0 ? -1 :
                http2_ctx_handshake_ready(ep->http2_ctx);
        } else if (ep->type == DNS_SERVER_HTTP3) {
            int control = _dns_http3_control_poll(ep); ready = control < 0 ? -1 : control == 0;
        }
        if (ready > 0) {
            __atomic_store_n(&ep->service_protocol_ready, 1, __ATOMIC_RELEASE);
            _dns_service_endpoint_ready(ep);
        } else if (!ready) next_due(s, now, now + 50);
        else if (ready < 0) { _dns_service_endpoint_failure(ep); _dns_client_close_socket(ep); }
    }
    if ((ep->status == DNS_SERVER_STATUS_CONNECTING ||
        (ep->status == DNS_SERVER_STATUS_CONNECTED && !ep->service_protocol_ready)) && ep->service_connect_tick) {
        unsigned long deadline = ep->service_connect_tick + s->config.connect_timeout_ms;
        if (now >= deadline) {
            _dns_service_detail(NULL, ep, DNS_DETAIL_CONNECT_TIMEOUT, DNS_PHASE_CONNECT, ETIMEDOUT,
                now - ep->service_connect_tick, s->config.connect_timeout_ms);
            _dns_service_endpoint_failure(ep); _dns_client_close_socket(ep);
        } else next_due(s, now, deadline);
    }
    if ((ep->service_draining || ep->service_rotation) && !ep->active_attempts && !ep->process_depth && list_empty(&ep->conn_stream_list)) {
        ep->service_normal_close = 1; _dns_client_close_socket(ep); ep->service_draining = ep->service_rotation = 0;
    }
    if (ep->status != DNS_SERVER_STATUS_CONNECTED || ep->service_draining || s->config.keepalive_disabled ||
        (ep->type != DNS_SERVER_HTTPS && ep->type != DNS_SERVER_HTTP3) ||
        (ep->type == DNS_SERVER_HTTPS && !ep->http2_ctx)) {
        ep->service_keepalive_interval_ms = 0; goto out;
    }
    if (ep->active_attempts) { next_due(s, now, now + 1000); goto out; }
    unsigned interval = s->config.keepalive_ms;
#if defined(OSSL_QUIC1_VERSION) && defined(SSL_VALUE_QUIC_IDLE_TIMEOUT)
    if (ep->type == DNS_SERVER_HTTP3 && ep->ssl) {
        uint64_t negotiated = 0;
        if (SSL_get_feature_negotiated_uint(ep->ssl, SSL_VALUE_QUIC_IDLE_TIMEOUT, &negotiated) &&
            negotiated && negotiated / 2 < interval) interval = negotiated / 2;
    }
#endif
    if (!interval) interval = 1;
    ep->service_keepalive_interval_ms = interval;
    if (ep->service_ping_tick && ep->http2_ctx) {
        if (http2_ctx_ping_acked(ep->http2_ctx, ep->service_ping_cookie)) {
            _dns_service_detail(NULL, ep, DNS_DETAIL_KEEPALIVE_ACK, DNS_PHASE_HTTP2, 0,
                now - ep->service_ping_tick, 5000); ep->service_ping_tick = 0;
        } else if (now - ep->service_ping_tick >= 5000) {
            _dns_service_detail(NULL, ep, DNS_DETAIL_KEEPALIVE_TIMEOUT, DNS_PHASE_HTTP2, ETIMEDOUT,
                now - ep->service_ping_tick, 5000);
            ep->service_ping_tick = 0; _dns_service_endpoint_failure(ep); _dns_client_close_socket(ep);
            goto out;
        } else next_due(s, now, ep->service_ping_tick + 5000);
    }
    /* Active application traffic already maintains liveness. A keepalive is a
     * protocol frame, never a DNS query and never consumes DNS QPS/send budget. */
    unsigned long last = ep->service_keepalive_tick;
    if (ep->send_tick > last) last = ep->send_tick;
    if (!ep->service_ping_tick && now >= last + interval) {
        int sent = -1;
        if (ep->type == DNS_SERVER_HTTPS && ep->http2_ctx) {
            uint64_t cookie = ++ep->service_ping_cookie;
            if (!cookie) cookie = ++ep->service_ping_cookie;
            if (http2_ctx_ping(ep->http2_ctx, cookie) >= 0) {
                ep->service_ping_tick = now; sent = 1; next_due(s, now, now + 5000);
                if (http2_ctx_want_write(ep->http2_ctx)) {
                    struct epoll_event event = {.events = EPOLLIN | EPOLLOUT, .data.ptr = ep};
                    if (epoll_ctl(client.epoll_fd, EPOLL_CTL_MOD, ep->fd, &event)) {
                        ep->service_system_error = errno;
                        _dns_service_detail(NULL, ep, DNS_DETAIL_TRANSPORT_ERROR, DNS_PHASE_SOCKET, errno, 0, 0);
                        _dns_service_endpoint_failure(ep); _dns_client_close_socket(ep);
                        goto out;
                    }
                }
            }
        } else if (ep->type == DNS_SERVER_HTTP3) sent = _dns_http3_keepalive(ep);
        if (sent > 0) {
            ep->service_keepalive_tick = now;
            _dns_service_detail(NULL, ep, DNS_DETAIL_KEEPALIVE_SENT,
                ep->type == DNS_SERVER_HTTP3 ? DNS_PHASE_HTTP3 : DNS_PHASE_HTTP2, 0, 0, interval);
        } else if (!sent) next_due(s, now, now + 100);
        else if (ep->type == DNS_SERVER_HTTP3) {
            _dns_service_detail(NULL, ep, DNS_DETAIL_TRANSPORT_ERROR, DNS_PHASE_HTTP3, ep->service_error_code, 0, 0);
            _dns_service_endpoint_failure(ep); _dns_client_close_socket(ep);
            goto out;
        } else ep->service_keepalive_tick = now; /* HTTP/1 has no protocol PING. */
    }
    next_due(s, now, ep->service_keepalive_tick + interval);
out:
    quic_deadline(s, ep, now); /* writes/control processing may create a new pacing deadline */
    pthread_mutex_unlock(&ep->lock);
}
void _dns_service_connection_tick(struct dns_upstream_service *s, unsigned long now)
{
    struct dns_server_info *members[DNS_UPSTREAM_BACKENDS_MAX * 2];
    unsigned count = 0;
    s->connection_due = ULONG_MAX;
    if (s->stopping || !s->desired) return;
    pthread_mutex_lock(&s->lock);
    for (unsigned pass = 0; pass < 2; pass++) for (unsigned i = 0; i < s->member_count; i++) {
        struct dns_server_info *ep = s->members[i];
        if (pass == 0 ? ep->service_member_id <= s->cursor : ep->service_member_id > s->cursor) continue;
        members[count++] = ep; dns_client_server_info_get(ep);
    }
    int demand = s->stats.in_flight != 0;
    pthread_mutex_unlock(&s->lock);
    for (unsigned i = 0; i < count; i++) connection_maintain(s, members[i], now);
    if (demand && !_dns_policy_service_cooldown(s, now)) {
        for (unsigned i = 0; i < count; i++) {
            struct dns_server_info *ep = members[i];
            if (ep->type == DNS_SERVER_UDP || !_dns_service_endpoint_eligible(ep, now)) continue;
            pthread_mutex_lock(&ep->lock);
            int needs = ep->fd < 0; unsigned family = strchr(ep->ip, ':') ? 6 : 4;
            pthread_mutex_unlock(&ep->lock);
            if (!needs) continue;
            if (s->race_due > now && s->race_family != family) {
                next_due(s, now, s->race_due); continue;
            }
            _dns_service_prepare_connection(ep);
            unsigned cap = s->flags.max_upstream_connections ? s->flags.max_upstream_connections : s->selected_count;
            if (!cap || __atomic_load_n(&s->connections, __ATOMIC_ACQUIRE) >= cap) {
                next_due(s, now, now + 100);
                break; /* standby warmup must not postpone traffic on healthy sockets */
            }
            if (_dns_client_create_socket(ep)) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) next_due(s, now, now + 100);
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    ep->service_system_error = errno;
                    _dns_service_detail(NULL, ep, DNS_DETAIL_TRANSPORT_ERROR, DNS_PHASE_CONNECT, errno, 0, 0);
                    _dns_service_endpoint_failure(ep);
                }
                continue;
            }
            s->race_family = family; s->race_due = now + s->config.connect_delay_ms;
            next_due(s, now, now + s->config.connect_timeout_ms);
            next_due(s, now, s->race_due);
            break; /* one new connection per service turn, within its shared cap */
        }
    }
    for (unsigned i = 0; i < count; i++) dns_client_server_info_release(members[i]);
}
