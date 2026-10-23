#include "upstream_service.h"
/* HTTP/3 connection control. Static-only QPACK; no additional QUIC connection. */
#include "client_http3_control.h"
#include "smartdns/util.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
#define H3_SLOTS 8
#define H3_BUFFER 8192
struct h3_peer_stream {
    SSL *ssl;
    unsigned char data[H3_BUFFER];
    size_t used;
    uint64_t type, skip;
    int typed, settings;
};
struct dns_http3_control {
    SSL *local;
    size_t sent;
    struct h3_peer_stream peer[H3_SLOTS];
    unsigned int seen;
    int settings, goaway;
    unsigned keepalive_pending, keepalive_offset;
    uint64_t goaway_id, fatal;
    unsigned long epoch;
    unsigned int accepts, bytes, transitions, rotate;
    int transport_fatal;
};
static int h3_fail(struct dns_http3_control *c, uint64_t code)
{
    if (!c->fatal) c->fatal = code;
    return -1;
}
/* 0 incomplete, otherwise bytes consumed. QUIC varints need not be minimal. */
static int h3_varint(const unsigned char *p, size_t n, uint64_t *v)
{
    if (!n) return 0;
    unsigned int bytes = 1U << (p[0] >> 6);
    if (n < bytes) return 0;
    *v = p[0] & 63;
    for (unsigned int i = 1; i < bytes; i++) *v = (*v << 8) | p[i];
    return bytes;
}
static void h3_consume(struct h3_peer_stream *p, size_t n)
{
    p->used -= n;
    if (p->used) memmove(p->data, p->data + n, p->used);
}
static int h3_id_compare(const void *a, const void *b)
{
    uint64_t left = *(const uint64_t *)a, right = *(const uint64_t *)b;
    return left < right ? -1 : left > right;
}
static int h3_settings(const unsigned char *p, size_t n)
{
    uint64_t ids[2048];
    size_t count = 0, offset = 0;
    while (offset < n) {
        uint64_t id, value;
        int a = h3_varint(p + offset, n - offset, &id);
        if (!a) return -1;
        offset += a;
        int b = h3_varint(p + offset, n - offset, &value);
        if (!b || count == 2048) return -1;
        offset += b;
        ids[count++] = id;
        if (id >= 2 && id <= 5) return -1; /* prohibited HTTP/2 settings */
        if ((id == 8 || id == 0x33) && value > 1) return -1;
        /* Peer QPACK capacity limits our encoder, which always uses zero. */
    }
    qsort(ids, count, sizeof(ids[0]), h3_id_compare);
    for (size_t i = 1; i < count; i++) if (ids[i] == ids[i - 1]) return -1;
    return 0;
}
static int h3_parse(struct dns_http3_control *c, struct h3_peer_stream *p)
{
    if (!p->typed) {
        int n = h3_varint(p->data, p->used, &p->type);
        if (!n) return 0;
        p->typed = 1; h3_consume(p, n);
        if (p->type == 1) return h3_fail(c, 0x108); /* no MAX_PUSH_ID has been sent */
        if (p->type != 0 && p->type != 2 && p->type != 3) return 1;
        unsigned int bit = 1U << p->type;
        if (c->seen & bit) return h3_fail(c, 0x103);
        c->seen |= bit;
    }
    if (p->type == 2) {
        /* RFC 9204 forbids instructions with maximum capacity zero. Google
         * nevertheless sends Set Dynamic Table Capacity(0). Tolerate only
         * that idempotent instruction, never inserts or a positive capacity.
         * Handle fragmented streams within the existing work budget. */
        while (p->used) {
            if (c->transitions >= 64) return 0;
            if ((p->data[0] & 0xe0) != 0x20) return h3_fail(c, 0x201);
            /* Zero has exactly this representation; a saturated five-bit
             * prefix is already positive, even before continuation bytes. */
            if (p->data[0] != 0x20) return h3_fail(c, 0x201);
            h3_consume(p, 1);
            c->transitions++;
        }
        return 0;
    }
    if (p->type == 3) {
        while (p->used) {
            if (c->transitions >= 64) return 0;
            if ((p->data[0] & 0xc0) != 0x40) return h3_fail(c, 0x202); /* only Stream Cancellation is legal */
            uint64_t id = p->data[0] & 0x3f;
            size_t n = 1;
            if (id == 0x3f) {
                unsigned int shift = 0;
                for (;;) {
                    if (n == p->used) return 0;
                    unsigned int byte = p->data[n++];
                    if (shift >= 63 || (uint64_t)(byte & 127) > (UINT64_MAX - id) >> shift) return h3_fail(c, 0x202);
                    id += (uint64_t)(byte & 127) << shift;
                    if (!(byte & 128)) break;
                    shift += 7;
                }
            }
            if (id & 3) return h3_fail(c, 0x202);
            h3_consume(p, n);
            c->transitions++;
        }
        return 0;
    }
    for (;;) {
        if (c->transitions >= 64) return 0;
        if (p->skip) {
            size_t n = p->skip < p->used ? (size_t)p->skip : p->used;
            p->skip -= n; h3_consume(p, n);
            if (p->skip) return 0;
        }
        uint64_t type, len;
        int a = h3_varint(p->data, p->used, &type);
        if (!a) return 0;
        int b = h3_varint(p->data + a, p->used - a, &len);
        if (!b) return 0;
        size_t header = a + b;
        if (!p->settings && type != 4) return h3_fail(c, 0x10a);
        if (type == 4) {
            if (p->settings) return h3_fail(c, 0x105);
            if (len > 4096) return h3_fail(c, 0x107);
            if (len > p->used - header) return 0;
            if (h3_settings(p->data + header, len)) return h3_fail(c, 0x109);
            p->settings = 1; c->settings = 1;
        } else if (type == 7) {
            uint64_t id;
            if (len > 8) return h3_fail(c, 0x106);
            if (len > p->used - header) return 0;
            int bytes = h3_varint(p->data + header, len, &id);
            if (!bytes || (uint64_t)bytes != len) return h3_fail(c, 0x106);
            if ((id & 3) || (c->goaway && id > c->goaway_id)) return h3_fail(c, 0x108);
            c->goaway = 1; c->goaway_id = id;
        } else {
            if (type == 0 || type == 1 || type == 3 || type == 5 || type == 13 || type == 2 || type == 6 || type == 8 || type == 9) return h3_fail(c, 0x105);
            h3_consume(p, header); p->skip = len; c->transitions++; continue;
        }
        h3_consume(p, header + (size_t)len);
        c->transitions++;
    }
}
static int h3_control_poll(struct dns_server_info *s)
{
    if (s->type != DNS_SERVER_HTTP3) return 0;
    if (!s->ssl || s->status != DNS_SERVER_STATUS_CONNECTED) return 1;
    struct dns_http3_control *c = s->http3_control;
    if (!c) {
        c = calloc(1, sizeof(*c));
        if (!c) return -1;
        s->http3_control = c;
    }
    if (c->fatal || c->transport_fatal) return -1;
    if (c->epoch != s->http3_control_epoch) {
        c->epoch = s->http3_control_epoch;
        c->accepts = c->bytes = c->transitions = 0;
    }
    if (!c->local) {
        c->local = SSL_new_stream(s->ssl, SSL_STREAM_FLAG_UNI);
        if (!c->local) return 1;
    }
    int local_state = SSL_get_stream_write_state(c->local);
    if (local_state != SSL_STREAM_STATE_OK) {
        if (local_state == SSL_STREAM_STATE_CONN_CLOSED) c->transport_fatal = 1;
        return h3_fail(c, 0x104);
    }
    /* stream type, SETTINGS frame length, capacity=0, blocked-streams=0 */
    static const unsigned char settings[] = {0, 4, 4, 1, 0, 7, 0};
    if (c->sent < sizeof(settings)) {
        size_t written = 0;
        int ok = SSL_write_ex(c->local, settings + c->sent, sizeof(settings) - c->sent, &written);
        if (!ok) {
            int err = SSL_get_error(c->local, ok);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                if (SSL_get_stream_write_state(c->local) == SSL_STREAM_STATE_CONN_CLOSED)
                    c->transport_fatal = 1;
                return h3_fail(c, 0x104);
            }
        }
        c->sent += written;
        if (c->sent < sizeof(settings)) return 1;
    }
    for (; c->accepts < H3_SLOTS; c->accepts++) {
        size_t slot;
        for (slot = 0; slot < H3_SLOTS; slot++) if (!c->peer[slot].ssl) break;
        if (slot == H3_SLOTS) {
            if (SSL_get_accept_stream_queue_len(s->ssl)) return h3_fail(c, 0x107);
            break;
        }
        SSL *ssl = SSL_accept_stream(s->ssl, SSL_ACCEPT_STREAM_NO_BLOCK);
        if (!ssl) break;
        if ((SSL_get_stream_id(ssl) & 3) != 3) { SSL_free(ssl); return h3_fail(c, 0x103); }
        c->peer[slot].ssl = ssl;
    }
    /* Cumulative per outer event turn: 16KiB / 64 transitions / eight accepts. */
    for (size_t i = 0; i < H3_SLOTS && c->bytes < 16384 && c->transitions < 64; i++) {
        struct h3_peer_stream *p = &c->peer[(c->rotate + i) % H3_SLOTS];
        if (!p->ssl) continue;
        int parsed = h3_parse(c, p);
        if (parsed < 0) return h3_fail(c, 0x101);
        if (parsed > 0) { SSL_free(p->ssl); memset(p, 0, sizeof(*p)); continue; }
        if (c->transitions >= 64) break;
        if (p->used == sizeof(p->data)) return h3_fail(c, 0x107);
        size_t received = 0, room = sizeof(p->data) - p->used;
        if (room > 16384 - c->bytes) room = 16384 - c->bytes;
        int ok = SSL_read_ex(p->ssl, p->data + p->used, room, &received);
        if (!ok) {
            int err = SSL_get_error(p->ssl, ok);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                if (SSL_get_stream_read_state(p->ssl) == SSL_STREAM_STATE_CONN_CLOSED)
                    c->transport_fatal = 1;
                return h3_fail(c, 0x104);
            }
        }
        p->used += received; c->bytes += received;
        int ret = h3_parse(c, p);
        if (ret < 0) return h3_fail(c, 0x101);
        if (ret > 0) { SSL_free(p->ssl); memset(p, 0, sizeof(*p)); }
    }
    c->rotate = (c->rotate + 1) % H3_SLOTS;
    return 0;
}
int _dns_http3_keepalive(struct dns_server_info *s)
{
    struct dns_http3_control *c = s->http3_control;
    if (!c || !c->local || c->sent != 7) return 0;
    if (c->fatal || c->goaway) return -1;
    static const unsigned char grease[] = {0x21, 0}; /* RFC 9114 7.2.8 */
    c->keepalive_pending = 1;
    size_t written = 0;
    int ok = SSL_write_ex(c->local, grease + c->keepalive_offset,
        sizeof(grease) - c->keepalive_offset, &written);
    if (!ok) {
        int error = SSL_get_error(c->local, ok);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
            s->service_error_phase = DNS_PHASE_HTTP3; s->service_error_code = error;
            s->service_system_error = errno; return -1;
        }
    }
    c->keepalive_offset += written;
    if (c->keepalive_offset < sizeof(grease)) return 0;
    c->keepalive_pending = c->keepalive_offset = 0; return 1;
}
int _dns_http3_control_poll(struct dns_server_info *s)
{
    pthread_mutex_lock(&s->lock);
    int was_draining = s->http3_control && s->http3_control->goaway;
    int ret = h3_control_poll(s);
    if (!was_draining && s->http3_control && s->http3_control->goaway) {
        s->service_draining = 1;
        _dns_service_detail(NULL, s, DNS_DETAIL_GOAWAY, DNS_PHASE_HTTP3, 0, 0, 0);
    }
    if (ret < 0 && s->http3_control) {
        s->service_error_phase = DNS_PHASE_HTTP3; s->service_error_code = s->http3_control->fatal;
    }
    pthread_mutex_unlock(&s->lock);
    return ret;
}
int _dns_http3_request_allowed(struct dns_server_info *s, uint64_t id, int started)
{
    struct dns_http3_control *c = s->http3_control;
    return c && c->sent == 7 && !c->fatal &&
        (!c->goaway || (started && id < c->goaway_id));
}
int _dns_http3_connection_error(struct dns_server_info *s, uint64_t code)
{
    if (!s->http3_control) s->http3_control = calloc(1, sizeof(struct dns_http3_control));
    return s->http3_control ? h3_fail(s->http3_control, code) : -1;
}
uint64_t _dns_http3_error(struct dns_server_info *s)
{
    return s->http3_control ? s->http3_control->fatal : 0;
}
int _dns_http3_is_draining(struct dns_server_info *s)
{
    return s->http3_control && s->http3_control->goaway;
}
int _dns_http3_control_shutdown(struct dns_server_info *s)
{
    struct dns_http3_control *c = s->http3_control;
    if (!c) return 0;
    if (c->transport_fatal) return 1;
    if (!c->fatal) return 0;
    tlog(TLOG_DEBUG, "http3 protocol error from %s:%d: 0x%llx", s->ip, s->port,
         (unsigned long long)c->fatal);
    SSL_SHUTDOWN_EX_ARGS args = {0};
    args.quic_error_code = c->fatal;
    args.quic_reason = "HTTP/3 connection protocol error";
    SSL_shutdown_ex(s->ssl, SSL_SHUTDOWN_FLAG_NO_BLOCK | SSL_SHUTDOWN_FLAG_NO_STREAM_FLUSH, &args, sizeof(args));
    return 1;
}
void _dns_http3_control_free(struct dns_server_info *s)
{
    struct dns_http3_control *c = s->http3_control;
    if (!c) return;
    for (size_t i = 0; i < H3_SLOTS; i++) SSL_free(c->peer[i].ssl);
    SSL_free(c->local); free(c); s->http3_control = NULL;
}
#ifdef TEST
int _dns_http3_control_test_feed(struct dns_server_info *s, unsigned slot, const unsigned char *data, size_t len)
{
    if (slot >= H3_SLOTS) return -1;
    if (!s->http3_control) s->http3_control = calloc(1, sizeof(struct dns_http3_control));
    struct dns_http3_control *c = s->http3_control;
    if (!c || c->fatal) return -1;
    c->sent = 7;
    c->transitions = 0;
    struct h3_peer_stream *p = &c->peer[slot];
    if (len > sizeof(p->data) - p->used) return -1;
    if (len) memcpy(p->data + p->used, data, len);
    p->used += len;
    return h3_parse(c, p);
}
#endif

#else
int _dns_http3_control_poll(struct dns_server_info *s) { (void)s; return -1; }
int _dns_http3_request_allowed(struct dns_server_info *s, uint64_t id, int started) { (void)s; (void)id; (void)started; return 0; }
int _dns_http3_is_draining(struct dns_server_info *s) { (void)s; return 0; }
int _dns_http3_keepalive(struct dns_server_info *s) { (void)s; return -1; }
int _dns_http3_connection_error(struct dns_server_info *s, uint64_t code) { (void)s; (void)code; return -1; }
uint64_t _dns_http3_error(struct dns_server_info *s) { (void)s; return 0; }
int _dns_http3_control_shutdown(struct dns_server_info *s) { (void)s; return 0; }
void _dns_http3_control_free(struct dns_server_info *s) { (void)s; }
#endif
