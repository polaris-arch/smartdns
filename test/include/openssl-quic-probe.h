#ifndef SMARTDNS_TEST_OPENSSL_QUIC_PROBE_H
#define SMARTDNS_TEST_OPENSSL_QUIC_PROBE_H
#include <openssl/ssl.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct openssl_quic_stream_snapshot {
    size_t total, requests, deleted_requests, ready_for_gc, control;
    size_t fully_received_requests, fully_acked_requests;
    size_t fully_read_requests, deleted_ready_requests;
    uint64_t oldest_request_id, newest_request_id, next_local_bidi_ordinal;
    unsigned oldest_request_send_state, oldest_request_recv_state;
    uint64_t received_bytes, retired_bytes, transmitted_bytes;
};
/* Caller keeps the parent SSL alive through its endpoint lock or owner thread.
 * Helpers acquire the SDK engine mutex themselves; do not call with it held.
 * These private APIs are linked only into the mandatory CI profile. */
int test_openssl_quic_snapshot(SSL *, struct openssl_quic_stream_snapshot *);
/* Before the initial handshake only: advertise a genuinely small connection
 * window so a peer is demonstrably blocked, instead of masking retirement. */
int test_openssl_quic_receive_window(SSL *, uint64_t);
/* Exactly one real channel subtick and transport flush. No app read/write or
 * second event tick can accidentally publish credit after GC. */
int test_openssl_quic_single_tick(SSL *);
#ifdef __cplusplus
}
#endif
#endif
