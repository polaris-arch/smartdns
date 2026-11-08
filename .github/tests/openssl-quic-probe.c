/* Test-only private dependency inspection; never linked into the product. */
#ifndef NDEBUG
# error "Compile private OpenSSL consumers with the pinned release ABI (-DNDEBUG)"
#endif
#include <string.h>
#include "internal/quic_ssl.h"
#include "internal/quic_channel.h"
#include "internal/quic_reactor.h"
#include "internal/quic_stream_map.h"
#include "ssl/quic/quic_channel_local.h"
#include "test/include/openssl-quic-probe.h"

/* The caller keeps the parent SSL alive (endpoint lock or peer owner thread).
 * Lock order is endpoint -> SDK engine. Only private non-locking SDK calls are
 * made under this mutex; callbacks never acquire the endpoint lock. */

static void count_stream(QUIC_STREAM *stream, void *arg)
{
    struct openssl_quic_stream_snapshot *out = arg;
    ++out->total;
    if (stream->id % 4 == 0) {
        if (out->requests == 0 || stream->id < out->oldest_request_id) {
            out->oldest_request_id = stream->id;
            out->oldest_request_send_state = stream->send_state;
            out->oldest_request_recv_state = stream->recv_state;
        }
        if (stream->id > out->newest_request_id)
            out->newest_request_id = stream->id;
        ++out->requests;
        out->deleted_requests += stream->deleted != 0;
        out->fully_received_requests += stream->recv_state == QUIC_RSTREAM_STATE_DATA_RECVD;
        out->fully_acked_requests += stream->send_state == QUIC_SSTREAM_STATE_DATA_RECVD;
        out->fully_read_requests += stream->recv_state == QUIC_RSTREAM_STATE_DATA_READ;
        out->deleted_ready_requests += stream->deleted && stream->ready_for_gc;
    } else if (stream->id & 2) {
        ++out->control;
    }
    out->ready_for_gc += stream->ready_for_gc != 0;
}

int test_openssl_quic_snapshot(SSL *ssl, struct openssl_quic_stream_snapshot *out)
{
    QUIC_CHANNEL *channel;
    if (ssl == NULL || out == NULL || (channel = ossl_quic_conn_get_channel(ssl)) == NULL)
        return 0;
    CRYPTO_MUTEX *mutex = ossl_quic_channel_get_mutex(channel);
    ossl_crypto_mutex_lock(mutex);
    memset(out, 0, sizeof(*out));
    ossl_quic_stream_map_visit(ossl_quic_channel_get_qsm(channel), count_stream, out);
    out->next_local_bidi_ordinal = channel->next_local_stream_ordinal_bidi;
    out->received_bytes = ossl_quic_rxfc_get_swm(&channel->conn_rxfc);
    out->retired_bytes = ossl_quic_rxfc_get_rwm(&channel->conn_rxfc);
    out->transmitted_bytes = ossl_quic_txfc_get_swm(&channel->conn_txfc);
    ossl_crypto_mutex_unlock(mutex);
    return 1;
}

int test_openssl_quic_receive_window(SSL *ssl, uint64_t size)
{
    QUIC_CHANNEL *ch = ossl_quic_conn_get_channel(ssl);
    int result = 0;
    if (ch == NULL)
        return 0;
    CRYPTO_MUTEX *mutex = ossl_quic_channel_get_mutex(ch);
    ossl_crypto_mutex_lock(mutex);
    if (ch->state == QUIC_CHANNEL_STATE_IDLE && ch->conn_rxfc.swm == 0
        && ch->conn_rxfc.rwm == 0 && size != 0)
        result = ossl_quic_rxfc_init(&ch->conn_rxfc, NULL, size, size,
                                   ch->conn_rxfc.now, ch->conn_rxfc.now_arg);
    ossl_crypto_mutex_unlock(mutex);
    return result;
}

int test_openssl_quic_single_tick(SSL *ssl)
{
    QUIC_CHANNEL *ch = ossl_quic_conn_get_channel(ssl);
    QUIC_TICK_RESULT result = {0};
    int flushed = 0;
    if (ch == NULL)
        return 0;
    CRYPTO_MUTEX *mutex = ossl_quic_channel_get_mutex(ch);
    ossl_crypto_mutex_lock(mutex);
    if (ossl_quic_channel_is_active(ch)) {
        ossl_quic_channel_subtick(ch, &result, 0);
        ossl_qtx_finish_dgram(ch->qtx);
        flushed = ossl_qtx_flush_net(ch->qtx);
    }
    ossl_crypto_mutex_unlock(mutex);
    return flushed;
}
