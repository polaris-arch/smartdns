/* Deterministic tests of the real statically linked dependency, not a model of
 * its GC predicate. Run one named case per process with a bounded CI deadline.
 * SD_QUIC_PATCHED selects the actual private signature of each exact variant.
 */
#ifndef NDEBUG
# error "Compile private OpenSSL consumers with the pinned release ABI (-DNDEBUG)"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include "internal/quic_stream_map.h"
#include "internal/quic_fifd.h"
#include "internal/quic_txp.h"
#include "internal/quic_statm.h"
#include "internal/quic_ssl.h"
#include "internal/quic_channel.h"
#include "internal/quic_rx_depack.h"
#include "internal/quic_error.h"
#include "internal/quic_demux.h"
#include "internal/quic_wire.h"
#include "internal/packet.h"
#include "ssl/quic/quic_channel_local.h"
#include "ssl/quic/quic_record_rx_local.h"

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); ok = 0; goto cleanup; } } while (0)

static OSSL_TIME now_value;
static OSSL_TIME now_cb(void *arg) { (void)arg; return now_value; }
static void *watched[64];
static size_t released;
void __real_CRYPTO_free(void *, const char *, int);
void __wrap_CRYPTO_free(void *ptr, const char *file, int line)
{
    size_t i;
    if (ptr != NULL)
        for (i = 0; i < sizeof(watched) / sizeof(*watched); ++i)
            if (watched[i] == ptr) { watched[i] = NULL; ++released; break; }
    __real_CRYPTO_free(ptr, file, line);
}
static void watch(void *ptr)
{
    size_t i;
    for (i = 0; i < sizeof(watched) / sizeof(*watched); ++i)
        if (watched[i] == NULL) { watched[i] = ptr; return; }
    abort();
}

static int collect(QUIC_STREAM_MAP *map)
{
#ifdef SD_QUIC_PATCHED
    return ossl_quic_stream_map_gc(map, ossl_ms2time(10));
#else
    ossl_quic_stream_map_gc(map);
    return 1;
#endif
}

struct map_fixture {
    QUIC_STREAM_MAP map;
    QUIC_RXFC connection, max_bidi, max_uni;
    QUIC_TXFC tx_connection;
    QUIC_CHANNEL *buffer_channel;
    QUIC_RSTREAM_QPARM *qparm;
    int initialized;
};
static int map_init(struct map_fixture *f)
{
    memset(f, 0, sizeof(*f));
    f->buffer_channel = OPENSSL_zalloc(sizeof(*f->buffer_channel));
    if (f->buffer_channel == NULL)
        return 0;
    f->qparm = ossl_quic_rstream_qparm_new(f->buffer_channel);
    if (f->qparm == NULL
        || !ossl_quic_txfc_init(&f->tx_connection, NULL)
        || !ossl_quic_rxfc_init(&f->connection, NULL, 16, 16, now_cb, NULL)
        || !ossl_quic_rxfc_init(&f->max_bidi, NULL, 32, 32, now_cb, NULL)
        || !ossl_quic_rxfc_init(&f->max_uni, NULL, 32, 32, now_cb, NULL)
        || !ossl_quic_stream_map_init(&f->map, NULL, NULL, &f->max_bidi, &f->max_uni, 0))
        return 0;
    f->initialized = 1;
    return 1;
}
static void map_cleanup(struct map_fixture *f)
{
    if (f->initialized) ossl_quic_stream_map_cleanup(&f->map);
    ossl_quic_rstream_qparm_destroy(f->qparm);
    OPENSSL_free(f->buffer_channel);
}
static QUIC_STREAM *stream_new(struct map_fixture *f, uint64_t id, int type)
{
    QUIC_STREAM *s = ossl_quic_stream_map_alloc(&f->map, id, type);
    if (s == NULL) return NULL;
    watch(s);
    if (ossl_quic_stream_has_send(s)) {
        s->sstream = ossl_quic_sstream_new(256);
        if (s->sstream == NULL || !ossl_quic_txfc_init(&s->txfc, &f->tx_connection)) return NULL;
    }
    if (ossl_quic_stream_has_recv(s)) {
        if (!ossl_quic_rxfc_init(&s->rxfc, &f->connection, 16, 16, now_cb, NULL)) return NULL;
        s->rstream = ossl_quic_rstream_new(&s->rxfc, NULL, f->qparm);
        if (s->rstream == NULL) return NULL;
    }
    return s;
}
static int send_state(struct map_fixture *f, QUIC_STREAM *s, unsigned state)
{
    if (state == QUIC_SSTREAM_STATE_NONE) return s->send_state == state;
    if (state == QUIC_SSTREAM_STATE_RESET_SENT || state == QUIC_SSTREAM_STATE_RESET_RECVD) {
        if (!ossl_quic_stream_map_reset_stream_send_part(&f->map, s, 7)) return 0;
        return state == QUIC_SSTREAM_STATE_RESET_SENT || ossl_quic_stream_map_notify_reset_stream_acked(&f->map, s);
    }
    ossl_quic_sstream_fin(s->sstream);
    if (state == QUIC_SSTREAM_STATE_READY) return 1;
    if (!ossl_quic_stream_map_ensure_send_part_id(&f->map, s)) return 0;
    if (state == QUIC_SSTREAM_STATE_SEND) return 1;
    if (!ossl_quic_sstream_mark_transmitted_fin(s->sstream, 0)
        || !ossl_quic_stream_map_notify_all_data_sent(&f->map, s)) return 0;
    return state == QUIC_SSTREAM_STATE_DATA_SENT || ossl_quic_stream_map_notify_totally_acked(&f->map, s);
}
static int receive_state(struct map_fixture *f, QUIC_STREAM *s, unsigned state, uint64_t size, uint64_t read)
{
    if (state == QUIC_RSTREAM_STATE_NONE) return s->recv_state == state;
    if (state == QUIC_RSTREAM_STATE_RECV) return 1;
    if (!ossl_quic_rxfc_on_rx_stream_frame(&s->rxfc, size, 1)) return 0;
    if (read && !ossl_quic_rxfc_on_retire(&s->rxfc, read, ossl_ms2time(10))) return 0;
    if (state == QUIC_RSTREAM_STATE_RESET_RECVD || state == QUIC_RSTREAM_STATE_RESET_READ) {
        if (!ossl_quic_stream_map_notify_reset_recv_part(&f->map, s, 9, size)) return 0;
        return state == QUIC_RSTREAM_STATE_RESET_RECVD || ossl_quic_stream_map_notify_app_read_reset_recv_part(&f->map, s);
    }
    if (!ossl_quic_stream_map_notify_size_known_recv_part(&f->map, s, size)) return 0;
    if (state == QUIC_RSTREAM_STATE_SIZE_KNOWN) return 1;
    if (!ossl_quic_stream_map_notify_totally_received(&f->map, s)) return 0;
    return state == QUIC_RSTREAM_STATE_DATA_RECVD || ossl_quic_stream_map_notify_totally_read(&f->map, s);
}

static int state_matrix(void)
{
    /* Explicit cases, with real transition functions and actual free evidence.
     * Fields: send, recv, owner-gone, STOP ACK, expected collection. */
    static const unsigned cases[][5] = {
        {4,4,1,0,1},{4,3,1,0,1},{4,5,1,0,1},{4,6,1,0,1},
        {6,4,1,0,1},{0,4,1,0,1},{4,0,1,0,1},{6,0,1,0,1},
        {4,2,1,1,1},{4,2,1,0,0},{4,1,1,1,0},{4,1,1,0,0},
        {1,4,1,0,0},{2,4,1,0,0},{3,4,1,0,0},{5,4,1,0,0},
        {4,4,0,0,0},{6,5,0,1,0},{0,3,0,0,0},{4,0,0,0,0}
    };
    size_t i;
    int ok = 1;
    for (i = 0; i < sizeof(cases)/sizeof(*cases); ++i) {
        struct map_fixture f;
        const unsigned *c = cases[i];
        uint64_t id = c[0] == 0 ? 3 : c[1] == 0 ? 2 : 0;
        QUIC_STREAM *s;
        size_t before = released;
        CHECK(map_init(&f));
        s = stream_new(&f, id, (int)(id & 3));
        if (!s || !send_state(&f,s,c[0]) || !receive_state(&f,s,c[1],0,0)) {
            map_cleanup(&f); CHECK(0);
        }
        s->deleted = c[2]; s->acked_stop_sending = c[3];
        ossl_quic_stream_map_update_state(&f.map, s);
        if (!collect(&f.map) || (ossl_quic_stream_map_get_by_id(&f.map,id)==NULL) != (int)c[4]
            || released-before != c[4]) {
            fprintf(stderr,"matrix case %zu send=%u receive=%u\n",i,c[0],c[1]);
            map_cleanup(&f); CHECK(0);
        }
        map_cleanup(&f);
    }
cleanup:
    return ok;
}

static int credit_retirement(void)
{
    struct map_fixture f;
    QUIC_STREAM *s;
    int ok = 1;
    CHECK(map_init(&f));
    s=stream_new(&f,0,0);CHECK(s);
    CHECK(send_state(&f,s,4));
    /* Known final-size with an unread gap is already GC-eligible in pristine
     * 3.5.9. This distinguishes byte-credit repair from admission repair. */
    CHECK(receive_state(&f,s,2,12,3));
    s->deleted=1;s->acked_stop_sending=1;
    ossl_quic_stream_map_update_state(&f.map,s);
    CHECK(collect(&f.map));
    CHECK(ossl_quic_stream_map_get_by_id(&f.map,0)==NULL);
    CHECK(ossl_quic_rxfc_get_swm(&f.connection)==12);
    CHECK(ossl_quic_rxfc_get_rwm(&f.connection)==12);
    CHECK(ossl_quic_rxfc_get_rwm(&f.max_bidi)==0);
    CHECK(collect(&f.map));
    CHECK(ossl_quic_rxfc_get_rwm(&f.connection)==12);
cleanup:
    map_cleanup(&f);return ok;
}

static int multiple_gc(void)
{
    struct map_fixture f;
    QUIC_STREAM *s;
    size_t before = released;
    int ok=1;unsigned i;
    CHECK(map_init(&f));
    for(i=0;i<8;++i) {
        s=stream_new(&f,4*i,0);CHECK(s);
        CHECK(send_state(&f,s,4));CHECK(receive_state(&f,s,4,0,0));
        s->deleted=i!=3;ossl_quic_stream_map_update_state(&f.map,s);
    }
    CHECK(collect(&f.map));CHECK(released-before==7);
    CHECK(ossl_quic_stream_map_get_by_id(&f.map,12)!=NULL);
    CHECK(f.map.ready_for_gc_list.next==&f.map.ready_for_gc_list);
    CHECK(collect(&f.map));CHECK(released-before==7);
    {
        QUIC_STREAM_ITER iterator;QUIC_STREAM *retiring,*neighbor;
        size_t frees=released;
        retiring=stream_new(&f,32,0);CHECK(retiring);CHECK(send_state(&f,retiring,2));
        CHECK(receive_state(&f,retiring,4,0,0));
        ossl_quic_stream_map_update_state(&f.map,retiring);
        neighbor=stream_new(&f,36,0);CHECK(neighbor);CHECK(send_state(&f,neighbor,2));
        ossl_quic_stream_map_update_state(&f.map,neighbor);
        ossl_quic_stream_iter_init(&iterator,&f.map,0);CHECK(iterator.stream==retiring);
        CHECK(ossl_quic_sstream_mark_transmitted_fin(retiring->sstream,0));
        CHECK(ossl_quic_stream_map_notify_all_data_sent(&f.map,retiring));
        CHECK(ossl_quic_stream_map_notify_totally_acked(&f.map,retiring));
        retiring->deleted=1;ossl_quic_stream_map_update_state(&f.map,retiring);
        CHECK(collect(&f.map));CHECK(released==frees+1);
        // Start a fresh TX iteration after the GC boundary; old temporaries
        // must not survive it. The active RR cursor belongs to the live peer.
        ossl_quic_stream_iter_init(&iterator,&f.map,1);CHECK(iterator.stream==neighbor);
        ossl_quic_stream_iter_next(&iterator);CHECK(iterator.stream==NULL);
    }
    /* An accept-queue owner is also retained, independently of an XSO. */
    s=stream_new(&f,3,3);CHECK(s);CHECK(receive_state(&f,s,4,0,0));
    ossl_quic_stream_map_push_accept_queue(&f.map,s);
    ossl_quic_stream_map_update_state(&f.map,s);CHECK(collect(&f.map));
    CHECK(ossl_quic_stream_map_get_accept_queue_len(&f.map,1)==1);
    CHECK(ossl_quic_stream_map_get_by_id(&f.map,3)==s);
cleanup:
    map_cleanup(&f);return ok;
}

static int retirement_error(void)
{
    struct map_fixture f;
    QUIC_STREAM *s;int ok=1;
    CHECK(map_init(&f));s=stream_new(&f,0,0);CHECK(s);
    CHECK(send_state(&f,s,4));CHECK(receive_state(&f,s,2,8,0));
    s->deleted=1;s->acked_stop_sending=1;
    ossl_quic_stream_map_update_state(&f.map,s);
    /* Deliberately corrupt internal state: must not free and report success. */
    s->rxfc.rwm=9;
    CHECK(!collect(&f.map));CHECK(ossl_quic_stream_map_get_by_id(&f.map,0)==s);
cleanup:
    map_cleanup(&f);return ok;
}

struct receive_fixture {
    SSL_CTX *ctx;SSL *ssl;QUIC_CHANNEL *channel;QUIC_STREAM *stream;
    RXE *packets[4];QUIC_PKT_HDR headers[4];unsigned char wire[4][32];unsigned used;
};
static int receive_init(struct receive_fixture *f) {
    QUIC_STREAM *s;
    memset(f,0,sizeof(*f));
    if(!(f->ctx=SSL_CTX_new(OSSL_QUIC_client_method()))||!(f->ssl=SSL_new(f->ctx))
        ||!SSL_set_default_stream_mode(f->ssl,SSL_DEFAULT_STREAM_MODE_NONE)
        ||!(f->channel=ossl_quic_conn_get_channel(f->ssl)))return 0;
    s=f->stream=ossl_quic_stream_map_alloc(&f->channel->qsm,0,0);if(!s)return 0;watch(s);
    s->sstream=ossl_quic_sstream_new(256);if(!s->sstream)return 0;
    if(!ossl_quic_txfc_init(&s->txfc,&f->channel->conn_txfc)
        ||!ossl_quic_rxfc_init(&s->rxfc,&f->channel->conn_rxfc,16,16,now_cb,NULL))return 0;
    /* Match channel allocation: the API layer retires bytes after each read. */
    s->rstream=ossl_quic_rstream_new(NULL,NULL,f->channel->rsqp);if(!s->rstream)return 0;
    if(!ossl_quic_stream_map_reset_stream_send_part(&f->channel->qsm,s,0))return 0;
    s->want_reset_stream=0; /* sent RESET */
    return ossl_quic_stream_map_notify_reset_stream_acked(&f->channel->qsm,s);
}
static int inject_frame(struct receive_fixture *f,const unsigned char *wire,size_t length) {
    unsigned i=f->used;RXE *packet;QUIC_PKT_HDR *header;
    if(i>=4||length>sizeof(f->wire[0]))return 0;
    packet=f->packets[i]=OPENSSL_zalloc(sizeof(*packet));if(!packet)return 0;
    ++f->used;header=&f->headers[i];memcpy(f->wire[i],wire,length);
    header->type=QUIC_PKT_TYPE_1RTT;header->data=f->wire[i];header->len=length;
    packet->refcount=1;packet->datagram_len=length;packet->pkt.datagram_len=length;
    packet->pkt.hdr=header;packet->pkt.time=ossl_time_now();packet->pkt.pn=i;
    return ossl_quic_handle_frames(f->channel,&packet->pkt);
}
static int receive_cleanup(struct receive_fixture *f) {
    unsigned i;int ok=1;
    SSL_free(f->ssl);SSL_CTX_free(f->ctx);
    for(i=0;i<f->used;++i) {
        if(f->packets[i]->refcount!=1){fprintf(stderr,"RXE buffer reference retained\n");ok=0;}
        OPENSSL_free(f->packets[i]);
    }
    return ok;
}
static int receive_guards(void) {
    unsigned kind;int ok=1;
    for(kind=0;kind<2;++kind) {
        struct receive_fixture f;
        const unsigned char fin[]={0x0f,0,8,0},bad_reset[]={4,0,0,7},over_credit[]={0x0e,0,17,0};
        if(!receive_init(&f)){receive_cleanup(&f);CHECK(0);}
        // Discard buffers but still enforce peer final size and stream credit.
        f.stream->stop_sending=1;
        if(kind==0 && !inject_frame(&f,fin,sizeof(fin))){receive_cleanup(&f);CHECK(0);}
        int accepted=inject_frame(&f,kind==0?bad_reset:over_credit,4);
        const QUIC_TERMINATE_CAUSE *cause=ossl_quic_channel_get_terminate_cause(f.channel);
        int guarded=!accepted&&cause&&cause->error_code==(kind==0?OSSL_QUIC_ERR_FINAL_SIZE_ERROR:OSSL_QUIC_ERR_FLOW_CONTROL_ERROR);
        int clean=receive_cleanup(&f);
        if(!guarded||!clean)CHECK(0);
    }
cleanup:return ok;
}
static int receive_progress(int stopped)
{
    struct receive_fixture f;int ok=1;
    const unsigned char fin_empty[]={0x0b,0,0},fin_gap[]={0x0f,0,8,0};
    CHECK(receive_init(&f));
    if(stopped) {
        CHECK(ossl_quic_stream_map_stop_sending_recv_part(&f.channel->qsm,f.stream,0));
        f.stream->acked_stop_sending=1;f.stream->want_stop_sending=0;
    }
    f.stream->deleted=1;
    // Real STREAM decoding must enqueue GC without another API read/global scan.
    CHECK(inject_frame(&f,stopped?fin_gap:fin_empty,stopped?sizeof(fin_gap):sizeof(fin_empty)));
    CHECK(f.stream->ready_for_gc);
    CHECK(ossl_quic_rxfc_get_swm(&f.channel->conn_rxfc)==(stopped?8U:0U));
    CHECK(collect(&f.channel->qsm));CHECK(ossl_quic_stream_map_get_by_id(&f.channel->qsm,0)==NULL);
    CHECK(ossl_quic_rxfc_get_rwm(&f.channel->conn_rxfc)==(stopped?8U:0U));
cleanup:
    return receive_cleanup(&f)&&ok;
}
static int fin_after_stop(void){return receive_guards()&&receive_progress(1);}
static int receive_gap_completion(void)
{
    struct receive_fixture f;int ok=1;size_t frees=released;
    const unsigned char fin[]={0x0f,0,8,0};
    const unsigned char data[]={0x0a,0,8,'a','b','c','d','e','f','g','h'};
    CHECK(receive_init(&f));
    CHECK(inject_frame(&f,fin,sizeof(fin)));
    f.stream->deleted=1;ossl_quic_stream_map_update_state(&f.channel->qsm,f.stream);
    CHECK(!f.stream->ready_for_gc);CHECK(collect(&f.channel->qsm));
    CHECK(ossl_quic_stream_map_get_by_id(&f.channel->qsm,0)==f.stream);
    CHECK(inject_frame(&f,data,sizeof(data)));
    CHECK(f.stream->recv_state==QUIC_RSTREAM_STATE_DATA_RECVD&&f.stream->ready_for_gc);
    CHECK(f.packets[1]->refcount==2);
    CHECK(ossl_quic_rxfc_get_swm(&f.channel->conn_rxfc)==8);
    CHECK(ossl_quic_rxfc_get_rwm(&f.channel->conn_rxfc)==0);
    CHECK(collect(&f.channel->qsm));CHECK(released==frees+1);
    CHECK(f.packets[1]->refcount==1);
    CHECK(ossl_quic_rxfc_get_rwm(&f.channel->conn_rxfc)==8);
    CHECK(collect(&f.channel->qsm));CHECK(released==frees+1);
    CHECK(ossl_quic_rxfc_get_rwm(&f.channel->conn_rxfc)==8);
cleanup:return receive_cleanup(&f)&&ok;
}
static int receive_partial_reset(void)
{
    struct receive_fixture f;int ok=1,is_fin=0;size_t count=0,frees=released;
    unsigned char read[3];
    const unsigned char data[]={0x0a,0,8,'a','b','c','d','e','f','g','h'};
    const unsigned char reset[]={4,0,9,12};
    CHECK(receive_init(&f));CHECK(inject_frame(&f,data,sizeof(data)));
    CHECK(f.packets[0]->refcount==2);
    CHECK(ossl_quic_rxfc_get_rwm(&f.channel->conn_rxfc)==0);
    CHECK(ossl_quic_rstream_read(f.stream->rstream,read,sizeof(read),&count,&is_fin));
    CHECK(count==3&&!is_fin&&!memcmp(read,"abc",3));
    CHECK(ossl_quic_rxfc_get_rwm(&f.channel->conn_rxfc)==0);
    /* Use the same retirement operation as the public SDK read path. */
    CHECK(ossl_quic_rxfc_on_retire(&f.stream->rxfc,count,ossl_ms2time(1)));
    CHECK(ossl_quic_rxfc_get_rwm(&f.channel->conn_rxfc)==3);
    CHECK(ossl_quic_stream_map_stop_sending_recv_part(&f.channel->qsm,f.stream,0));
    f.stream->deleted=1;ossl_quic_stream_map_update_state(&f.channel->qsm,f.stream);
    CHECK(!f.stream->ready_for_gc);
    CHECK(inject_frame(&f,reset,sizeof(reset)));
    CHECK(f.stream->recv_state==QUIC_RSTREAM_STATE_RESET_RECVD&&f.stream->ready_for_gc);
    CHECK(ossl_quic_rxfc_get_swm(&f.channel->conn_rxfc)==12);
    CHECK(ossl_quic_rxfc_get_rwm(&f.channel->conn_rxfc)==3);
    CHECK(collect(&f.channel->qsm));CHECK(released==frees+1);
    CHECK(f.packets[0]->refcount==1);
    CHECK(ossl_quic_stream_map_get_by_id(&f.channel->qsm,0)==NULL);
    CHECK(ossl_quic_rxfc_get_rwm(&f.channel->conn_rxfc)==12);
    CHECK(collect(&f.channel->qsm));CHECK(released==frees+1);
    CHECK(ossl_quic_rxfc_get_rwm(&f.channel->conn_rxfc)==12);
cleanup:return receive_cleanup(&f)&&ok;
}
static int zero_fin_received(void){return receive_guards()&&receive_progress(0)&&receive_gap_completion();}

/* Capture callbacks provided by the real TX packetiser, rather than replacing
 * regeneration with a test implementation of want-bit state transitions. */
static QUIC_FIFD *captured;
int __real_ossl_quic_fifd_init(QUIC_FIFD *,QUIC_CFQ *,OSSL_ACKM *,QUIC_TXPIM *,
    QUIC_SSTREAM *(*)(uint64_t,uint32_t,void *),void *,
    void (*)(uint64_t,uint64_t,QUIC_TXPIM_PKT *,void *),void *,
    void (*)(uint64_t,uint64_t,QUIC_TXPIM_PKT *,void *),void *,
    void (*)(uint64_t,void *),void *,QLOG *(*)(void *),void *);
int __wrap_ossl_quic_fifd_init(QUIC_FIFD *f,QUIC_CFQ *c,OSSL_ACKM *a,QUIC_TXPIM *p,
    QUIC_SSTREAM *(*get)(uint64_t,uint32_t,void *),void *ga,
    void (*regen)(uint64_t,uint64_t,QUIC_TXPIM_PKT *,void *),void *ra,
    void (*confirm)(uint64_t,uint64_t,QUIC_TXPIM_PKT *,void *),void *ca,
    void (*updated)(uint64_t,void *),void *ua,QLOG *(*qlog)(void *),void *qa)
{
    int result=__real_ossl_quic_fifd_init(f,c,a,p,get,ga,regen,ra,confirm,ca,updated,ua,qlog,qa);
    if(result)captured=f;return result;
}
struct flight_fixture {
    struct map_fixture streams;
    OSSL_STATM statm;
    OSSL_CC_DATA *cc;
    OSSL_ACKM *ackm;
    QUIC_TXPIM *pim;
    QUIC_CFQ *cfq;
    OSSL_QTX *qtx;
    OSSL_QRX *qrx;
    QUIC_DEMUX *demux;
    BIO *sender,*receiver;
    OSSL_QUIC_TX_PACKETISER *txp;
    QUIC_SSTREAM *crypto[QUIC_PN_SPACE_NUM];
    int have_statm;
};
static void receive_datagram(QUIC_URXE *packet,void *arg,const QUIC_CONN_ID *id)
{
    struct flight_fixture *f=arg;(void)id;
    ossl_qrx_inject_urxe(f->qrx,packet);
}
static int flight_init(struct flight_fixture *f)
{
    OSSL_QTX_ARGS qargs={0};OSSL_QUIC_TX_PACKETISER_ARGS args={0};
    OSSL_QRX_ARGS rxargs={0};static const unsigned char secret[32]={1};
    memset(f,0,sizeof(*f));
    if(!map_init(&f->streams)||!ossl_statm_init(&f->statm))return 0;
    f->have_statm=1;
    f->cc=ossl_cc_newreno_method.new(now_cb,NULL);
    f->ackm=ossl_ackm_new(now_cb,NULL,&f->statm,&ossl_cc_newreno_method,f->cc,0);
    f->pim=ossl_quic_txpim_new();f->cfq=ossl_quic_cfq_new();
    if(!BIO_new_bio_dgram_pair(&f->sender,0,&f->receiver,0))return 0;
    qargs.mdpl=1200;qargs.bio=f->sender;f->qtx=ossl_qtx_new(&qargs);
    if(!f->cc||!f->ackm||!f->pim||!f->cfq||!f->qtx)return 0;
    if(!ossl_ackm_on_handshake_confirmed(f->ackm))return 0;
    ossl_statm_update_rtt(&f->statm,ossl_time_zero(),ossl_ms2time(1));
    args.qtx=f->qtx;args.txpim=f->pim;args.cfq=f->cfq;args.ackm=f->ackm;
    args.qsm=&f->streams.map;args.conn_txfc=&f->streams.tx_connection;
    args.conn_rxfc=&f->streams.connection;args.max_streams_bidi_rxfc=&f->streams.max_bidi;
    args.max_streams_uni_rxfc=&f->streams.max_uni;
    args.cc_method=&ossl_cc_newreno_method;args.cc_data=f->cc;args.now=now_cb;
    args.protocol_version=QUIC_VERSION_1;
    args.cur_scid.id_len=1;args.cur_scid.id[0]=0x5f;
    args.cur_dcid.id_len=8;memset(args.cur_dcid.id,0xa1,8);
    for(unsigned i=0;i<QUIC_PN_SPACE_NUM;++i) {
        f->crypto[i]=ossl_quic_sstream_new(256);if(!f->crypto[i])return 0;
        args.crypto[i]=f->crypto[i];
    }
    captured=NULL;f->txp=ossl_quic_tx_packetiser_new(&args);
    if(f->txp==NULL||captured==NULL)return 0;
    ossl_quic_tx_packetiser_set_validated(f->txp);
    ossl_quic_tx_packetiser_notify_handshake_complete(f->txp);
    f->demux=ossl_quic_demux_new(f->receiver,8,now_cb,NULL);
    if(!f->demux)return 0;
    ossl_quic_demux_set_default_handler(f->demux,receive_datagram,f);
    rxargs.demux=f->demux;rxargs.short_conn_id_len=8;rxargs.max_deferred=32;
    f->qrx=ossl_qrx_new(&rxargs);if(!f->qrx)return 0;
    ossl_qrx_allow_1rtt_processing(f->qrx);
    return ossl_qtx_provide_secret(f->qtx,QUIC_ENC_LEVEL_1RTT,QRL_SUITE_AES128GCM,NULL,secret,sizeof(secret))
        &&ossl_qrx_provide_secret(f->qrx,QUIC_ENC_LEVEL_1RTT,QRL_SUITE_AES128GCM,NULL,secret,sizeof(secret));
}
static void flight_cleanup(struct flight_fixture *f)
{
    unsigned i;
    if(f->ackm)for(i=0;i<QUIC_PN_SPACE_NUM;++i)ossl_ackm_on_pkt_space_discarded(f->ackm,i);
    ossl_quic_tx_packetiser_free(f->txp);
    for(i=0;i<QUIC_PN_SPACE_NUM;++i)ossl_quic_sstream_free(f->crypto[i]);
    ossl_qtx_free(f->qtx);
    ossl_quic_txpim_free(f->pim);ossl_quic_cfq_free(f->cfq);ossl_ackm_free(f->ackm);
    ossl_qrx_free(f->qrx);ossl_quic_demux_free(f->demux);
    BIO_free(f->sender);BIO_free(f->receiver);
    if(f->cc)ossl_cc_newreno_method.free(f->cc);
    if(f->have_statm)ossl_statm_destroy(&f->statm);
    map_cleanup(&f->streams);captured=NULL;
}
static int commit_packet(struct flight_fixture *f,uint64_t number,uint64_t stream,int reset,int stop)
{
    QUIC_TXPIM_PKT *p=ossl_quic_txpim_pkt_alloc(f->pim);
    QUIC_TXPIM_CHUNK chunk={0};
    if(!p)return 0;
    if(stream!=UINT64_MAX) {
        chunk.stream_id=stream;chunk.start=1;chunk.end=0;
        chunk.has_reset_stream=reset;chunk.has_stop_sending=stop;
        if(!ossl_quic_txpim_pkt_append_chunk(p,&chunk)){ossl_quic_txpim_pkt_release(f->pim,p);return 0;}
    }
    p->ackm_pkt.pkt_num=number;p->ackm_pkt.pkt_space=QUIC_PN_SPACE_APP;
    p->ackm_pkt.largest_acked=QUIC_PN_INVALID;p->ackm_pkt.num_bytes=50;
    p->ackm_pkt.time=now_value;p->ackm_pkt.is_inflight=1;p->ackm_pkt.is_ack_eliciting=1;
    return ossl_quic_fifd_pkt_commit(captured,p);
}
static int ack_packet(struct flight_fixture *f,uint64_t number)
{
    OSSL_QUIC_ACK_RANGE range={0};OSSL_QUIC_FRAME_ACK ack={0};
    range.start=range.end=number;ack.ack_ranges=&range;ack.num_ack_ranges=1;
    return ossl_ackm_on_rx_ack_frame(f->ackm,&ack,QUIC_PN_SPACE_APP,now_value);
}
static OSSL_QRX_PKT *generate_packet(struct flight_fixture *f)
{
    QUIC_TXP_STATUS status={0};OSSL_QRX_PKT *packet=NULL;
    if(!ossl_quic_tx_packetiser_generate(f->txp,&status)||status.sent_pkt!=1)return NULL;
    ossl_qtx_finish_dgram(f->qtx);
    if(!ossl_qtx_flush_net(f->qtx)||ossl_quic_demux_pump(f->demux)!=QUIC_DEMUX_PUMP_RES_OK
        ||!ossl_qrx_read_pkt(f->qrx,&packet))return NULL;
    return packet;
}
static int credit_frame(OSSL_QRX_PKT *packet,uint64_t wanted_id,uint64_t *limit)
{
    PACKET data;uint64_t type,id,value;OSSL_QUIC_FRAME_RESET_STREAM reset;
    OSSL_QUIC_FRAME_STOP_SENDING stop;int found=0;
    if(!PACKET_buf_init(&data,packet->hdr->data,packet->hdr->len))return 0;
    while(PACKET_remaining(&data)) {
        if(!ossl_quic_wire_peek_frame_header(&data,&type,NULL))return 0;
        switch(type) {
        case OSSL_QUIC_FRAME_TYPE_PADDING:
            if(!ossl_quic_wire_decode_padding(&data))return 0;break;
        case OSSL_QUIC_FRAME_TYPE_PING:
            if(!ossl_quic_wire_decode_frame_ping(&data))return 0;break;
        case OSSL_QUIC_FRAME_TYPE_MAX_DATA:
            if(!ossl_quic_wire_decode_frame_max_data(&data,&value))return 0;break;
        case OSSL_QUIC_FRAME_TYPE_RESET_STREAM:
            if(!ossl_quic_wire_decode_frame_reset_stream(&data,&reset)||reset.app_error_code!=7||reset.final_size!=0)return 0;break;
        case OSSL_QUIC_FRAME_TYPE_STOP_SENDING:
            if(!ossl_quic_wire_decode_frame_stop_sending(&data,&stop)||stop.app_error_code!=8)return 0;break;
        case OSSL_QUIC_FRAME_TYPE_MAX_STREAM_DATA:
            if(!ossl_quic_wire_decode_frame_max_stream_data(&data,&id,&value))return 0;
            if(id==wanted_id){*limit=value;found=1;}break;
        default:return 0;
        }
    }
    return found;
}
static int lost_controls(void)
{
    struct flight_fixture f;QUIC_STREAM *reset,*stop,*credit;int ok=1;
    OSSL_QRX_PKT *packet=NULL;QUIC_TXFC peer_connection,peer_stream;
    uint64_t maximum=0;unsigned i;
    CHECK(flight_init(&f));
    reset=stream_new(&f.streams,0,0);stop=stream_new(&f.streams,3,3);credit=stream_new(&f.streams,7,3);
    CHECK(reset&&stop&&credit);CHECK(send_state(&f.streams,reset,5));
    CHECK(ossl_quic_stream_map_stop_sending_recv_part(&f.streams.map,stop,8));
    CHECK(ossl_quic_rxfc_on_rx_stream_frame(&credit->rxfc,16,0));
    CHECK(ossl_quic_rxfc_on_retire(&credit->rxfc,16,ossl_ms2time(1)));
    ossl_quic_stream_map_update_state(&f.streams.map,credit);
    CHECK(ossl_quic_txfc_init(&peer_connection,NULL));CHECK(ossl_quic_txfc_bump_cwm(&peer_connection,64));
    CHECK(ossl_quic_txfc_init(&peer_stream,&peer_connection));CHECK(ossl_quic_txfc_bump_cwm(&peer_stream,16));
    CHECK(ossl_quic_txfc_consume_credit(&peer_stream,16));CHECK(ossl_quic_txfc_get_credit(&peer_stream,0)==0);
    packet=generate_packet(&f);CHECK(packet);CHECK(packet->pn==0);
    CHECK(credit_frame(packet,7,&maximum));CHECK(maximum==32);
    /* Drop this packet from the peer's control accounting. The encoder itself
     * clears wants/cwm-changed, so no hand-written flag reset hides a defect. */
    ossl_qrx_pkt_release(packet);packet=NULL;
    CHECK(!reset->want_reset_stream&&!stop->want_stop_sending&&!credit->want_max_stream_data);
    for(i=1;i<=3;++i) {
        ossl_quic_tx_packetiser_schedule_ack_eliciting(f.txp,QUIC_PN_SPACE_APP);
        packet=generate_packet(&f);CHECK(packet);CHECK(packet->pn==i);
        ossl_qrx_pkt_release(packet);packet=NULL;
    }
    now_value=ossl_time_add(now_value,ossl_ms2time(100));
    CHECK(ack_packet(&f,3));
    fprintf(stderr,"loss flags reset=%u stop=%u credit=%u\n",(unsigned)reset->want_reset_stream,
        (unsigned)stop->want_stop_sending,(unsigned)credit->want_max_stream_data);
    CHECK(reset->want_reset_stream&&stop->want_stop_sending&&credit->want_max_stream_data);
    /* No new application read follows the lost credit update. Actual
     * retransmitted wire credit must unblock the peer's real stream TXFC. */
    packet=generate_packet(&f);CHECK(packet);CHECK(packet->pn==4);
    CHECK(credit_frame(packet,7,&maximum));CHECK(maximum==32);
    CHECK(ossl_quic_txfc_bump_cwm(&peer_stream,maximum));
    CHECK(ossl_quic_txfc_get_credit(&peer_stream,0)==16);
    CHECK(ossl_quic_txfc_consume_credit(&peer_stream,1));
    CHECK(ossl_quic_txfc_get_swm(&peer_stream)==17);
cleanup:
    ossl_qrx_pkt_release(packet);
    flight_cleanup(&f);return ok;
}
static int reset_late_loss(void)
{
    struct flight_fixture f;QUIC_STREAM *s;QUIC_TXPIM_PKT event={0};int ok=1;
    CHECK(flight_init(&f));s=stream_new(&f.streams,0,0);CHECK(s);CHECK(send_state(&f.streams,s,5));
    s->want_reset_stream=0;
    CHECK(commit_packet(&f,0,0,1,0));CHECK(ack_packet(&f,0));
    CHECK(s->send_state==QUIC_SSTREAM_STATE_RESET_RECVD);
    captured->regen_frame(OSSL_QUIC_FRAME_TYPE_RESET_STREAM,0,&event,captured->regen_frame_arg);
    CHECK(!s->want_reset_stream);
cleanup:
    flight_cleanup(&f);return ok;
}
static int reset_pending_ack(void)
{
    struct flight_fixture f;QUIC_STREAM *s;QUIC_TXPIM_PKT event={0};int ok=1;
    CHECK(flight_init(&f));s=stream_new(&f.streams,0,0);CHECK(s);CHECK(send_state(&f.streams,s,5));
    s->want_reset_stream=0;CHECK(commit_packet(&f,0,0,1,0));
    captured->regen_frame(OSSL_QUIC_FRAME_TYPE_RESET_STREAM,0,&event,captured->regen_frame_arg);
    CHECK(s->want_reset_stream);CHECK(ack_packet(&f,0));
    CHECK(s->send_state==QUIC_SSTREAM_STATE_RESET_RECVD);CHECK(!s->want_reset_stream);
cleanup:
    flight_cleanup(&f);return ok;
}

static int final_reset_credit(void)
{
    struct map_fixture f;QUIC_STREAM *s;int ok=1;
    CHECK(map_init(&f));s=stream_new(&f,0,0);CHECK(s);CHECK(send_state(&f,s,4));
    CHECK(ossl_quic_rxfc_on_rx_stream_frame(&s->rxfc,3,0));
    CHECK(ossl_quic_rxfc_on_retire(&s->rxfc,3,ossl_ms2time(1)));
    CHECK(ossl_quic_stream_map_stop_sending_recv_part(&f.map,s,0));
    s->deleted=1;s->acked_stop_sending=1;s->want_stop_sending=0;
    ossl_quic_stream_map_update_state(&f.map,s);CHECK(collect(&f.map));
    CHECK(ossl_quic_stream_map_get_by_id(&f.map,0)==s);
    CHECK(ossl_quic_rxfc_on_rx_stream_frame(&s->rxfc,12,1));
    CHECK(ossl_quic_stream_map_notify_reset_recv_part(&f.map,s,9,12));
    CHECK(ossl_quic_rxfc_get_swm(&f.connection)==12&&ossl_quic_rxfc_get_rwm(&f.connection)==3);
    CHECK(collect(&f.map));CHECK(ossl_quic_stream_map_get_by_id(&f.map,0)==NULL);
    CHECK(ossl_quic_rxfc_get_rwm(&f.connection)==12);CHECK(collect(&f.map));
    CHECK(ossl_quic_rxfc_get_rwm(&f.connection)==12);
cleanup:map_cleanup(&f);return ok&&receive_partial_reset();
}
static int late_events_after_gc(void)
{
    struct flight_fixture f;QUIC_STREAM *s;int ok=1;size_t before;
    CHECK(flight_init(&f));s=stream_new(&f.streams,0,0);CHECK(s);CHECK(send_state(&f.streams,s,5));
    CHECK(receive_state(&f.streams,s,5,0,0));
    s->want_reset_stream=0;s->deleted=1;
    CHECK(commit_packet(&f,0,0,1,0));CHECK(commit_packet(&f,1,0,1,0));CHECK(commit_packet(&f,2,0,1,0));
    CHECK(ack_packet(&f,1));before=released;
    CHECK(collect(&f.streams.map));CHECK(released==before+1);
    CHECK(ossl_quic_stream_map_get_by_id(&f.streams.map,0)==NULL);
    CHECK(ack_packet(&f,0));
    now_value=ossl_time_add(now_value,ossl_ms2time(100));
    CHECK(commit_packet(&f,50,UINT64_MAX,0,0));CHECK(ack_packet(&f,50));
    CHECK(ossl_quic_stream_map_get_by_id(&f.streams.map,0)==NULL);
    CHECK(released==before+1);CHECK(ossl_quic_txpim_get_in_use(f.pim)==0);
cleanup:flight_cleanup(&f);return ok;
}

struct named_case {const char *name;int (*run)(void);};
static const struct named_case cases[]={
    {"StateMatrix",state_matrix},{"ByteCreditOnce",credit_retirement},{"MultipleGcAndOwners",multiple_gc},
    {"RetirementFailureRetainsStream",retirement_error},{"NullSendBufferControlLoss",lost_controls},
    {"ResetAckThenLateLoss",reset_late_loss},{"ResetQueuedLossThenAck",reset_pending_ack},
    {"ReceiveFinAfterStop",fin_after_stop},{"ReceiveZeroFinCompletes",zero_fin_received},
    {"ResetFinalSizeRetiresUnreadGap",final_reset_credit},{"LateAckLossAfterGc",late_events_after_gc}
};
int main(int argc,char **argv)
{
    size_t i;int result;
    if(argc!=2)return 2;
    now_value=ossl_seconds2time(1000);
    for(i=0;i<sizeof(cases)/sizeof(*cases);++i)
        if(strcmp(argv[1],cases[i].name)==0) {
            result=cases[i].run();OPENSSL_cleanup();
            printf("%s: %s (watched real stream frees=%zu)\n",cases[i].name,result?"PASS":"FAIL",released);
            return result?0:1;
        }
    return 2;
}
