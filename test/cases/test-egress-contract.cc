#include "gtest/gtest.h"
#include <fstream>
#include <cstdlib>
#include <string>
#include <memory>
#include <thread>
#include <cerrno>
#include <sys/epoll.h>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <net/if.h>
extern "C" {
#include "dns_client/dns_client.h"
#include "dns_client/egress_contract.h"
#include "dns_client/upstream_service.h"
#include "dns_client/upstream_discovery.h"
#include "dns_client/client_tls.h"
#include "dns_client/client_http3_control.h"
#include "dns_client/client_http3.h"
#include "dns_client/client_quic.h"
#include "dns_client/client_socket.h"
#include "dns_client/conn_stream.h"
#include "smartdns/dns_conf.h"
#include "smartdns/util.h"
}
namespace {
class EgressContract : public ::testing::Test {
protected:
    std::string path, saved, boot;
    dns_upstream_service service{};
    void adopt(dns_server_info &server) { service.wan_count=1;service.egress_contract=1; std::strcpy(service.wans[0].interface,"lo"); server.service=&service; server.type=DNS_SERVER_HTTPS; }
    void SetUp() override {
        ASSERT_EQ(geteuid(), 0U) << "contract fixtures require the privileged offline CI namespace";
        _dns_egress_close();
        _dns_egress_test_interface_opens = 0;
        saved = dns_conf.upstream_egress_contract;
        char name[] = "/tmp/smartdns-egress-XXXXXX"; int fd = mkstemp(name);
        ASSERT_GE(fd, 0); close(fd); path = name;
        std::ifstream input("/proc/sys/kernel/random/boot_id"); input >> boot;
        std::strcpy(dns_conf.upstream_egress_contract, path.c_str());
    }
    void TearDown() override {
        _dns_egress_before_bind=nullptr;_dns_egress_test_now=nullptr;
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
        _dns_quic_lifecycle_test_hook=nullptr;
#endif
        /* Match dns_client_exit: stop discovery/timers before draining and freeing services. */
        _dns_services_stop();_dns_services_remove_all();_dns_paths_close(); free(service.failures); free(service.event_sources);
        std::strcpy(dns_conf.upstream_egress_contract, saved.c_str()); unlink(path.c_str()); _dns_egress_invalidate();
        _dns_egress_close();
    }
    void write(const std::string &rows, long offset = 10000, const std::string &boot_override = "") {
        std::ofstream out(path); out << "smartdns-egress-v1 4000 " << (_dns_egress_now() + offset) << " " <<
            (boot_override.empty() ? boot : boot_override) << "\n" << rows; out.close(); _dns_egress_invalidate();
    }
    std::string row(char token = 'a', unsigned families = 3) {
        return "lo " + std::to_string(if_nametoindex("lo")) + " " + std::string(64, token) + " " + std::to_string(families) + "\n";
    }
    int lease(int family = AF_INET) { unsigned mark; char session[65]; return _dns_egress_lease("lo", family, -1, &mark, session); }
};
TEST_F(EgressContract, ExpiryRevocationBootPermissionAndMalformedInputFailClosed) {
    write(row()); ASSERT_EQ(lease(), 1);
    auto epoch = _dns_egress_epoch(); write(row()); EXPECT_EQ(_dns_egress_epoch(), epoch);
    write(row('b')); EXPECT_NE(_dns_egress_epoch(), epoch); ASSERT_EQ(lease(AF_INET6), 1);
    write(row(), -1); EXPECT_EQ(lease(), -1);
    write(row(), 10000, "00000000-0000-0000-0000-000000000000"); EXPECT_EQ(lease(), -1);
    write(row()); chmod(path.c_str(), 0666); _dns_egress_invalidate(); EXPECT_EQ(lease(), -1); chmod(path.c_str(), 0600);
    write(row()+row()); EXPECT_EQ(lease(), -1);
    write("lo 1 invalid 3\n"); EXPECT_EQ(lease(), -1);
    write(row('a', 4)); EXPECT_EQ(lease(), -1);
    write(""); EXPECT_EQ(lease(), -1);
    unlink(path.c_str()); _dns_egress_invalidate(); EXPECT_EQ(lease(), -1);
}
TEST_F(EgressContract, RepeatedAdmissionReusesIoctlSocketWithoutCachingInterfaceIdentity) {
    write(row());
    for (unsigned i = 0; i < 1000; i++) ASSERT_EQ(lease(i % 2 ? AF_INET : AF_INET6), 1);
    EXPECT_EQ(_dns_egress_test_interface_opens, 1U);
    write(row('b'));
    EXPECT_EQ(lease(), 1);
    EXPECT_EQ(_dns_egress_test_interface_opens, 1U);
    _dns_egress_close();
    EXPECT_EQ(lease(), 1);
    EXPECT_EQ(_dns_egress_test_interface_opens, 2U);
}
TEST_F(EgressContract, ReusedIoctlDetectsLinkRemovalAndRecreationBeforeLeaseRefresh) {
    std::string name = "ec" + std::to_string(getpid());
    ASSERT_EQ(std::system(("ip link add " + name + " type dummy").c_str()), 0);
    unsigned index = if_nametoindex(name.c_str()), mark;
    char session[65];
    write(name + " " + std::to_string(index) + " " + std::string(64, 'a') + " 3\n" + row());
    EXPECT_EQ(_dns_egress_lease(name.c_str(), AF_INET, -1, &mark, session), 1);
    ASSERT_EQ(std::system(("ip link del " + name).c_str()), 0);
    // No invalidation/lease renewal: the cached descriptor must see current links.
    EXPECT_EQ(_dns_egress_lease(name.c_str(), AF_INET, -1, &mark, session), -1);
    EXPECT_EQ(lease(), 1); // another WAN is unaffected
    ASSERT_EQ(std::system(("ip link add " + name + " type dummy").c_str()), 0);
    EXPECT_NE(if_nametoindex(name.c_str()), index);
    EXPECT_EQ(_dns_egress_lease(name.c_str(), AF_INET, -1, &mark, session), -1);
    EXPECT_EQ(_dns_egress_test_interface_opens, 1U);
    EXPECT_EQ(std::system(("ip link del " + name).c_str()), 0);
}
TEST_F(EgressContract, LeaseParsingFitsSmallStackBelowNestedDiscoveryFrames) {
    write(row());
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    ASSERT_EXIT({
        int result = -1;
        pthread_attr_t attr;
        ASSERT_EQ(pthread_attr_init(&attr), 0);
        ASSERT_EQ(pthread_attr_setstacksize(&attr, 128 * 1024), 0);
        pthread_t thread;
        int created = pthread_create(&thread, &attr, [](void *opaque) -> void * {
            // Live discovery/receive/reconcile frames consumed >100 KiB before
            // lease parsing. Reserve that budget while testing the leaf parser.
            volatile unsigned char outer_frames[96 * 1024];
            for (size_t i = 0; i < sizeof(outer_frames); i += 4096) outer_frames[i] = 0x5a;
            outer_frames[sizeof(outer_frames) - 1] = 0x5a;
            unsigned mark = 0; char session[65];
            int good = 1;
            for (unsigned i = 0; i < 8; i++) {
                _dns_egress_invalidate();
                good &= _dns_egress_lease("lo", i % 2 ? AF_INET6 : AF_INET, -1, &mark, session) == 1;
                good &= mark == DNS_EGRESS_MARK && strlen(session) == 64;
            }
            good &= outer_frames[0] == 0x5a && outer_frames[sizeof(outer_frames) - 1] == 0x5a;
            *static_cast<int *>(opaque) = good;
            return nullptr;
        }, &result);
        pthread_attr_destroy(&attr);
        ASSERT_EQ(created, 0); ASSERT_EQ(pthread_join(thread, nullptr), 0);
        EXPECT_EQ(result, 1);
        _exit(::testing::Test::HasFailure() ? 1 : 0);
    }, ::testing::ExitedWithCode(0), "");
}
uint64_t wide_now;
uint64_t wide_clock(){return wide_now;}
TEST_F(EgressContract, LeaseClockRemainsWideBeyond32BitMillisecondRollover) {
    wide_now=UINT64_C(0x100000000)+12000;_dns_egress_test_now=wide_clock;
    write(row(),10000);EXPECT_EQ(lease(),1);wide_now+=10001;EXPECT_EQ(lease(),-1);
}
TEST_F(EgressContract, BoundTcpAndUdpBothFamiliesPrepareBeforeIoAndRejectConflictingMarks) {
    write(row());
    for (int family : {AF_INET, AF_INET6}) for (int type : {SOCK_STREAM, SOCK_DGRAM}) {
        int fd = socket(family, type, 0); ASSERT_GE(fd, 0);
        dns_server_info server{}; adopt(server); server.ai_family=family; server.so_mark=-1; std::strcpy(server.flags.ifname,"lo");
        ASSERT_EQ(_dns_socket_prepare(&server,fd),0);
        unsigned mark=0; socklen_t size=sizeof(mark); ASSERT_EQ(getsockopt(fd,SOL_SOCKET,SO_MARK,&mark,&size),0);
        EXPECT_EQ(mark,DNS_EGRESS_MARK);
        char name[IFNAMSIZ]{}; size=sizeof(name); ASSERT_EQ(getsockopt(fd,SOL_SOCKET,SO_BINDTODEVICE,name,&size),0); EXPECT_STREQ(name,"lo");
        server.so_mark=0x7d4; EXPECT_EQ(_dns_socket_prepare(&server,fd),-1); close(fd);
    }
}
TEST_F(EgressContract, UnboundSocketsKeepTheirConfiguredPolicyAndFamilyAdmissionIsExplicit) {
    write(row('a',1)); EXPECT_EQ(lease(AF_INET),1); EXPECT_EQ(lease(AF_INET6),-1);
    unsigned mark; char session[65];
    EXPECT_EQ(_dns_egress_lease("",AF_INET,0x7d4,&mark,session),0); EXPECT_EQ(mark,0x7d4U);
    dns_conf.upstream_egress_contract[0]=0;
    EXPECT_EQ(_dns_egress_lease("lo",AF_INET,-1,&mark,session),0); EXPECT_EQ(mark,0U);
}
TEST_F(EgressContract, SameInterfaceSameAddressNewSessionRetiresSocketIdentity) {
    write(row()); dns_server_info server{}; adopt(server); server.ai_family=AF_INET; server.so_mark=-1;
    std::strcpy(server.flags.ifname,"lo"); pthread_mutex_init(&server.lock,nullptr);
    int fd=socket(AF_INET,SOCK_DGRAM,0); ASSERT_GE(fd,0); ASSERT_EQ(_dns_socket_prepare(&server,fd),0);
    EXPECT_TRUE(_dns_egress_socket_current(&server)); write(row('b'));
    EXPECT_FALSE(_dns_egress_socket_current(&server)); close(fd); pthread_mutex_destroy(&server.lock);
}
TEST_F(EgressContract, MaximumInventoryIsBoundedAndOneExtraRowRevokesAdmission) {
    std::string rows=row();
    for (unsigned i=2;i<=127;i++) rows += "x"+std::to_string(i)+" "+std::to_string(i)+" "+std::string(64,'a')+" 3\n";
    write(rows); EXPECT_EQ(lease(),1); write(rows+"x128 128 "+std::string(64,'a')+" 3\n"); EXPECT_EQ(lease(),-1);
}
TEST_F(EgressContract, UnchangedRenewalAndOneWanReplacementPreserveOtherWanGenerationAndSocket) {
    std::string name="ep"+std::to_string(getpid());ASSERT_EQ(std::system(("ip link add "+name+" type dummy").c_str()),0);
    service.egress_contract=1;service.wan_count=2;service.type=DNS_SERVER_HTTPS;service.port=443;service.flags.set_mark=-1;
    std::strcpy(service.wans[0].interface,"lo");std::strcpy(service.wans[1].interface,name.c_str());
    dns_discovery_snapshot desired{};desired.count=1;std::strcpy(desired.addresses[0].text,"127.0.0.2");service.desired=&desired;
    auto second=name+" "+std::to_string(if_nametoindex(name.c_str()))+" "+std::string(64,'a')+" 3\n";
    write(row()+second);service.path_refresh_due=0;_dns_paths_refresh(&service,get_tick_count());
    auto first=service.wans[0].generation,other=service.wans[1].generation;
    dns_server_info ep{};ep.service=&service;ep.type=DNS_SERVER_HTTPS;ep.ai_family=AF_INET;ep.so_mark=-1;
    std::strcpy(ep.flags.ifname,name.c_str());pthread_mutex_init(&ep.lock,nullptr);int fd=socket(AF_INET,SOCK_DGRAM,0);ASSERT_GE(fd,0);ASSERT_EQ(_dns_socket_prepare(&ep,fd),0);
    write(row()+second);service.path_refresh_due=0;_dns_paths_refresh(&service,get_tick_count());
    EXPECT_EQ(service.wans[0].generation,first);EXPECT_EQ(service.wans[1].generation,other);
    write(row('b')+second);service.path_refresh_due=0;_dns_paths_refresh(&service,get_tick_count());
    EXPECT_GT(service.wans[0].generation,first);EXPECT_EQ(service.wans[1].generation,other);EXPECT_TRUE(_dns_egress_socket_current(&ep));
    close(fd);pthread_mutex_destroy(&ep.lock);service.desired=nullptr;EXPECT_EQ(std::system(("ip link del "+name).c_str()),0);
}
TEST_F(EgressContract, RealServiceConstructionKeepsLanAndExplicitWanOffOutsideTheContract) {
    write("");
    for(bool wan:{false,true}) {
        client_dns_server_flags flags{};dns_client_flags_init(&flags);
        flags.server_flag|=SERVER_FLAG_EXCLUDE_DEFAULT;
        if(wan){flags.upstream_wan_count=1;std::strcpy(flags.upstream_wan_interfaces[0],"lo");}
        else std::strcpy(flags.ifname,"lo"); // parser's explicit multi-WAN-off result has the same zero count
        dns_upstream_pool_config config{};config.max_backends=2;
        const char *host=wan?"wan.example":"lan.example";
        ASSERT_EQ(dns_client_add_service(host,15443,DNS_SERVER_HTTPS,&flags,&config),0);
        std::unique_ptr<dns_upstream_service,decltype(&_dns_service_put)> real(
            _dns_service_find_test(host,15443,DNS_SERVER_HTTPS,&flags),&_dns_service_put);
        ASSERT_NE(real,nullptr);EXPECT_EQ(real->wan_count,1U);EXPECT_EQ(real->egress_contract,wan);
        dns_server_info server{};server.service=real.get();server.type=DNS_SERVER_HTTPS;
        server.ai_family=AF_INET;server.so_mark=-1;std::strcpy(server.flags.ifname,"lo");
        pthread_mutexattr_t attr;pthread_mutexattr_init(&attr);pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&server.lock,&attr);pthread_mutexattr_destroy(&attr);
        int fd=socket(AF_INET,SOCK_DGRAM,0);ASSERT_GE(fd,0);
        EXPECT_EQ(_dns_socket_prepare(&server,fd),wan?-1:0);
        EXPECT_EQ(_dns_egress_io_allowed(&server),!wan);
        real->desired->count=1;std::strcpy(real->desired->addresses[0].text,"127.0.0.2");real->desired->addresses[0].valid_until=ULONG_MAX;
        _dns_paths_refresh(real.get(),get_tick_count());
        EXPECT_EQ(_dns_path_allowed(real.get(),"127.0.0.2"),!wan);
        EXPECT_EQ(real->wans[0].egress_session[0],0);
        close(fd);pthread_mutex_destroy(&server.lock);
    }
}
TEST_F(EgressContract, MdnsAndLanBindingAreNotImplicitContractAdopters) {
    write("");dns_server_info server{};server.type=DNS_SERVER_MDNS;std::strcpy(server.flags.ifname,"lo");
    EXPECT_TRUE(_dns_egress_io_allowed(&server));server.type=DNS_SERVER_TLS;
    EXPECT_TRUE(_dns_egress_io_allowed(&server));server.service=&service;service.wan_count=0;
    EXPECT_TRUE(_dns_egress_io_allowed(&server));
}
TEST_F(EgressContract, RevokedQuicEventsAndTlsShutdownDoNotTouchTransportObjects) {
    write(row());dns_server_info server{};adopt(server);server.ai_family=AF_INET;server.so_mark=-1;
    std::strcpy(server.flags.ifname,"lo");pthread_mutexattr_t attr;pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_RECURSIVE);pthread_mutex_init(&server.lock,&attr);pthread_mutexattr_destroy(&attr);
    int fd=socket(AF_INET,SOCK_DGRAM,0);ASSERT_GE(fd,0);ASSERT_EQ(_dns_socket_prepare(&server,fd),0);
    write("");server.type=DNS_SERVER_HTTP3;
    // A poison transport proves these entry points gate before OpenSSL access.
    server.ssl=reinterpret_cast<SSL *>(1);
    EXPECT_EQ(_ssl_do_handevent(&server),-1);EXPECT_EQ(_ssl_shutdown(&server),-1);
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
    dns_conn_stream stream{};stream.quic_stream=reinterpret_cast<SSL *>(1);
    EXPECT_EQ(_dns_client_process_recv_http3(&server,&stream),-1);
    server.http3_control=reinterpret_cast<dns_http3_control *>(1);
    EXPECT_EQ(_dns_http3_control_poll(&server),-1);EXPECT_EQ(_dns_http3_keepalive(&server),-1);
    EXPECT_EQ(_dns_http3_control_shutdown(&server),1);server.http3_control=nullptr;
#endif
    EXPECT_EQ(server.egress_revoked,1);EXPECT_EQ(server.service_normal_close,1);
    server.ssl=nullptr;close(fd);pthread_mutex_destroy(&server.lock);
}
std::string race_name,race_old;
void replace_interface() {
    std::system(("ip link set "+race_name+" name "+race_old).c_str());
    std::system(("ip link add "+race_name+" type dummy").c_str());
}
TEST_F(EgressContract, ReplacingInterfaceNameBetweenLookupAndBindRejectsBeforeConnect) {
    race_name="eg"+std::to_string(getpid());race_old="eo"+std::to_string(getpid());
    ASSERT_EQ(std::system(("ip link add "+race_name+" type dummy").c_str()),0);
    unsigned index=if_nametoindex(race_name.c_str());
    write(race_name+" "+std::to_string(index)+" "+std::string(64,'a')+" 3\n");
    dns_server_info server{};adopt(server);server.ai_family=AF_INET;server.so_mark=-1;std::strcpy(server.flags.ifname,race_name.c_str());
    int fd=socket(AF_INET,SOCK_DGRAM,0);ASSERT_GE(fd,0);_dns_egress_before_bind=replace_interface;
    EXPECT_EQ(_dns_socket_prepare(&server,fd),-1);_dns_egress_before_bind=nullptr;close(fd);
    EXPECT_EQ(std::system(("ip link del "+race_name).c_str()),0);EXPECT_EQ(std::system(("ip link del "+race_old).c_str()),0);
}

#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
unsigned revoke_stage,flush_turns,opened_streams;
void revoke_quic_lifecycle(dns_server_info *server,unsigned stage) {
    if(stage==3)opened_streams++;
    if((revoke_stage==1&&stage==1)||(revoke_stage==2&&stage==2&&++flush_turns==2)) {
        server->egress_revoked=1;server->service_normal_close=1;
        if(stage==1)_dns_client_close_socket(server); // must defer while the poll guard owns moved nodes
    }
}
TEST_F(EgressContract, QuicPollAndEpolloutRevocationRestoreMutexGuardAndMixedStreamLifetimes) {
    for(unsigned mode:{1U,2U}) {
        write(row());dns_server_info server{};adopt(server);server.type=DNS_SERVER_QUIC;
        server.ai_family=AF_INET;server.so_mark=-1;std::strcpy(server.flags.ifname,"lo");service.stopping=1;
        pthread_mutexattr_t attr;pthread_mutexattr_init(&attr);pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&server.lock,&attr);pthread_mutexattr_destroy(&attr);atomic_set(&server.refcnt,1);
        INIT_LIST_HEAD(&server.conn_stream_list);server.fd=socket(AF_INET,SOCK_DGRAM,0);ASSERT_GE(server.fd,0);
        ASSERT_EQ(_dns_socket_prepare(&server,server.fd),0);server.status=DNS_SERVER_STATUS_CONNECTED;
        SSL_CTX *ctx=SSL_CTX_new(TLS_client_method());ASSERT_NE(ctx,nullptr);server.ssl=SSL_new(ctx);ASSERT_NE(server.ssl,nullptr);
        dns_conn_stream *streams[3]{};
        for(unsigned i=0;i<3;i++) {
            streams[i]=_dns_client_conn_stream_new_write();ASSERT_NE(streams[i],nullptr);
            if(i==0){streams[i]->quic_stream=SSL_new(ctx);ASSERT_NE(streams[i]->quic_stream,nullptr);}
            streams[i]->send_buff.len=1;streams[i]->server_info=&server;
            _dns_client_conn_stream_get(streams[i]);list_add_tail(&streams[i]->server_list,&server.conn_stream_list);
        }
        revoke_stage=mode;flush_turns=opened_streams=0;_dns_quic_lifecycle_test_hook=revoke_quic_lifecycle;
        if(mode==1)EXPECT_EQ(_dns_client_quic_poll_test(&server),-1);
        else {
            _dns_client_process_guard_enter(&server);epoll_event event{};event.events=EPOLLOUT;
            EXPECT_EQ(_dns_client_process_quic(&server,&event,get_tick_count()),-1);
            EXPECT_EQ(server.process_depth,1U);EXPECT_EQ(server.close_deferred,1);
            _dns_client_process_guard_leave(&server);
        }
        _dns_quic_lifecycle_test_hook=nullptr;
        int lock_result=EBUSY;std::thread other([&]{lock_result=pthread_mutex_trylock(&server.lock);if(!lock_result)pthread_mutex_unlock(&server.lock);});other.join();
        EXPECT_EQ(lock_result,0);EXPECT_EQ(server.process_depth,0U);EXPECT_EQ(server.close_deferred,0);
        EXPECT_EQ(server.fd,-1);EXPECT_TRUE(list_empty(&server.conn_stream_list));EXPECT_EQ(opened_streams,0U);
        for(auto *stream:streams){EXPECT_EQ(atomic_read(&stream->refcnt),1);EXPECT_TRUE(list_empty(&stream->server_list));EXPECT_EQ(stream->server_info,nullptr);_dns_client_conn_stream_put(stream);}
        SSL_CTX_free(ctx);pthread_mutex_destroy(&server.lock);
    }
}
#endif

}
