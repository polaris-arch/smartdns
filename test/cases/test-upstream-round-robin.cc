/* Bounded correctness fixtures only: no public DNS, load, or benchmarks. */
#include "gtest/gtest.h"
extern "C" {
#include "dns_client/upstream_policy.h"
#include "dns_client/client_socket.h"
#include "dns_client/client_udp.h"
#include "dns_client/proxy.h"
#include "smartdns/util.h"
}
#include <arpa/inet.h>
#include <atomic>
#include <cstring>
#include <thread>
#include <vector>
#include <unistd.h>
#include <chrono>
#include <sys/epoll.h>
#include <poll.h>

namespace {
struct RrEndpoint {
    dns_server_info s{};
    explicit RrEndpoint(int port, unsigned cap = 2, const char *name = "rr-unit") {
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&s.lock, &attr);
        pthread_mutexattr_destroy(&attr);
        INIT_LIST_HEAD(&s.conn_stream_list);
        atomic_set(&s.refcnt, 1);
        s.fd = -1;
        s.type = DNS_SERVER_HTTPS;
        s.in.sin_family = AF_INET;
        s.in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        s.in.sin_port = htons(port);
        s.ai_addrlen = sizeof(s.in);
        s.flags.upstream_round_robin = 1;
        s.flags.max_upstream_connections = cap;
        strncpy(s.flags.quota_group, name, sizeof(s.flags.quota_group)-1);
        EXPECT_EQ(_dns_policy_attach(&s), 0);
    }
    ~RrEndpoint() { _dns_policy_detach(&s); pthread_mutex_destroy(&s.lock); }
};
struct RrQuery {
    dns_query_struct q{};
    RrQuery() { pthread_mutex_init(&q.lock, nullptr); INIT_LIST_HEAD(&q.conn_stream_list); }
    ~RrQuery() { _dns_attempt_free_all(&q); dns_query_budget_put(q.budget); pthread_mutex_destroy(&q.lock); }
};
int Healthy(dns_server_info *s, void *) { return !s->prohibit; }
dns_server_info *Pick(RrQuery &q, std::vector<dns_server_info *> &members) {
    return _dns_policy_rr_begin(&q.q, members.data(), members.size(), members[0], Healthy, nullptr);
}
void Retire(RrQuery &q, dns_server_info *s) { ASSERT_EQ(_dns_attempt_retire(&q.q, s, 0), 1); }
}

TEST(UpstreamRoundRobin, StrictAlternationAndDuplicateGroupMembership) {
    RrEndpoint a(1), b(2);
    std::vector<dns_server_info *> members{&b.s, &a.s, &a.s};
    for (int i = 0; i < 10; i++) {
        RrQuery q;
        auto *picked = Pick(q, members);
        ASSERT_EQ(picked, i % 2 ? &b.s : &a.s);
        EXPECT_EQ(Pick(q, members), nullptr); // never fan out one active logical query
        Retire(q, picked);
    }
}
TEST(UpstreamRoundRobin, ConcurrentSelectionHasOneSharedCursor) {
    RrEndpoint a(1), b(2);
    std::vector<dns_server_info *> members{&a.s, &b.s};
    std::atomic<unsigned> counts[2]{};
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; i++) threads.emplace_back([&] {
        RrQuery q;
        auto *picked = Pick(q, members);
        EXPECT_NE(picked, nullptr);
        if (picked) { counts[picked == &b.s]++; Retire(q, picked); }
    });
    for (auto &thread : threads) thread.join();
    EXPECT_EQ(counts[0], 4U); EXPECT_EQ(counts[1], 4U);
}
TEST(UpstreamRoundRobin, HealthCapacityAndCancellationDoNotRewindCursor) {
    RrEndpoint a(1), b(2);
    std::vector<dns_server_info *> members{&a.s, &b.s};
    { RrQuery q; ASSERT_EQ(Pick(q, members), &a.s); q.q.terminal = 1; }
    { RrQuery q; ASSERT_EQ(Pick(q, members), &b.s); }
    a.s.prohibit = 1;
    { RrQuery q; ASSERT_EQ(Pick(q, members), &b.s); }
    a.s.prohibit = 0;
    { RrQuery q; ASSERT_EQ(Pick(q, members), &a.s); } // future turn, no debt
    { RrQuery q; ASSERT_EQ(Pick(q, members), &b.s); }
}
TEST(UpstreamRoundRobin, GroupIntersectionDoesNotSelectAnUnroutedMember) {
    RrEndpoint a(1, 4), b(2, 4), c(3, 4);
    std::vector<dns_server_info *> group{&a.s, &c.s};
    for (int i = 0; i < 6; i++) {
        RrQuery q;
        ASSERT_EQ(Pick(q, group), i % 2 ? &c.s : &a.s);
    }
    EXPECT_EQ(b.s.active_attempts, 0U);
}
TEST(UpstreamRoundRobin, PhysicalSlotsAreSharedIdempotentAndReleasedOnClose) {
    RrEndpoint a(1), b(2), c(3);
    EXPECT_EQ(_dns_policy_connection_acquire(&a.s), 0);
    EXPECT_EQ(_dns_policy_connection_acquire(&a.s), 0);
    EXPECT_EQ(_dns_policy_connection_acquire(&b.s), 0);
    EXPECT_EQ(_dns_policy_connection_acquire(&c.s), -1);
    _dns_client_close_socket(&a.s);
    EXPECT_EQ(_dns_policy_connection_acquire(&c.s), 0);
    EXPECT_EQ(_dns_policy_connection_acquire(&a.s), -1);
    _dns_client_close_socket(&b.s);
    _dns_client_close_socket(&b.s);
    EXPECT_EQ(_dns_policy_connection_acquire(&a.s), 0);
}
TEST(UpstreamRoundRobin, MaximumFourPhysicalReservationsAcrossAllEndpoints) {
    RrEndpoint a(1, 4), b(2, 4), c(3, 4), d(4, 4), e(5, 4);
    for (auto *s : {&a.s, &b.s, &c.s, &d.s}) EXPECT_EQ(_dns_policy_connection_acquire(s), 0);
    EXPECT_EQ(_dns_policy_connection_acquire(&e.s), -1);
    _dns_policy_connection_release(&c.s);
    EXPECT_EQ(_dns_policy_connection_acquire(&e.s), 0);
}
TEST(UpstreamRoundRobin, IncompatibleTransportSecurityAndQuerySemanticsAreRejected) {
    RrEndpoint a(1);
    dns_server_info bad{};
    bad.flags = a.s.flags; bad.type = DNS_SERVER_UDP;
    EXPECT_EQ(_dns_policy_attach(&bad), -1);
    bad.type = a.s.type; strcpy(bad.flags.https.path, "/different-dns");
    EXPECT_EQ(_dns_policy_attach(&bad), -1);
    bad.flags = a.s.flags; strcpy(bad.flags.https.hostname, "other.test");
    EXPECT_EQ(_dns_policy_attach(&bad), -1);
    bad.flags = a.s.flags; bad.flags.https.skip_check_cert = 1;
    EXPECT_EQ(_dns_policy_attach(&bad), -1);
    bad.flags = a.s.flags; bad.flags.result_flag = 1;
    EXPECT_EQ(_dns_policy_attach(&bad), -1);
    bad.flags = a.s.flags; bad.flags.upstream_round_robin = bad.flags.max_upstream_connections = 0;
    EXPECT_EQ(_dns_policy_attach(&bad), -1);
}
TEST(UpstreamRoundRobin, NewEpochRejectsOldUnsentOwnerAndProbeFollowsCursor) {
    RrEndpoint a(1), b(2);
    std::vector<dns_server_info *> members{&a.s, &b.s};
    RrQuery old, probe, waiting;
    ASSERT_EQ(Pick(old, members), &a.s);
    _dns_policy_http_error(&b.s, 429, "0");
    EXPECT_EQ(Pick(probe, members), nullptr);
    EXPECT_EQ(_dns_attempt_wire_begin(&old.q, &a.s, _dns_attempt_generation(&old.q, &a.s)), DNS_ADMIT_DONE);
    Retire(old, &a.s);
    usleep(150000);
    ASSERT_EQ(Pick(probe, members), &b.s);
    EXPECT_EQ(Pick(waiting, members), nullptr); // probe reserved before handshake
    auto gen = _dns_attempt_generation(&probe.q, &b.s);
    ASSERT_EQ(_dns_attempt_wire_begin(&probe.q, &b.s, gen), DNS_ADMIT_OK);
    _dns_attempt_mark_sent(&probe.q, &b.s, gen);
    _dns_attempt_replied(&probe.q, &b.s);
    Retire(probe, &b.s);
    EXPECT_EQ(Pick(waiting, members), &a.s);
}
TEST(UpstreamRoundRobin, OldInflightReplyCannotClearNewEpochAndRetiredProbeReleasesLease) {
    RrEndpoint a(1), b(2);
    std::vector<dns_server_info *> members{&a.s, &b.s};
    RrQuery old, probe, waiting;
    ASSERT_EQ(Pick(old, members), &a.s);
    auto gen = _dns_attempt_generation(&old.q, &a.s);
    ASSERT_EQ(_dns_attempt_wire_begin(&old.q, &a.s, gen), DNS_ADMIT_OK);
    _dns_attempt_mark_sent(&old.q, &a.s, gen);
    _dns_policy_http_error(&b.s, 429, "0");
    EXPECT_EQ(_dns_attempt_wire_begin(&old.q, &a.s, gen), DNS_ADMIT_OK); // continuation
    _dns_attempt_replied(&old.q, &a.s);
    Retire(old, &a.s);
    usleep(150000);
    ASSERT_EQ(Pick(probe, members), &b.s);
    EXPECT_EQ(Pick(waiting, members), nullptr);
    Retire(probe, &b.s);
    EXPECT_EQ(Pick(waiting, members), &a.s);
}
TEST(UpstreamRoundRobin, ParentDeadlineAndBudgetRemainAuthoritative) {
    RrEndpoint a(1), b(2);
    std::vector<dns_server_info *> members{&a.s, &b.s};
    RrQuery q;
    q.q.budget = dns_query_budget_new(1, 1000);
    ASSERT_EQ(Pick(q, members), &a.s);
    ASSERT_EQ(_dns_attempt_wire_begin(&q.q, &a.s, _dns_attempt_generation(&q.q, &a.s)), DNS_ADMIT_OK);
    Retire(q, &a.s);
    EXPECT_EQ(Pick(q, members), nullptr);
    RrQuery cancelled; cancelled.q.budget = dns_query_budget_new(4, 1000);
    dns_query_budget_cancel(cancelled.q.budget);
    EXPECT_EQ(Pick(cancelled, members), nullptr);
}

TEST(UpstreamRoundRobin, BusyEndpointsAreSkippedWithoutDoubleAdmission) {
    RrEndpoint a(1), b(2);
    a.s.flags.max_concurrent_queries = b.s.flags.max_concurrent_queries = 1;
    std::vector<dns_server_info *> members{&a.s, &b.s};
    RrQuery first, second, third;
    ASSERT_EQ(Pick(first, members), &a.s);
    ASSERT_EQ(Pick(second, members), &b.s);
    EXPECT_EQ(Pick(third, members), nullptr);
    Retire(first, &a.s);
    EXPECT_EQ(Pick(third, members), &a.s);
    EXPECT_EQ(a.s.active_attempts, 1U); EXPECT_EQ(b.s.active_attempts, 1U);
}
TEST(UpstreamRoundRobin, FailedPhysicalCreationReleasesItsReservation) {
    RrEndpoint a(1, 1), b(2, 1);
    // Deterministic unsupported constructor exercises the common cleanup path
    // without contacting an endpoint or depending on OS descriptor numbering.
    a.s.type = DNS_SERVER_TYPE_END;
    ASSERT_EQ(_dns_policy_connection_acquire(&a.s), 0);
    EXPECT_EQ(_dns_client_create_socket(&a.s), -1);
    EXPECT_EQ(a.s.fd, -1); EXPECT_EQ(a.s.policy_connection_held, 0);
    EXPECT_EQ(_dns_policy_connection_acquire(&b.s), 0);
}

TEST(UpstreamRoundRobin, ProxyConnectingEnqueuesWholeFramesUnderEndpointLock) {
    RrEndpoint endpoint(1);
    auto &s = endpoint.s;
    s.fd = 123; // CONNECTING enqueue never uses the descriptor/proxy object
    s.proxy = reinterpret_cast<proxy_conn *>(1);
    s.status = DNS_SERVER_STATUS_CONNECTING;
    unsigned char first[] = {1, 2, 3, 4, 5}, second[] = {6, 7, 8, 9, 10, 11, 12};
    std::atomic<int> started{0}, done{0};
    pthread_mutex_lock(&s.lock);
    std::thread a([&] { started++; EXPECT_EQ(_dns_client_send_udp(&s, first, sizeof(first)), 0); done++; });
    std::thread b([&] { started++; EXPECT_EQ(_dns_client_send_udp(&s, second, sizeof(second)), 0); done++; });
    while (started != 2) std::this_thread::yield();
    // Bounded blocking assertion: both producers must obey the endpoint mutex.
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_EQ(done, 0);
    pthread_mutex_unlock(&s.lock);
    a.join(); b.join();
    EXPECT_EQ(s.send_buff.len, int(sizeof(first) + sizeof(second) + 2 * sizeof(int)));
    int offset = 0; bool seen_first = false, seen_second = false;
    for (int i = 0; i < 2; i++) {
        int length = 0; memcpy(&length, s.send_buff.data + offset, sizeof(length)); offset += sizeof(length);
        if (length == sizeof(first)) { EXPECT_EQ(memcmp(s.send_buff.data + offset, first, length), 0); seen_first = true; }
        else if (length == sizeof(second)) { EXPECT_EQ(memcmp(s.send_buff.data + offset, second, length), 0); seen_second = true; }
        else { ADD_FAILURE() << "interleaved frame length " << length; break; }
        offset += length;
    }
    EXPECT_TRUE(seen_first && seen_second);
    // Header space alone is insufficient: failure cannot leave a partial record.
    s.send_buff.len = DNS_TCP_BUFFER - sizeof(int);
    unsigned char tail[sizeof(int)]; memcpy(tail, s.send_buff.data + s.send_buff.len, sizeof(tail));
    EXPECT_EQ(_dns_client_send_udp(&s, first, sizeof(first)), -1);
    EXPECT_EQ(s.send_buff.len, int(DNS_TCP_BUFFER - sizeof(int)));
    EXPECT_EQ(memcmp(tail, s.send_buff.data + s.send_buff.len, sizeof(tail)), 0);
    s.proxy = nullptr; s.fd = -1; s.send_buff.len = 0;
}

TEST(UpstreamRoundRobin, MixedGroupLegacyFirstConnectionIsNotFalselyProhibited) {
    RrEndpoint rr(1), legacy(2, 2, "legacy-mixed-fixture");
    _dns_policy_detach(&legacy.s);
    legacy.s.flags.upstream_round_robin = legacy.s.flags.max_upstream_connections = 0;
    legacy.s.type = DNS_SERVER_UDP;
    ASSERT_EQ(_dns_policy_attach(&legacy.s), 0);
    rr.s.flags.fallback = 1; // first pass selects only the ordinary group member
    int receiver = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(receiver, 0);
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(bind(receiver, reinterpret_cast<sockaddr *>(&address), sizeof(address)), 0);
    socklen_t size = sizeof(address); ASSERT_EQ(getsockname(receiver, reinterpret_cast<sockaddr *>(&address), &size), 0);
    legacy.s.in = address; legacy.s.ai_family = AF_INET;
    timeval timeout{1, 0}; setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    int previous_epoll = client.epoll_fd;
    client.epoll_fd = epoll_create1(EPOLL_CLOEXEC); ASSERT_GE(client.epoll_fd, 0);
    pthread_mutexattr_t attr; pthread_mutexattr_init(&attr); pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&client.server_list_lock, &attr); pthread_mutexattr_destroy(&attr);
    dns_server_group group{}; INIT_LIST_HEAD(&group.head); group.round_robin_members = 1;
    dns_server_group_member members[2]{};
    members[0].server = &rr.s; members[1].server = &legacy.s;
    for (auto &member : members) list_add_tail(&member.list, &group.head);
    RrQuery first, second;
    first.q.server_group = second.q.server_group = &group;
    first.q.created_tick = second.q.created_tick = get_tick_count();
    unsigned char packet[12]{};
    std::atomic<int> ready{0};
    auto send = [&](RrQuery &q) { ready++; while (ready != 2) std::this_thread::yield(); EXPECT_EQ(_dns_client_send_packet(&q.q, packet, sizeof(packet)), 0); };
    std::thread a([&] { send(first); }), b([&] { send(second); }); a.join(); b.join();
    EXPECT_EQ(legacy.s.prohibit, 0); EXPECT_GT(legacy.s.fd, 0);
    unsigned char received[16];
    EXPECT_EQ(recv(receiver, received, sizeof(received), 0), sizeof(packet));
    EXPECT_EQ(recv(receiver, received, sizeof(received), 0), sizeof(packet));
    _dns_client_close_socket(&legacy.s);
    close(receiver); close(client.epoll_fd); client.epoll_fd = previous_epoll;
    pthread_mutex_destroy(&client.server_list_lock);
}

TEST(UpstreamRoundRobin, LoopbackSocks5HandshakeDrainsCompleteQueuedDatagrams) {
    // Use the existing production proxy and UDP entry points with a tiny local
    // SOCKS5 peer. Two datagrams only; no load loop or performance measurement.
    struct Fd { int value = -1; ~Fd() { if (value >= 0) close(value); } } listener, relay, peer;
    listener.value = socket(AF_INET, SOCK_STREAM, 0);
    relay.value = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(listener.value, 0); ASSERT_GE(relay.value, 0);
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(bind(listener.value, reinterpret_cast<sockaddr *>(&address), sizeof(address)), 0);
    ASSERT_EQ(listen(listener.value, 1), 0);
    socklen_t addrlen = sizeof(address);
    ASSERT_EQ(getsockname(listener.value, reinterpret_cast<sockaddr *>(&address), &addrlen), 0);
    proxy_info info{}; info.type = PROXY_SOCKS5; strcpy(info.server, "127.0.0.1"); info.port = ntohs(address.sin_port);
    address.sin_port = 0;
    ASSERT_EQ(bind(relay.value, reinterpret_cast<sockaddr *>(&address), sizeof(address)), 0);
    ASSERT_EQ(getsockname(relay.value, reinterpret_cast<sockaddr *>(&address), &addrlen), 0);
    timeval timeout{1, 0}; setsockopt(relay.value, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ASSERT_EQ(proxy_init(), 0);
    RrEndpoint endpoint(5300);
    struct Cleanup {
        dns_server_info *s; int previous_epoll;
        ~Cleanup() { _dns_client_close_socket(s); proxy_exit(); if (client.epoll_fd >= 0) close(client.epoll_fd); client.epoll_fd = previous_epoll; }
    } cleanup{&endpoint.s, client.epoll_fd};
    client.epoll_fd = epoll_create1(EPOLL_CLOEXEC); ASSERT_GE(client.epoll_fd, 0);
    ASSERT_EQ(proxy_add("rr-local-socks", &info), 0);
    auto &s = endpoint.s;
    s.type = DNS_SERVER_UDP; s.ai_family = AF_INET; s.so_mark = -1;
    strcpy(s.ip, "127.0.0.1"); s.port = 5300; strcpy(s.proxy_name, "rr-local-socks");
    ASSERT_EQ(_dns_client_create_socket(&s), 0);
    pollfd ready{listener.value, POLLIN, 0}; ASSERT_EQ(poll(&ready, 1, 1000), 1);
    peer.value = accept(listener.value, nullptr, nullptr); ASSERT_GE(peer.value, 0);
    setsockopt(peer.value, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    unsigned char first[] = {0x11, 0x22, 0x33}, second[] = {0x44, 0x55, 0x66, 0x77, 0x88};
    ASSERT_EQ(_dns_client_send_udp(&s, first, sizeof(first)), 0);
    ASSERT_EQ(_dns_client_send_udp(&s, second, sizeof(second)), 0);
    EXPECT_EQ(s.send_buff.len, int(sizeof(first) + sizeof(second) + 2 * sizeof(int)));
    epoll_event event{}; event.events = EPOLLOUT; event.data.ptr = &s;
    _dns_proxy_handshake(&s, &event, get_tick_count());
    unsigned char bytes[64]{};
    ASSERT_EQ(recv(peer.value, bytes, 4, MSG_WAITALL), 4);
    EXPECT_EQ(bytes[0], 5); EXPECT_EQ(bytes[1], 2);
    unsigned char auth[] = {5, 0}; ASSERT_EQ(send(peer.value, auth, sizeof(auth), MSG_NOSIGNAL), sizeof(auth));
    event.events = EPOLLIN; _dns_proxy_handshake(&s, &event, get_tick_count());
    ASSERT_EQ(recv(peer.value, bytes, 10, MSG_WAITALL), 10);
    EXPECT_EQ(bytes[0], 5); EXPECT_EQ(bytes[1], 3); EXPECT_EQ(bytes[3], 1);
    unsigned char associated[] = {5, 0, 0, 1, 127, 0, 0, 1, 0, 0};
    memcpy(associated + 8, &address.sin_port, 2);
    ASSERT_EQ(send(peer.value, associated, sizeof(associated), MSG_NOSIGNAL), sizeof(associated));
    event.events = EPOLLIN; EXPECT_EQ(_dns_proxy_handshake(&s, &event, get_tick_count()), 0);
    ASSERT_EQ(s.status, DNS_SERVER_STATUS_CONNECTED);
    event.events = EPOLLOUT;
    ASSERT_EQ(_dns_client_process_udp(&s, &event, get_tick_count()), 0);
    EXPECT_EQ(s.send_buff.len, 0);
    for (int i = 0; i < 2; i++) {
        int length = i ? sizeof(second) : sizeof(first);
        ASSERT_EQ(recv(relay.value, bytes, sizeof(bytes), 0), length + 10);
        EXPECT_EQ(bytes[0], 0); EXPECT_EQ(bytes[1], 0); EXPECT_EQ(bytes[2], 0); EXPECT_EQ(bytes[3], 1);
        EXPECT_EQ(memcmp(bytes + 4, &s.in.sin_addr, 4), 0);
        EXPECT_EQ(memcmp(bytes + 8, &s.in.sin_port, 2), 0);
        EXPECT_EQ(memcmp(bytes + 10, i ? second : first, length), 0);
    }
    // Exercise production nonblocking recv with no response, retaining the
    // connected proxy and leaving the drained queue empty.
    event.events = EPOLLIN;
    EXPECT_EQ(_dns_client_process_udp(&s, &event, get_tick_count()), 0);
    EXPECT_EQ(s.status, DNS_SERVER_STATUS_CONNECTED); EXPECT_EQ(s.send_buff.len, 0);
}
