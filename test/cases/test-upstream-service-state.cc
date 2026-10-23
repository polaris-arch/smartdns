/* Bounded production state-machine tests. No public peers or performance loops. */
#include "gtest/gtest.h"
extern "C" {
#include "dns_client/upstream_service.h"
#include "dns_client/upstream_policy.h"
#include "dns_client/client_socket.h"
#include "dns_client/query.h"
#include "smartdns/util.h"
}
#include <arpa/inet.h>
#include <cstring>
#include <memory>
#include <thread>
#include <atomic>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <cerrno>
#include <unistd.h>

namespace {
struct ServiceState {
    dns_upstream_service s{};
    std::unique_ptr<dns_server_info[]> endpoints;
    unsigned count;
    static std::vector<dns_upstream_service *> &Live() {
        static std::vector<dns_upstream_service *> live; return live;
    }
    ServiceState(unsigned n = 2, unsigned cap = 0, const char *quota = "", unsigned rate = 0, unsigned burst = 0, unsigned cooldown = 100)
      : endpoints(new dns_server_info[n]{}), count(n) {
        atomic_set(&s.refs, 1); pthread_mutex_init(&s.lock, nullptr); pthread_mutex_init(&s.turn_lock, nullptr);
        INIT_LIST_HEAD(&s.list); INIT_LIST_HEAD(&s.timer); INIT_LIST_HEAD(&s.waiters);
        s.started = 1; s.timer_due = ULONG_MAX; s.config.max_backends = n;
        s.type = DNS_SERVER_HTTPS; s.flags.type = s.type; s.flags.max_upstream_connections = cap;
        s.flags.max_query_rate = rate; s.flags.query_burst = burst;
        s.flags.upstream_cooldown_ms = cooldown; // explicit fixture timing; zero exercises the production default
        strncpy(s.flags.quota_group, quota, sizeof(s.flags.quota_group) - 1);
        EXPECT_EQ(_dns_policy_service_init(&s), 0);
        for (unsigned i = 0; i < n; i++) {
            auto &ep = endpoints[i]; pthread_mutexattr_t attr;
            pthread_mutexattr_init(&attr); pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
            pthread_mutex_init(&ep.lock, &attr); pthread_mutexattr_destroy(&attr);
            atomic_set(&ep.refcnt, 1); INIT_LIST_HEAD(&ep.conn_stream_list);
            ep.fd = -1; ep.type = s.type; ep.flags = s.flags; ep.service = &s;
            ep.service_member_id = i + 1; ep.service_valid_until = ULONG_MAX; ep.ai_family = AF_INET; ep.ai_addrlen = sizeof(ep.in);
            ep.in.sin_family = AF_INET; ep.in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            ep.in.sin_port = htons(63000 + i); ep.so_mark = -1;
            EXPECT_EQ(_dns_policy_attach(&ep), 0); s.members[s.member_count++] = &ep;
        }
        s.selected_count = n; Live().push_back(&s);
    }
    /* These fixtures invoke the scheduler explicitly. Suppress automatic query
     * dispatch during finalization, not the real state transitions or counters. */
    void Flush() {
        std::vector<unsigned long> old;
        for (auto *service : Live()) { old.push_back(service->next_eligible); service->next_eligible = ULONG_MAX; }
        _dns_services_flush_pending();
        for (unsigned i = 0; i < Live().size(); i++) Live()[i]->next_eligible = old[i];
    }
    ~ServiceState() {
        Flush(); s.stopping = 1; list_del_init(&s.timer);
        for (unsigned i = 0; i < count; i++) { _dns_policy_detach(&endpoints[i]); pthread_mutex_destroy(&endpoints[i].lock); }
        _dns_policy_service_release(&s); EXPECT_EQ(atomic_read(&s.refs), 1);
        pthread_mutex_destroy(&s.turn_lock); pthread_mutex_destroy(&s.lock);
        for (auto it = Live().begin(); it != Live().end(); ++it) if (*it == &s) { Live().erase(it); break; }
    }
};
struct ServiceQuery {
    dns_query_struct q{};
    ServiceState &owner;
    explicit ServiceQuery(ServiceState &s) : owner(s) {
        atomic_set(&q.refcnt, 1); pthread_mutex_init(&q.lock, nullptr);
        INIT_LIST_HEAD(&q.conn_stream_list); INIT_LIST_HEAD(&q.dns_request_list);
        q.created_tick = get_tick_count();
    }
    ~ServiceQuery() {
        // A failed ASSERT may leave the fixture between synchronous write hooks.
        // Complete that synthetic call before tearing down observation ownership.
        if (owner.s.turn_state == DNS_SERVICE_TURN_WRITING && owner.s.turn_observation &&
            owner.s.turn_observation->query == &q && owner.s.turn_endpoint)
            _dns_service_write_result(&q, owner.s.turn_endpoint, owner.s.turn_attempt_generation, 0, 0);
        q.terminal = 1; _dns_service_query_terminal(&q);
        _dns_attempt_free_all(&q); owner.Flush(); _dns_service_query_free(&q);
        dns_query_budget_put(q.budget); EXPECT_EQ(atomic_read(&q.refcnt), 1);
        pthread_mutex_destroy(&q.lock);
    }
};
dns_server_info *Pick(ServiceState &s, ServiceQuery &q) {
    auto *ep = _dns_service_select(&s.s, &q.q, nullptr, nullptr);
    if (ep) dns_client_server_info_release(ep); // fixture owner pins every member
    return ep;
}
unsigned Generation(ServiceQuery &q, dns_server_info *ep) { return _dns_attempt_generation(&q.q, ep); }
void Positive(ServiceState &s, ServiceQuery &q, dns_server_info *ep) {
    unsigned gen = Generation(q, ep);
    ASSERT_EQ(_dns_attempt_wire_begin(&q.q, ep, gen), DNS_ADMIT_OK);
    _dns_attempt_mark_sent(&q.q, ep, gen);
    s.Flush();
}
void Retire(ServiceQuery &q, dns_server_info *ep) { EXPECT_EQ(_dns_attempt_retire(&q.q, ep, 0), 1); }
}

TEST(UpstreamServiceState, CursorCommitsOnlyPositiveRequestWrites) {
    ServiceState s;
    { ServiceQuery canceled(s); auto *ep = Pick(s, canceled); ASSERT_EQ(ep, &s.endpoints[0]);
      EXPECT_EQ(s.s.cursor, 0U); Retire(canceled, ep); s.Flush(); EXPECT_EQ(s.s.cursor, 0U); }
    { ServiceQuery a(s); auto *ep = Pick(s, a); ASSERT_EQ(ep, &s.endpoints[0]); Positive(s, a, ep);
      EXPECT_EQ(s.s.cursor, 1U); EXPECT_EQ(s.s.stats.attempt_count, 1U); Retire(a, ep); }
    { ServiceQuery b(s); auto *ep = Pick(s, b); ASSERT_EQ(ep, &s.endpoints[1]); Positive(s, b, ep);
      EXPECT_EQ(s.s.cursor, 2U); EXPECT_EQ(s.s.stats.attempt_count, 2U); Retire(b, ep); }
    EXPECT_EQ(s.s.stats.query_count, 3U); EXPECT_EQ(s.s.stats.skip_count, 1U);
    EXPECT_EQ(s.s.stats.failure_count, 2U); EXPECT_EQ(s.s.stats.in_flight, 0U);
}
TEST(UpstreamServiceState, WantWriteRetainsOneTurnAndAbortedOwnerCannotResume) {
    ServiceState s; ServiceQuery first(s), second(s);
    auto *ep = Pick(s, first); ASSERT_NE(ep, nullptr); auto gen = Generation(first, ep);
    ASSERT_EQ(_dns_attempt_wire_begin(&first.q, ep, gen), DNS_ADMIT_OK);
    _dns_service_write_result(&first.q, ep, gen, 0, 1);
    EXPECT_EQ(s.s.turn_state, unsigned(DNS_SERVICE_TURN_WRITE_WAIT)); EXPECT_EQ(Pick(s, second), nullptr);
    EXPECT_EQ(s.s.cursor, 0U); EXPECT_EQ(s.s.stats.attempt_count, 0U);
    Retire(first, ep); s.Flush();
    EXPECT_EQ(_dns_service_write_begin(&first.q, ep, gen), DNS_ADMIT_DONE);
    auto *next = Pick(s, second); ASSERT_EQ(next, ep); Positive(s, second, next); Retire(second, next);
}
TEST(UpstreamServiceState, PositiveWriteWinningCancellationCannotBecomeSkip) {
    ServiceState s; ServiceQuery q(s);
    auto *ep = Pick(s, q); ASSERT_NE(ep, nullptr); auto gen = Generation(q, ep);
    ASSERT_EQ(_dns_attempt_wire_begin(&q.q, ep, gen), DNS_ADMIT_OK);
    q.q.terminal = 1; _dns_service_query_terminal(&q.q);
    s.Flush(); EXPECT_EQ(s.s.stats.skip_count, 0U); EXPECT_EQ(s.s.stats.in_flight, 1U);
    _dns_attempt_mark_sent(&q.q, ep, gen); s.Flush();
    EXPECT_EQ(s.s.stats.attempt_count, 1U); EXPECT_EQ(s.s.stats.failure_count, 1U);
    EXPECT_EQ(s.s.stats.skip_count, 0U); EXPECT_EQ(s.s.stats.in_flight, 0U); EXPECT_EQ(s.s.cursor, 1U);
    Retire(q, ep);
}
TEST(UpstreamServiceState, ReadyEndpointFailureIsolationAndNoCatchupDebt) {
    ServiceState s;
    _dns_service_endpoint_failure(&s.endpoints[0]); s.Flush();
    { ServiceQuery q(s); auto *ep = Pick(s, q); ASSERT_EQ(ep, &s.endpoints[1]); Positive(s, q, ep); Retire(q, ep); }
    EXPECT_GT(s.endpoints[0].service_retry_at, get_tick_count());
    s.endpoints[0].service_retry_at = 0;
    { ServiceQuery q(s); auto *ep = Pick(s, q); ASSERT_EQ(ep, &s.endpoints[0]); Positive(s, q, ep); Retire(q, ep); }
}
TEST(UpstreamServiceState, ConfigurablePhysicalCapIncludesConnectingAndRevokedMembers) {
    ServiceState s(5, 3);
    for (unsigned i = 0; i < 3; i++) { ASSERT_EQ(_dns_policy_connection_acquire(&s.endpoints[i]), 0); EXPECT_EQ(_dns_policy_connection_acquire(&s.endpoints[i]), 0); }
    EXPECT_EQ(s.s.connections, 3U); EXPECT_EQ(_dns_policy_connection_acquire(&s.endpoints[3]), -1);
    s.endpoints[0].service_revoked = 1; EXPECT_EQ(_dns_policy_connection_acquire(&s.endpoints[3]), -1);
    _dns_policy_connection_release(&s.endpoints[0]); EXPECT_EQ(_dns_policy_connection_acquire(&s.endpoints[3]), 0);
    for (unsigned i = 0; i < 5; i++) _dns_policy_connection_release(&s.endpoints[i]); s.Flush(); EXPECT_EQ(s.s.connections, 0U);
}
TEST(UpstreamServiceState, UnspecifiedPhysicalCapTracksActualMembersNotTwo) {
    ServiceState s(5);
    for (unsigned i = 0; i < 5; i++) EXPECT_EQ(_dns_policy_connection_acquire(&s.endpoints[i]), 0);
    EXPECT_EQ(s.s.connections, 5U);
    for (unsigned i = 0; i < 5; i++) _dns_policy_connection_release(&s.endpoints[i]); s.Flush();
}
TEST(UpstreamServiceState, SharedQuotaNeverMultipliesWithDifferentServicesOrIPs) {
    ServiceState a(2, 0, "state-shared", 1, 1), b(2, 0, "state-shared", 1, 1);
    ServiceQuery qa(a), qb(b);
    auto *ep = Pick(a, qa); ASSERT_NE(ep, nullptr); Positive(a, qa, ep);
    EXPECT_EQ(Pick(b, qb), nullptr); EXPECT_EQ(b.s.stats.attempt_count, 0U);
    Retire(qa, ep);
    // Prevent another service's pending finalization from autonomously dispatching.
    qb.q.terminal = 1; _dns_service_query_terminal(&qb.q); b.Flush();
}
TEST(UpstreamServiceState, ParentBudgetAndDeadlineRemainAuthoritativeAcrossIPs) {
    ServiceState s; ServiceQuery q(s); q.q.budget = dns_query_budget_new(1, 1000);
    auto *ep = Pick(s, q); ASSERT_NE(ep, nullptr); Positive(s, q, ep); Retire(q, ep);
    EXPECT_EQ(Pick(s, q), nullptr); s.Flush(); EXPECT_EQ(s.s.stats.attempt_count, 1U);
    ServiceQuery expired(s); expired.q.budget = dns_query_budget_new(2, 1000); dns_query_budget_cancel(expired.q.budget);
    EXPECT_EQ(Pick(s, expired), nullptr); s.Flush();
}
TEST(UpstreamRoundRobin, MixedGroupLegacyFirstConnectionIsNotFalselyProhibited) {
    ServiceState pool(1);
    auto &legacy = pool.endpoints[0];
    _dns_policy_detach(&legacy); legacy.service = nullptr; legacy.type = DNS_SERVER_UDP;
    legacy.flags.max_upstream_connections = 0; ASSERT_EQ(_dns_policy_attach(&legacy), 0);
    pool.s.member_count = pool.s.selected_count = 0; // legitimate discovering pool alongside ordinary endpoint
    int receiver = socket(AF_INET, SOCK_DGRAM, 0); ASSERT_GE(receiver, 0);
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(bind(receiver, reinterpret_cast<sockaddr *>(&address), sizeof(address)), 0);
    socklen_t size = sizeof(address); ASSERT_EQ(getsockname(receiver, reinterpret_cast<sockaddr *>(&address), &size), 0);
    legacy.in = address; legacy.ai_family = AF_INET;
    timeval timeout{1, 0}; setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    int previous_epoll = client.epoll_fd;
    client.epoll_fd = epoll_create1(EPOLL_CLOEXEC); ASSERT_GE(client.epoll_fd, 0);
    pthread_mutexattr_t attr; pthread_mutexattr_init(&attr); pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&client.server_list_lock, &attr); pthread_mutexattr_destroy(&attr);
    dns_server_group group{}; INIT_LIST_HEAD(&group.head); group.service_members = 1;
    dns_server_group_member members[2]{};
    members[0].service = &pool.s; members[1].server = &legacy;
    for (auto &member : members) list_add_tail(&member.list, &group.head);
    {
        ServiceQuery first(pool), second(pool);
        first.q.server_group = second.q.server_group = &group;
        unsigned char packet[12]{}; std::atomic<int> ready{0};
        auto send = [&](ServiceQuery &q) { ready++; while (ready != 2) std::this_thread::sleep_for(std::chrono::milliseconds(1)); EXPECT_EQ(_dns_client_send_packet(&q.q, packet, sizeof(packet)), 0); };
        std::thread a([&] { send(first); }), b([&] { send(second); }); a.join(); b.join();
        EXPECT_EQ(legacy.prohibit, 0); EXPECT_GE(legacy.fd, 0);
        unsigned char received[16];
        EXPECT_EQ(recv(receiver, received, sizeof(received), 0), sizeof(packet));
        EXPECT_EQ(recv(receiver, received, sizeof(received), 0), sizeof(packet));
        _dns_client_close_socket(&legacy);
    }
    close(receiver); close(client.epoll_fd); client.epoll_fd = previous_epoll;
    pthread_mutex_destroy(&client.server_list_lock);
}
TEST(UpstreamServiceState, NewEpochRejectsOldUnsentOwnerAndAllowsExactlyOneProbe) {
    ServiceState s; ServiceQuery old(s), probe(s), waiting(s);
    auto *old_ep = Pick(s, old); ASSERT_NE(old_ep, nullptr); unsigned old_gen = Generation(old, old_ep);
    _dns_policy_http_error(&s.endpoints[1], 429, "0");
    EXPECT_EQ(_dns_attempt_wire_begin(&old.q, old_ep, old_gen), DNS_ADMIT_DONE);
    Retire(old, old_ep); s.Flush();
    EXPECT_EQ(Pick(s, probe), nullptr);
    usleep(150000); // configured 100ms fixture cooldown, no traffic/load loop
    auto *probe_ep = Pick(s, probe); ASSERT_EQ(probe_ep, &s.endpoints[0]);
    EXPECT_EQ(Pick(s, waiting), nullptr); // probe held before handshake/first write
    Positive(s, probe, probe_ep); EXPECT_EQ(Pick(s, waiting), nullptr); // lease committed, recovery still exclusive
    _dns_attempt_replied(&probe.q, probe_ep); Retire(probe, probe_ep);
    s.s.next_eligible = 0; // deterministic advisory-timer wake after policy recovery
    auto *next = Pick(s, waiting); ASSERT_EQ(next, &s.endpoints[1]); Retire(waiting, next); s.Flush();
}
TEST(UpstreamServiceState, OldInflightReplyCannotClearNewEpochAndCanceledProbeReleasesOnlyItsLease) {
    ServiceState s; ServiceQuery old(s), probe(s), replacement(s);
    auto *old_ep = Pick(s, old); ASSERT_NE(old_ep, nullptr); Positive(s, old, old_ep);
    _dns_policy_http_error(&s.endpoints[1], 503, "0");
    _dns_attempt_replied(&old.q, old_ep); Retire(old, old_ep);
    EXPECT_GT(_dns_policy_service_wait(&s.s, get_tick_count()), 0UL);
    usleep(150000); s.s.next_eligible = 0;
    auto *probe_ep = Pick(s, probe); ASSERT_EQ(probe_ep, &s.endpoints[1]);
    EXPECT_EQ(Pick(s, replacement), nullptr);
    Retire(probe, probe_ep); s.Flush(); s.s.next_eligible = 0;
    auto *next = Pick(s, replacement); ASSERT_EQ(next, probe_ep); // unsent probe did not consume RR turn
    Positive(s, replacement, next); _dns_attempt_replied(&replacement.q, next); Retire(replacement, next);
    EXPECT_EQ(_dns_policy_service_wait(&s.s, get_tick_count()), 0UL);
}
TEST(UpstreamServiceState, ConcurrentSelectionsReserveExactlyOneUncommittedTurn) {
    ServiceState s;
    std::unique_ptr<ServiceQuery> queries[8]; dns_server_info *chosen[8]{};
    std::vector<std::thread> workers; std::atomic<unsigned> ready{0};
    for (auto &q : queries) q.reset(new ServiceQuery(s));
    for (unsigned i = 0; i < 8; i++) workers.emplace_back([&, i] {
        ready++; while (ready != 8) std::this_thread::sleep_for(std::chrono::milliseconds(1)); chosen[i] = Pick(s, *queries[i]);
    });
    for (auto &worker : workers) worker.join();
    unsigned winners = 0;
    for (unsigned i = 0; i < 8; i++) if (chosen[i]) {
        winners++; EXPECT_EQ(chosen[i], &s.endpoints[0]); Positive(s, *queries[i], chosen[i]); Retire(*queries[i], chosen[i]);
    }
    EXPECT_EQ(winners, 1U); EXPECT_EQ(s.s.stats.attempt_count, 1U); EXPECT_EQ(s.s.cursor, 1U);
}
TEST(UpstreamServiceState, ServiceConcurrencyAndOneActiveAttemptDoNotMultiplyPerIP) {
    ServiceState s; s.s.flags.max_concurrent_queries = 1;
    for (unsigned i = 0; i < s.count; i++) s.endpoints[i].flags.max_concurrent_queries = 1;
    ServiceQuery a(s), b(s); auto *ep = Pick(s, a); ASSERT_NE(ep, nullptr); Positive(s, a, ep);
    EXPECT_EQ(Pick(s, a), nullptr); EXPECT_EQ(Pick(s, b), nullptr); EXPECT_EQ(s.s.active_attempts, 1U);
    Retire(a, ep); auto *other = Pick(s, b); ASSERT_EQ(other, &s.endpoints[1]); Retire(b, other); s.Flush();
}
TEST(UpstreamServiceState, ResponseBeforeCommitFinalizesOnceWithConsistentOutcomes) {
    ServiceState s; ServiceQuery q(s); auto *ep = Pick(s, q); ASSERT_NE(ep, nullptr);
    unsigned gen = Generation(q, ep); ASSERT_EQ(_dns_attempt_wire_begin(&q.q, ep, gen), DNS_ADMIT_OK);
    _dns_service_query_result(&q.q, ep, 1); s.Flush();
    EXPECT_EQ(s.s.stats.success_count, 0U); EXPECT_EQ(s.s.stats.skip_count, 0U); EXPECT_EQ(s.s.stats.in_flight, 1U);
    _dns_attempt_mark_sent(&q.q, ep, gen); s.Flush();
    EXPECT_EQ(s.s.stats.attempt_count, 1U); EXPECT_EQ(s.s.stats.success_count, 1U); EXPECT_EQ(s.s.stats.in_flight, 0U);
    _dns_service_query_result(&q.q, ep, 1); s.Flush(); EXPECT_EQ(s.s.stats.success_count, 1U);
    EXPECT_EQ(s.s.stats.query_count, s.s.stats.success_count + s.s.stats.failure_count + s.s.stats.skip_count + s.s.stats.in_flight);
    Retire(q, ep);
}
TEST(UpstreamServiceState, FailedPhysicalCreationReleasesItsReservation) {
    ServiceState s(2, 1); auto &a = s.endpoints[0]; auto &b = s.endpoints[1];
    a.type = DNS_SERVER_TYPE_END;
    ASSERT_EQ(_dns_policy_connection_acquire(&a), 0); EXPECT_EQ(_dns_client_create_socket(&a), -1);
    EXPECT_EQ(a.fd, -1); EXPECT_EQ(a.service_connection_held, 0);
    EXPECT_EQ(_dns_policy_connection_acquire(&b), 0); _dns_policy_connection_release(&b); s.Flush();
}
TEST(UpstreamServiceState, CancellationDuringSelectionCannotReleaseAnotherTurn) {
    ServiceState s; ServiceQuery canceled(s), waiting(s);
    struct Gate { std::mutex lock; std::condition_variable cv; bool entered = false, release = false; } gate;
    auto eligible = [](dns_server_info *, void *opaque) -> int {
        auto &g = *static_cast<Gate *>(opaque); std::unique_lock<std::mutex> lock(g.lock);
        g.entered = true; g.cv.notify_one(); g.cv.wait(lock, [&] { return g.release; }); return 1;
    };
    dns_server_info *selected = nullptr;
    std::thread selector([&] { selected = _dns_service_select(&s.s, &canceled.q, eligible, &gate); });
    {
        std::unique_lock<std::mutex> lock(gate.lock);
        EXPECT_TRUE(gate.cv.wait_for(lock, std::chrono::seconds(1), [&] { return gate.entered; }));
    }
    EXPECT_EQ(s.s.turn_state, unsigned(DNS_SERVICE_TURN_SELECTING));
    pthread_mutex_lock(&canceled.q.lock); canceled.q.terminal = 1; pthread_mutex_unlock(&canceled.q.lock);
    _dns_service_query_terminal(&canceled.q); s.Flush();
    EXPECT_EQ(s.s.turn_state, unsigned(DNS_SERVICE_TURN_SELECTING));
    EXPECT_EQ(s.s.stats.skip_count, 0U); EXPECT_EQ(Pick(s, waiting), nullptr);
    { std::lock_guard<std::mutex> lock(gate.lock); gate.release = true; gate.cv.notify_one(); }
    selector.join(); EXPECT_EQ(selected, nullptr); if (selected) dns_client_server_info_release(selected);
    s.Flush(); EXPECT_EQ(s.s.turn_state, unsigned(DNS_SERVICE_TURN_IDLE));
    EXPECT_EQ(s.s.stats.skip_count, 1U); EXPECT_EQ(s.s.cursor, 0U);
    auto *ep = Pick(s, waiting); ASSERT_EQ(ep, &s.endpoints[0]); Retire(waiting, ep); s.Flush();
}
TEST(UpstreamServiceState, CancelBeforePositiveWriteSkipsButCancelAfterPositivePendingCountsFailure) {
    ServiceState s;
    {
        ServiceQuery before(s); auto *ep = Pick(s, before); ASSERT_NE(ep, nullptr); auto gen = Generation(before, ep);
        before.q.terminal = 1; _dns_service_query_terminal(&before.q); Retire(before, ep); s.Flush();
        EXPECT_EQ(_dns_attempt_wire_begin(&before.q, ep, gen), DNS_ADMIT_DONE);
        EXPECT_EQ(s.s.cursor, 0U); EXPECT_EQ(s.s.stats.skip_count, 1U); EXPECT_EQ(s.s.stats.attempt_count, 0U);
    }
    {
        ServiceQuery after(s), waiting(s); auto *ep = Pick(s, after); ASSERT_NE(ep, nullptr); auto gen = Generation(after, ep);
        ASSERT_EQ(_dns_attempt_wire_begin(&after.q, ep, gen), DNS_ADMIT_OK); _dns_attempt_mark_sent(&after.q, ep, gen);
        EXPECT_EQ(s.s.turn_state, unsigned(DNS_SERVICE_TURN_COMMIT_PENDING)); EXPECT_EQ(Pick(s, waiting), nullptr);
        after.q.terminal = 1; _dns_service_query_terminal(&after.q); Retire(after, ep);
        EXPECT_EQ(s.s.stats.attempt_count, 0U); // finalization has not run, ownership still retained
        s.Flush(); EXPECT_EQ(s.s.cursor, 1U); EXPECT_EQ(s.s.stats.attempt_count, 1U);
        EXPECT_EQ(s.s.stats.failure_count, 1U); EXPECT_EQ(s.s.stats.skip_count, 1U);
    }
}
TEST(UpstreamServiceState, FiveBackendActualSendOrderIsStableAndBalanced) {
    ServiceState s(5); unsigned sent[5]{};
    for (unsigned i = 0; i < 10; i++) {
        ServiceQuery q(s); auto *ep = Pick(s, q); ASSERT_EQ(ep, &s.endpoints[i % 5]);
        Positive(s, q, ep); sent[i % 5]++; Retire(q, ep);
    }
    for (unsigned count : sent) EXPECT_EQ(count, 2U);
    EXPECT_EQ(s.s.stats.attempt_count, 10U);
}
TEST(UpstreamServiceState, StaleAttemptGenerationCannotWriteOrCommitNewTurn) {
    ServiceState s; ServiceQuery q(s); auto *ep = Pick(s, q); ASSERT_NE(ep, nullptr);
    unsigned gen = Generation(q, ep);
    EXPECT_EQ(_dns_service_write_begin(&q.q, ep, gen + 1), DNS_ADMIT_DONE);
    _dns_service_write_result(&q.q, ep, gen + 1, 1, 0);
    EXPECT_EQ(s.s.turn_state, unsigned(DNS_SERVICE_TURN_RESERVED)); EXPECT_EQ(s.s.cursor, 0U);
    Positive(s, q, ep); EXPECT_EQ(s.s.stats.attempt_count, 1U); Retire(q, ep);
}
TEST(UpstreamServiceState, ExpiredAndRevokedMembersStopNewAdmissionImmediately) {
    ServiceState s(3);
    s.endpoints[0].service_valid_until = get_tick_count();
    s.endpoints[1].service_revoked = 1;
    ServiceQuery q(s); auto *ep = Pick(s, q); ASSERT_EQ(ep, &s.endpoints[2]);
    Positive(s, q, ep); Retire(q, ep);
}


TEST(UpstreamServiceState, NoProgressWaitsWithoutEventfdSelfFeedOrDeadlineExtension) {
    int previous = client.fd_wakeup;
    int wake = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC); ASSERT_GE(wake, 0);
    client.fd_wakeup = wake;
    {
        ServiceState service; ServiceQuery query(service);
        query.q.budget = dns_query_budget_new(2, 2000);
        auto remaining = dns_query_budget_remaining_ms(query.q.budget);
        auto reject = [](dns_server_info *, void *) { return 0; };
        EXPECT_EQ(_dns_service_select(&service.s, &query.q, reject, nullptr), nullptr);
        uint64_t count = 0; ASSERT_EQ(read(wake, &count, sizeof(count)), ssize_t(sizeof(count)));
        EXPECT_EQ(count, 1U);
        EXPECT_GT(service.s.next_eligible, get_tick_count());
        // Do not use ServiceState::Flush: this exercises the real scheduler wake path.
        _dns_services_flush_pending();
        EXPECT_EQ(service.s.turn_state, unsigned(DNS_SERVICE_TURN_IDLE));
        for (unsigned i = 0; i < 4; i++) _dns_services_flush_pending();
        errno = 0; EXPECT_EQ(read(wake, &count, sizeof(count)), -1); EXPECT_EQ(errno, EAGAIN);
        EXPECT_LE(dns_query_budget_remaining_ms(query.q.budget), remaining);
        // A real socket readiness notification can break the finite wait early.
        _dns_service_endpoint_ready(&service.endpoints[0]);
        EXPECT_EQ(service.s.next_eligible, 0UL);
        ASSERT_EQ(read(wake, &count, sizeof(count)), ssize_t(sizeof(count)));
        EXPECT_EQ(count, 1U);
        query.q.terminal = 1; _dns_service_query_terminal(&query.q);
        _dns_services_flush_pending();
        EXPECT_EQ(service.s.stats.skip_count, 1U);
    }
    client.fd_wakeup = previous; close(wake);
}

TEST(UpstreamServiceState, ExhaustedBudgetSettlesWithoutRetryWakeLoop) {
    ServiceState service; ServiceQuery query(service);
    query.q.budget = dns_query_budget_new(1, 2000);
    ASSERT_EQ(_dns_query_budget_take(query.q.budget), 0);
    EXPECT_EQ(Pick(service, query), nullptr);
    EXPECT_GT(dns_query_budget_remaining_ms(query.q.budget), 0U);
    _dns_services_flush_pending();
    EXPECT_EQ(service.s.stats.skip_count, 1U);
    EXPECT_EQ(service.s.stats.in_flight, 0U);
    EXPECT_EQ(service.s.wake_pending, 0U);
    EXPECT_EQ(Pick(service, query), nullptr);
    EXPECT_EQ(service.s.wake_pending, 0U);
}


TEST(UpstreamServiceState, DatagramBackpressureAbortsOwnerButWaitsWithoutSelfFeed) {
    int sockets[2]; ASSERT_EQ(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, sockets), 0);
    int size = 4096; ASSERT_EQ(setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)), 0);
    unsigned char fill[512]{}; unsigned filled = 0;
    while (filled < 64 && send(sockets[0], fill, sizeof(fill), 0) == sizeof(fill)) filled++;
    ASSERT_LT(filled, 64U); ASSERT_EQ(errno, EAGAIN);
    int previous = client.fd_wakeup; int wake = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    ASSERT_GE(wake, 0); client.fd_wakeup = wake;
    pthread_mutex_init(&client.server_list_lock, nullptr);
    {
        ServiceState service(1); ServiceQuery query(service);
        auto &ep = service.endpoints[0]; ep.type = DNS_SERVER_UDP; ep.fd = sockets[0];
        dns_server_group group{}; INIT_LIST_HEAD(&group.head); group.service_members = 1;
        dns_server_group_member member{}; member.service = &service.s; list_add_tail(&member.list, &group.head);
        query.q.server_group = &group; query.q.budget = dns_query_budget_new(3, 2000);
        auto remaining = dns_query_budget_remaining_ms(query.q.budget);
        unsigned char packet[12]{};
        EXPECT_EQ(_dns_client_send_packet(&query.q, packet, sizeof(packet)), 0);
        EXPECT_GT(service.s.next_eligible, get_tick_count());
        uint64_t count; ASSERT_EQ(read(wake, &count, sizeof(count)), ssize_t(sizeof(count)));
        _dns_services_flush_pending();
        EXPECT_EQ(service.s.turn_state, unsigned(DNS_SERVICE_TURN_IDLE));
        EXPECT_EQ(ep.active_attempts, 0U); EXPECT_EQ(service.s.stats.attempt_count, 0U);
        for (unsigned i = 0; i < 4; i++) _dns_services_flush_pending();
        errno = 0; EXPECT_EQ(read(wake, &count, sizeof(count)), -1); EXPECT_EQ(errno, EAGAIN);
        EXPECT_LE(dns_query_budget_remaining_ms(query.q.budget), remaining);
        query.q.terminal = 1; _dns_service_query_terminal(&query.q); _dns_services_flush_pending();
        EXPECT_EQ(service.s.stats.skip_count, 1U); ep.fd = -1;
    }
    pthread_mutex_destroy(&client.server_list_lock);
    client.fd_wakeup = previous; close(wake); close(sockets[0]); close(sockets[1]);
}

TEST(UpstreamServiceState, EpollBatchPinsLaterEndpointAcrossEarlierCallbackRetirement) {
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC); ASSERT_GE(epoll_fd, 0);
    int old_epoll = client.epoll_fd, old_wakeup = client.fd_wakeup;
    client.epoll_fd = epoll_fd; client.fd_wakeup = -1;
    pthread_mutex_init(&client.server_list_lock, nullptr);
    dns_server_info *endpoints[2]{};
    for (unsigned i = 0; i < 2; i++) {
        endpoints[i] = static_cast<dns_server_info *>(calloc(1, sizeof(dns_server_info)));
        ASSERT_NE(endpoints[i], nullptr);
        auto *ep = endpoints[i]; atomic_set(&ep->refcnt, 1);
        INIT_LIST_HEAD(&ep->list); INIT_LIST_HEAD(&ep->check_list); INIT_LIST_HEAD(&ep->conn_stream_list);
        pthread_mutexattr_t attr; pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&ep->lock, &attr); pthread_mutexattr_destroy(&attr);
        ep->fd = eventfd(1, EFD_NONBLOCK | EFD_CLOEXEC); ASSERT_GE(ep->fd, 0);
        ep->type = DNS_SERVER_UDP; ep->service_member_id = i + 1;
        epoll_event event{}; event.events = EPOLLIN; event.data.ptr = ep;
        ASSERT_EQ(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ep->fd, &event), 0);
    }
    epoll_event events[2]{}; ASSERT_EQ(epoll_wait(epoll_fd, events, 2, 50), 2);
    _dns_client_event_batch_pin(events, 2);
    /* Model an earlier bootstrap/TTL callback dropping the registry's final
     * ownership of both endpoints, including the later event in this batch. */
    for (auto *ep : endpoints) dns_client_server_info_release(ep);
    for (auto &event : events) {
        auto *ep = static_cast<dns_server_info *>(event.data.ptr);
        EXPECT_EQ(atomic_read(&ep->refcnt), 1);
        EXPECT_TRUE(ep->service_member_id == 1 || ep->service_member_id == 2);
    }
    _dns_client_event_batch_unpin(events, 2); // final references free both objects
    EXPECT_EQ(epoll_wait(epoll_fd, events, 2, 0), 0);
    close(epoll_fd); pthread_mutex_destroy(&client.server_list_lock);
    client.epoll_fd = old_epoll; client.fd_wakeup = old_wakeup;
}

namespace { std::atomic<int> observation_registration_barrier{0}; }
TEST(UpstreamServiceState, CancelBetweenObservationPublicationAndRegistrationIsDeferred) {
    ServiceState s; ServiceQuery q(s);
    observation_registration_barrier = 0;
    _dns_service_observe_published_test_hook = [](dns_service_observation *) {
        observation_registration_barrier = 1;
        while (observation_registration_barrier.load() != 2) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    };
    std::thread publisher([&] { EXPECT_EQ(Pick(s, q), nullptr); });
    auto until = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!observation_registration_barrier.load() && std::chrono::steady_clock::now() < until)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_EQ(observation_registration_barrier.load(), 1);
    pthread_mutex_lock(&q.q.lock); q.q.terminal = 1; pthread_mutex_unlock(&q.q.lock);
    _dns_service_query_terminal(&q.q); s.Flush();
    EXPECT_EQ(s.s.stats.query_count, 0U); EXPECT_EQ(s.s.stats.in_flight, 0U);
    EXPECT_EQ(s.s.stats.skip_count, 0U); EXPECT_TRUE(list_empty(&s.s.waiters));
    EXPECT_EQ(Pick(s, q), nullptr); EXPECT_EQ(atomic_read(&q.q.refcnt), 2);
    observation_registration_barrier = 2; publisher.join();
    _dns_service_observe_published_test_hook = nullptr; s.Flush();
    EXPECT_EQ(s.s.stats.query_count, 1U); EXPECT_EQ(s.s.stats.in_flight, 0U);
    EXPECT_EQ(s.s.stats.skip_count, 1U); EXPECT_TRUE(list_empty(&s.s.waiters));
    EXPECT_EQ(s.s.hints, nullptr); EXPECT_EQ(atomic_read(&q.q.refcnt), 1);
}

TEST(UpstreamServiceState, SnapshotFreshnessHasNoInfiniteIntegerSentinel) {
    ServiceState state;
    dns_upstream_service_snapshot_v1 snapshot{};
    state.s.config.ip_count = 2;
    state.s.freshness_until = ULONG_MAX;
    _dns_service_snapshot_test(&state.s, &snapshot);
    EXPECT_EQ(snapshot.freshness_kind, DNS_FRESHNESS_NON_EXPIRING);
    EXPECT_EQ(snapshot.freshness_remaining_ms, 0U);
    // A static configuration is non-expiring even before first reconciliation.
    state.s.freshness_until = 0;
    _dns_service_snapshot_test(&state.s, &snapshot);
    EXPECT_EQ(snapshot.freshness_kind, DNS_FRESHNESS_NON_EXPIRING);
    state.s.config.ip_count = 0;
    _dns_service_snapshot_test(&state.s, &snapshot);
    EXPECT_EQ(snapshot.freshness_kind, DNS_FRESHNESS_UNKNOWN);
    EXPECT_EQ(snapshot.freshness_remaining_ms, 0U);
    // Discovery's empty/negative snapshot carries ULONG_MAX internally; it is
    // not a positive-membership TTL and must not become an infinite JSON TTL.
    state.s.freshness_until = ULONG_MAX;
    _dns_service_snapshot_test(&state.s, &snapshot);
    EXPECT_EQ(snapshot.freshness_kind, DNS_FRESHNESS_UNKNOWN);
    EXPECT_EQ(snapshot.freshness_remaining_ms, 0U);
    state.s.freshness_known = 1;
    state.s.freshness_until = get_tick_count() + 5000;
    _dns_service_snapshot_test(&state.s, &snapshot);
    EXPECT_EQ(snapshot.freshness_kind, DNS_FRESHNESS_FINITE);
    EXPECT_GT(snapshot.freshness_remaining_ms, 0U);
    EXPECT_LE(snapshot.freshness_remaining_ms, 5000U);
    state.s.freshness_until = get_tick_count() - 1;
    _dns_service_snapshot_test(&state.s, &snapshot);
    EXPECT_EQ(snapshot.freshness_kind, DNS_FRESHNESS_FINITE);
    EXPECT_EQ(snapshot.freshness_remaining_ms, 0U);
}

TEST(UpstreamServiceState, FixedCooldownDefaultsAndDoesNotGrowOrFollowRetryAfter) {
    for (unsigned configured : {0U, 1U, 1000U, 10000U}) {
        ServiceState s(2, 0, "", 0, 0, configured);
        unsigned expected = configured ? configured : 1000;
        for (const char *header : {"0", "3600", "invalid", "18446744073709551615000"}) {
            unsigned long before = get_tick_count();
            _dns_policy_http_error(&s.endpoints[0], 429, header);
            unsigned long after = get_tick_count();
            auto remaining = _dns_policy_service_cooldown(&s.s, before);
            EXPECT_GE(remaining, expected);
            EXPECT_LE(remaining, expected + after - before);
            unsigned reason = DNS_WAIT_NONE;
            EXPECT_GT(_dns_policy_service_wait_reason(&s.s, before, &reason), 0U);
            EXPECT_EQ(reason, DNS_WAIT_COOLDOWN);
        }
        EXPECT_EQ(s.s.diagnostics.events[DNS_EVENT_HTTP_429], 4U);
    }
}
TEST(UpstreamServiceState, DiagnosticDimensionsDistinguishOtherWinnerCoolingAndRejectedReply) {
    ServiceState s;
    { ServiceQuery canceled(s); auto *ep = Pick(s, canceled); ASSERT_NE(ep, nullptr);
      Positive(s, canceled, ep); canceled.q.has_result = 1; Retire(canceled, ep); }
    EXPECT_EQ(s.s.stats.failure_count, 1U);
    EXPECT_EQ(s.s.diagnostics.failure_end[DNS_END_OTHER_RESULT], 1U);
    EXPECT_EQ(s.s.diagnostics.failure_last_event[0], 1U);
    _dns_policy_http_error(&s.endpoints[0], 429, "3600");
    { ServiceQuery skipped(s); EXPECT_EQ(Pick(s, skipped), nullptr); skipped.q.has_result = 1; }
    EXPECT_EQ(s.s.stats.skip_count, 1U);
    EXPECT_EQ(s.s.diagnostics.skip_end[DNS_END_OTHER_RESULT], 1U);
    EXPECT_EQ(s.s.diagnostics.skip_wait[DNS_WAIT_COOLDOWN], 1U);
    EXPECT_EQ(s.s.diagnostics.events[DNS_EVENT_HTTP_429], 1U);
}
TEST(UpstreamServiceState, DiagnosticsRecordLastObservedErrorSeparatelyFromTerminalContext) {
    ServiceState s;
    { ServiceQuery rejected(s); auto *ep = Pick(s, rejected); ASSERT_NE(ep, nullptr);
      Positive(s, rejected, ep);
      _dns_service_diagnostic_event(&rejected.q, ep, DNS_EVENT_DNS_REJECTED);
      _dns_service_query_result(&rejected.q, ep, 0);
      _dns_attempt_replied(&rejected.q, ep); Retire(rejected, ep);
      rejected.q.created_tick = get_tick_count() - DNS_QUERY_RETRY * DNS_QUERY_TIMEOUT;
    }
    EXPECT_EQ(s.s.stats.failure_count, 1U);
    EXPECT_EQ(s.s.diagnostics.failure_end[DNS_END_DEADLINE], 1U);
    EXPECT_EQ(s.s.diagnostics.failure_last_event[DNS_EVENT_DNS_REJECTED + 1], 1U);
    EXPECT_EQ(s.s.diagnostics.events[DNS_EVENT_DNS_REJECTED], 1U);
}

TEST(UpstreamServiceState, DiagnosticResultProvenanceDoesNotCallOwnRejectedResultAnotherWinner) {
    ServiceState s;
    { ServiceQuery rejected(s); auto *ep = Pick(s, rejected); ASSERT_NE(ep, nullptr);
      Positive(s, rejected, ep); _dns_service_diagnostic_event(&rejected.q, ep, DNS_EVENT_DNS_RCODE);
      _dns_service_query_result(&rejected.q, ep, 0);
      rejected.q.has_result = 1; rejected.q.result_service = &s.s;
      _dns_attempt_replied(&rejected.q, ep); Retire(rejected, ep);
    }
    EXPECT_EQ(s.s.stats.failure_count, 1U);
    EXPECT_EQ(s.s.diagnostics.failure_end[DNS_END_UNACCEPTED_RESULT], 1U);
    EXPECT_EQ(s.s.diagnostics.failure_end[DNS_END_OTHER_RESULT], 0U);
}
