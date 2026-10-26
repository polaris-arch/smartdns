#include "gtest/gtest.h"
#include "server.h"
#include "client.h"
extern "C" {
#include "dns_server/prefetch.h"
#include "dns_server/request.h"
#include "smartdns/dns_client.h"
#include "smartdns/util.h"
}
#include <cstring>
#include <string>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <vector>

namespace {
struct PausedRefresh {
    PausedRefresh() { __atomic_store_n(&_dns_prefetch_test_paused, 1, __ATOMIC_RELEASE); }
    ~PausedRefresh() { __atomic_store_n(&_dns_prefetch_test_paused, 0, __ATOMIC_RELEASE); }
};
dns_refresh_queue_snapshot_v1 Snapshot() {
    dns_refresh_queue_snapshot_v1 out{};
    EXPECT_EQ(dns_server_get_refresh_queue_v1(&out), 0);
    EXPECT_EQ(out.version, 1U); EXPECT_EQ(out.struct_size, sizeof(out));
    return out;
}
int Enqueue(const std::string &name, dns_type_t type = DNS_T_A,
    dns_server_query_option *options = nullptr, int flags = PREFETCH_FLAGS_NO_DUALSTACK) {
    return _dns_server_prefetch_cached(const_cast<char *>(name.c_str()), type, options, flags, 0);
}
constexpr const char *config = R"(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode none
prefetch-domain no
serve-expired no
dualstack-ip-selection no
)";
}

TEST(RefreshQueue, BurstCoalescesBeforeFullRequestAllocationAndIsBounded) {
    PausedRefresh paused;
    smartdns::Server instance(smartdns::Server::CREATE_MODE_THREAD); ASSERT_TRUE(instance.Start(config));
    const auto before = Snapshot(); ASSERT_EQ(before.queued, 0U); ASSERT_EQ(before.active, 0U);
    ASSERT_EQ(Enqueue("Queue.test"), 0);
    for (unsigned i = 0; i < 518; i++)
        ASSERT_EQ(Enqueue("queue.TEST", DNS_T_A, nullptr, PREFETCH_FLAGS_NO_DUALSTACK | PREFETCH_FLAGS_CACHE_HIT), 0);
    auto one = Snapshot(); EXPECT_EQ(one.queued, 1U); EXPECT_EQ(one.merged - before.merged, 518U);
    for (unsigned i = 1; i < 512; i++) ASSERT_EQ(Enqueue("queue-" + std::to_string(i) + ".test"), 0);
    EXPECT_EQ(Enqueue("overflow.test"), -1);
    EXPECT_EQ(Enqueue("queue.TEST"), 0); // duplicates still merge when the room is full
    auto full = Snapshot(); EXPECT_EQ(full.queued, 512U); EXPECT_EQ(full.active, 0U);
    EXPECT_EQ(full.enqueued - before.enqueued, 512U); EXPECT_EQ(full.rejected - before.rejected, 1U);
    EXPECT_EQ(full.dispatched, before.dispatched);
    EXPECT_EQ(atomic_read(&::server.request_num), 0);
    EXPECT_LT(full.metadata_bytes, 1024U * 1024U);
    // The same production expiry loop, with a deterministic clock and no DNS traffic.
    for (unsigned i = 0; i < 16; i++) _dns_server_prefetch_test_run(get_tick_count() + 31000);
    auto after = Snapshot(); EXPECT_EQ(after.queued, 0U); EXPECT_EQ(after.active, 0U);
    EXPECT_EQ(after.dropped - before.dropped, 512U);
    EXPECT_EQ(after.enqueued, after.queued + after.active + after.completed + after.dropped + after.skipped_fresh);
}

TEST(RefreshQueue, DedupePreservesFamilyDoAndEcsView) {
    PausedRefresh paused;
    smartdns::Server instance(smartdns::Server::CREATE_MODE_THREAD); ASSERT_TRUE(instance.Start(config));
    const auto before = Snapshot(); ASSERT_EQ(before.queued, 0U);
    dns_server_query_option options{};
    options.ecs_enable_flag = DNS_QUEY_OPTION_ECS_DNS;
    options.ecs_dns.family = 1; options.ecs_dns.source_prefix = 24;
    options.ecs_dns.addr[0] = 192; options.ecs_dns.addr[1] = 0; options.ecs_dns.addr[2] = 2; options.ecs_dns.addr[3] = 1;
    ASSERT_EQ(Enqueue("view.test", DNS_T_A, &options), 0);
    options.ecs_dns.addr[3] = 240;
    ASSERT_EQ(Enqueue("view.test", DNS_T_A, &options), 0); // canonical /24 is the same view
    options.ecs_dns.addr[2] = 3;
    ASSERT_EQ(Enqueue("view.test", DNS_T_A, &options), 0);
    ASSERT_EQ(Enqueue("view.test", DNS_T_AAAA, &options), 0);
    options.ecs_enable_flag |= DNS_QUEY_OPTION_EDNS0_DO;
    ASSERT_EQ(Enqueue("view.test", DNS_T_AAAA, &options), 0);
    auto queued = Snapshot(); EXPECT_EQ(queued.queued, 4U); EXPECT_EQ(queued.merged - before.merged, 1U);
    _dns_server_prefetch_stop();
    EXPECT_EQ(Snapshot().queued, 0U); EXPECT_EQ(Enqueue("after-stop.test"), -1);
}

TEST(RefreshQueue, BackgroundSourceSurvivesInternalAddressChildFlags) {
    dns_request request{}; dns_query_options options{};
    request.prefetch_origin_flags = 2 | 4; // cache-hit + timer merged before dispatch
    request.prefetch_queue_wait_ms = 750;
    request.prefetch_flags = PREFETCH_FLAGS_NO_DUALSTACK | PREFETCH_FLAGS_NOPREFETCH;
    ASSERT_EQ(_dns_server_setup_query_option(&request, &options), 0);
    EXPECT_TRUE(options.enable_flag & DNS_QUEY_OPTION_BACKGROUND);
    EXPECT_TRUE(options.enable_flag & DNS_QUEY_OPTION_EXPIRED_REFRESH);
    EXPECT_EQ(options.background_origin_flags, 6U); EXPECT_EQ(options.background_queue_wait_ms, 750U);
    EXPECT_TRUE(dns_server_request_is_prefetch(&request));
    request.prefetch_origin_flags = 0; request.prefetch_queue_wait_ms = 0;
    ASSERT_EQ(_dns_server_setup_query_option(&request, &options), 0);
    EXPECT_FALSE(options.enable_flag & DNS_QUEY_OPTION_BACKGROUND);
    EXPECT_FALSE(dns_server_request_is_prefetch(&request));
}
TEST(RefreshQueue, ReplacementMakesQueuedWorkRedundantButLruAccessDoesNot) {
    PausedRefresh paused;
    std::atomic<unsigned> sends{0};
    smartdns::MockServer upstream;
    upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *request) {
        if (request->qtype != DNS_T_A) return smartdns::SERVER_REQUEST_SOA;
        sends++; smartdns::MockServer::AddIP(request, request->domain.c_str(), "192.0.2.21", 600);
        return smartdns::SERVER_REQUEST_OK;
    });
    smartdns::Server instance(smartdns::Server::CREATE_MODE_THREAD); ASSERT_TRUE(instance.Start(config));
    smartdns::Client client; ASSERT_TRUE(client.Query("fresh-room.test", 60053));
    dns_cache_key key{}; key.domain = "fresh-room.test"; key.dns_group_name = ""; key.qtype = DNS_T_A;
    auto *entry = dns_cache_lookup(&key); ASSERT_NE(entry, nullptr);
    uint64_t generation = dns_cache_get_generation(entry); ASSERT_GT(generation, 0U);
    dns_cache_update(entry); EXPECT_EQ(dns_cache_get_generation(entry), generation);
    const auto before = Snapshot();
    ASSERT_EQ(_dns_server_prefetch_cached(const_cast<char *>(key.domain), DNS_T_A, nullptr,
        PREFETCH_FLAGS_NO_DUALSTACK, generation), 0);
    auto *data = dns_cache_get_data(entry); ASSERT_NE(data, nullptr);
    ASSERT_EQ(dns_cache_replace(&key, DNS_RC_NOERROR, 600, 0, 600, 1, data), 0);
    EXPECT_NE(dns_cache_get_generation(entry), generation); dns_cache_release(entry);
    _dns_server_prefetch_test_run(get_tick_count());
    auto after = Snapshot(); EXPECT_EQ(after.queued, 0U); EXPECT_EQ(after.active, 0U);
    EXPECT_EQ(after.skipped_fresh - before.skipped_fresh, 1U);
    EXPECT_EQ(after.dispatched, before.dispatched); EXPECT_EQ(sends.load(), 1U);
}

TEST(RefreshQueue, QuotaDeadlineDispatchesWhileTheServerWouldOtherwiseBeIdle) {
    PausedRefresh paused;
    std::mutex lock; std::condition_variable cv;
    std::vector<unsigned long> received;
    std::atomic<unsigned> unexpected{0};
    smartdns::MockServer upstream;
    upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *request) {
        if (request->qtype != DNS_T_A) { unexpected++; return smartdns::SERVER_REQUEST_SOA; }
        { std::lock_guard<std::mutex> guard(lock); received.push_back(get_tick_count()); }
        cv.notify_all();
        smartdns::MockServer::AddIP(request, request->domain.c_str(), "192.0.2.20", 600);
        return smartdns::SERVER_REQUEST_OK;
    });
    smartdns::Server instance(smartdns::Server::CREATE_MODE_THREAD);
    ASSERT_TRUE(instance.Start(R"(bind [::]:60053
server 127.0.0.1:61053 -upstream-service -max-query-rate 20 -query-burst 1
speed-check-mode none
prefetch-domain no
serve-expired no
)" ));
    for (unsigned i = 0; i < 8; i++) ASSERT_EQ(Enqueue("paced-" + std::to_string(i) + ".test"), 0);
    // Process the first readiness check with the deterministic driver, then
    // let production epoll deadlines and transport notifications do the rest.
    _dns_server_prefetch_test_run(get_tick_count());
    __atomic_store_n(&_dns_prefetch_test_paused, 0, __ATOMIC_RELEASE);
    dns_server_refresh_notify();
    std::unique_lock<std::mutex> guard(lock);
    ASSERT_TRUE(cv.wait_for(guard, std::chrono::milliseconds(2500), [&] { return received.size() >= 8; }));
    ASSERT_EQ(received.size(), 8U);
    EXPECT_GE(received.back() - received.front(), 300U); // paced, not an eight-packet startup burst
    EXPECT_EQ(unexpected.load(), 0U);
}
