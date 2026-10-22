/* Bounded real UDP/bootstrap/runtime fixtures. No public network or benchmarks. */
#include "server.h"
#include "smartdns/dns.h"
#include "smartdns/upstream_service.h"
#include "gtest/gtest.h"
#include <arpa/inet.h>
#include <algorithm>
#include <netdb.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace {
constexpr const char *authority = "resolver.discovery.example";

bool query_udp(const std::string &name, unsigned port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    timeval timeout{2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    sockaddr_in target{}; target.sin_family = AF_INET; target.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &target.sin_addr);
    alignas(dns_packet) unsigned char storage[DNS_PACKSIZE];
    unsigned char wire[DNS_IN_PACKSIZE];
    auto *packet = reinterpret_cast<dns_packet *>(storage);
    dns_head head{}; head.id = 4321; head.rd = 1;
    dns_packet_init(packet, sizeof(storage), &head);
    dns_add_domain(packet, name.c_str(), DNS_T_A, DNS_C_IN);
    int length = dns_encode(wire, sizeof(wire), packet);
    bool good = length > 0 && sendto(fd, wire, length, 0, reinterpret_cast<sockaddr *>(&target), sizeof(target)) == length;
    if (good) {
        length = recv(fd, wire, sizeof(wire), 0);
        good = length > 0 && !dns_decode(packet, sizeof(storage), wire, length) &&
            packet->head.id == 4321 && packet->head.rcode == DNS_RC_NOERROR && packet->head.ancount == 1;
    }
    close(fd);
    return good;
}

smartdns::ServerRequestResult bootstrap_reply(smartdns::ServerRequestContext *r,
                                             const std::vector<const char *> &addresses, unsigned ttl)
{
    // MockServer does not populate question on SERVER_REQUEST_OK. Bootstrap's
    // validated raw parser must see the actual matching question and authority SOA.
    dns_add_domain(r->response_packet, r->domain.c_str(), r->qtype, r->qclass);
    if (r->domain != authority) return smartdns::SERVER_REQUEST_ERROR;
    if (r->qtype == DNS_T_A) {
        for (auto ip : addresses) smartdns::MockServer::AddIP(r, authority, ip, ttl);
    } else if (r->qtype == DNS_T_AAAA) {
        dns_soa soa{}; strcpy(soa.mname, "ns.example"); strcpy(soa.rname, "hostmaster.example");
        soa.minimum = ttl;
        dns_add_SOA(r->response_packet, DNS_RRS_NS, "example", ttl, &soa);
    } else return smartdns::SERVER_REQUEST_ERROR;
    return smartdns::SERVER_REQUEST_OK;
}

bool read_pool(dns_upstream_service_snapshot_v1 &result)
{
    int count = dns_client_get_service_snapshot_v1(nullptr, 0);
    if (count < 1 || count > 128) return false;
    std::vector<dns_upstream_service_snapshot_v1> snapshots(static_cast<size_t>(count));
    if (dns_client_get_service_snapshot_v1(snapshots.data(), snapshots.size()) != count) return false;
    unsigned pools = 0;
    for (const auto &snapshot : snapshots) if (snapshot.pool_enabled) {
        if (strcmp(snapshot.authority, authority)) return false;
        result = snapshot; pools++;
    }
    return pools == 1;
}

template<typename Predicate>
bool await_pool(dns_upstream_service_snapshot_v1 &result, Predicate predicate)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    do {
        if (read_pool(result) && predicate(result)) return true;
        poll(nullptr, 0, 5);
    } while (std::chrono::steady_clock::now() < deadline);
    return false;
}

std::string config(unsigned listen, unsigned bootstrap, unsigned upstream)
{
    return "bind 127.0.0.1:" + std::to_string(listen) + "\n" +
        "server udp://127.0.0.1:" + std::to_string(bootstrap) + " -bootstrap-dns -exclude-default-group\n" +
        "server udp://" + authority + ":" + std::to_string(upstream) + " -upstream-ip-pool\n" +
        "cache-size 0\ncache-persist no\nprefetch-domain no\nserve-expired no\n"
        "dualstack-ip-selection no\nspeed-check-mode none\nresponse-mode fastest-response\n";
}

bool packet_has_ecs(dns_packet *packet)
{
    int count = 0; auto *rr = dns_get_rrs_start(packet, DNS_RRS_OPT, &count);
    for (int i = 0; i < count && rr; i++, rr = dns_get_rrs_next(packet, rr)) {
        dns_opt_ecs ecs{}; if (!dns_get_OPT_ECS(rr, &ecs)) return true;
    }
    return false;
}

void bootstrap_ecs_isolation_case()
{
    std::atomic<unsigned> leaked{0}, seen{0}, ordinary_ecs{0}, ended{0};
    smartdns::MockServer bootstrap, upstream;
    ASSERT_TRUE(bootstrap.Start("udp://127.0.0.1:62675", [&](smartdns::ServerRequestContext *r) {
        seen++; if (packet_has_ecs(r->packet)) leaked++;
        dns_add_domain(r->response_packet, r->domain.c_str(), r->qtype, r->qclass);
        if (r->domain == authority) {
            dns_add_CNAME(r->response_packet, DNS_RRS_AN, authority, 30, "bootstrap-alias.example");
        } else if (r->domain == "bootstrap-alias.example" && r->qtype == DNS_T_A) {
            smartdns::MockServer::AddIP(r, r->domain.c_str(), "127.0.0.2", 30);
        } else if (r->domain == "bootstrap-alias.example" && r->qtype == DNS_T_AAAA) {
            dns_soa soa{}; strcpy(soa.mname, "ns.example"); strcpy(soa.rname, "hostmaster.example"); soa.minimum = 30;
            dns_add_SOA(r->response_packet, DNS_RRS_NS, "example", 30, &soa);
        } else return smartdns::SERVER_REQUEST_ERROR;
        return smartdns::SERVER_REQUEST_OK;
    }));
    ASSERT_TRUE(upstream.Start("udp://127.0.0.2:62875", [&](smartdns::ServerRequestContext *r) {
        if (packet_has_ecs(r->packet)) ordinary_ecs++;
        dns_add_domain(r->response_packet, r->domain.c_str(), r->qtype, r->qclass);
        smartdns::MockServer::AddIP(r, r->domain.c_str(), "192.0.2.75", 60);
        return smartdns::SERVER_REQUEST_OK;
    }));
    smartdns::Server resolver(smartdns::Server::CREATE_MODE_THREAD);
    auto conf = config(62775, 62675, 62875);
    auto marker = conf.find(" -bootstrap-dns"); ASSERT_NE(marker, std::string::npos);
    conf.insert(marker, " -subnet 198.51.100.0/24 -subnet-all-query-types");
    conf += "edns-client-subnet 203.0.113.0/24\n";
    ASSERT_TRUE(resolver.Start(conf));
    dns_upstream_service_snapshot_v1 snapshot{};
    ASSERT_TRUE(await_pool(snapshot, [](const auto &v) { return v.endpoint_count == 1; }));
    ASSERT_TRUE(query_udp("ordinary-ecs.example", 62775));
    EXPECT_GT(ordinary_ecs.load(), 0U);
    dns_query_options options{};
    options.enable_flag = DNS_QUEY_OPTION_BOOTSTRAP_ONLY | DNS_QUEY_OPTION_ECS_DNS;
    options.ecs_dns.family = DNS_OPT_ECS_FAMILY_IPV4; options.ecs_dns.source_prefix = 24;
    options.ecs_dns.addr[0] = 192; options.ecs_dns.addr[1] = 0; options.ecs_dns.addr[2] = 2;
    auto callback = [](const char *, dns_result_type type, dns_server_info *, dns_packet *, unsigned char *, int, void *user) {
        if (type == DNS_QUERY_END) static_cast<std::atomic<unsigned> *>(user)->fetch_add(1);
        return DNS_CLIENT_ACTION_OK;
    };
    ASSERT_EQ(dns_client_query(authority, DNS_T_A, callback, &ended, "bootstrap-dns", &options), 0);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!ended && std::chrono::steady_clock::now() < deadline) poll(nullptr, 0, 5);
    EXPECT_EQ(ended.load(), 1U);
    options.enable_flag = DNS_QUEY_OPTION_BOOTSTRAP_ONLY | DNS_QUEY_OPTION_ECS_IP;
    strcpy(options.ecs_ip.ip, "192.0.2.0"); options.ecs_ip.subnet = 24;
    ASSERT_EQ(dns_client_query(authority, DNS_T_AAAA, callback, &ended, "bootstrap-dns", &options), 0);
    deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (ended < 2 && std::chrono::steady_clock::now() < deadline) poll(nullptr, 0, 5);
    EXPECT_EQ(ended.load(), 2U); EXPECT_GE(seen.load(), 6U); EXPECT_EQ(leaked.load(), 0U);
}

void pending_bootstrap_rejected_case()
{
    std::atomic<unsigned> wire{0}; smartdns::MockServer safe;
    ASSERT_TRUE(safe.Start("udp://127.0.0.1:62676", [&](smartdns::ServerRequestContext *) {
        wire++; return smartdns::SERVER_REQUEST_ERROR;
    }));
    smartdns::Server resolver(smartdns::Server::CREATE_MODE_THREAD);
    auto conf = config(62776, 62676, 62876);
    conf += "server udp://alias.example:62776 -bootstrap-dns -exclude-default-group\n";
    EXPECT_FALSE(resolver.Start(conf));
    EXPECT_EQ(wire.load(), 0U); // reject before resolving the alias or starting discovery
}

void automatic_pool_case()
{
    std::atomic<unsigned> sends[2]{};
    std::atomic<unsigned> bootstrap_queries[2]{};
    std::atomic<bool> withdraw_first{false};
    smartdns::MockServer bootstrap, first, second;
    ASSERT_TRUE(bootstrap.Start("udp://127.0.0.1:62673", [&](smartdns::ServerRequestContext *r) {
        if (r->qtype == DNS_T_A) bootstrap_queries[0]++;
        if (r->qtype == DNS_T_AAAA) bootstrap_queries[1]++;
        return bootstrap_reply(r, withdraw_first.load() ? std::vector<const char *>{"127.0.0.2"} :
            std::vector<const char *>{"127.0.0.1", "127.0.0.2"}, 2);
    }));
    auto reply = [&](unsigned index, smartdns::ServerRequestContext *r) {
        dns_add_domain(r->response_packet, r->domain.c_str(), r->qtype, r->qclass);
        if (r->qtype != DNS_T_A) return smartdns::SERVER_REQUEST_ERROR;
        sends[index]++;
        smartdns::MockServer::AddIP(r, r->domain.c_str(), "192.0.2.73", 60);
        return smartdns::SERVER_REQUEST_OK;
    };
    ASSERT_TRUE(first.Start("udp://127.0.0.1:62873", [&](smartdns::ServerRequestContext *r) { return reply(0, r); }));
    ASSERT_TRUE(second.Start("udp://127.0.0.2:62873", [&](smartdns::ServerRequestContext *r) { return reply(1, r); }));
    // Share actual core snapshots with this test; outer re-exec isolates globals.
    smartdns::Server resolver(smartdns::Server::CREATE_MODE_THREAD);
    ASSERT_TRUE(resolver.Start(config(62773, 62673, 62873)));
    dns_upstream_service_snapshot_v1 before{};
    ASSERT_TRUE(await_pool(before, [](const auto &s) { return s.endpoint_count == 2; }));
    EXPECT_EQ(before.backend_cap, 4U); EXPECT_EQ(before.rejected_count, 0U);
    EXPECT_GT(bootstrap_queries[0].load(), 0U); EXPECT_GT(bootstrap_queries[1].load(), 0U);
    for (unsigned i = 0; i < 4; i++) ASSERT_TRUE(query_udp("auto-pool-" + std::to_string(i) + ".example", 62773));
    EXPECT_EQ(sends[0].load(), 2U); EXPECT_EQ(sends[1].load(), 2U);
    ASSERT_TRUE(await_pool(before, [](const auto &s) { return s.success_count == 4 && !s.in_flight; }));
    EXPECT_EQ(before.query_count, 4U); EXPECT_EQ(before.attempt_count, 4U);
    EXPECT_EQ(before.failure_count, 0U); EXPECT_EQ(before.skip_count, 0U);
    std::string stable_id = before.service_id;

    withdraw_first.store(true);
    dns_upstream_service_snapshot_v1 after{};
    ASSERT_TRUE(await_pool(after, [](const auto &s) {
        return s.endpoint_count == 1 && !strcmp(s.selected_ips[0], "127.0.0.2");
    }));
    EXPECT_EQ(stable_id, after.service_id);
    EXPECT_EQ(after.query_count, 4U); EXPECT_EQ(after.success_count, 4U);
    for (unsigned i = 4; i < 6; i++) ASSERT_TRUE(query_udp("auto-pool-" + std::to_string(i) + ".example", 62773));
    EXPECT_EQ(sends[0].load(), 2U); EXPECT_EQ(sends[1].load(), 4U);
    ASSERT_TRUE(await_pool(after, [](const auto &s) { return s.success_count == 6 && !s.in_flight; }));
    EXPECT_EQ(after.query_count, 6U); EXPECT_EQ(after.attempt_count, 6U);
    EXPECT_EQ(after.query_count, after.success_count + after.failure_count + after.skip_count + after.in_flight);
}

void precise_listener_recursion_case()
{
    std::atomic<unsigned> sends{0};
    smartdns::MockServer bootstrap, safe_backend;
    ASSERT_TRUE(bootstrap.Start("udp://127.0.0.1:62674", [&](smartdns::ServerRequestContext *r) {
        return bootstrap_reply(r, {"127.0.0.1", "127.0.0.2"}, 60);
    }));
    ASSERT_TRUE(safe_backend.Start("udp://127.0.0.2:62774", [&](smartdns::ServerRequestContext *r) {
        dns_add_domain(r->response_packet, r->domain.c_str(), r->qtype, r->qclass);
        if (r->qtype != DNS_T_A) return smartdns::SERVER_REQUEST_ERROR;
        sends++;
        smartdns::MockServer::AddIP(r, r->domain.c_str(), "192.0.2.74", 60);
        return smartdns::SERVER_REQUEST_OK;
    }));
    smartdns::Server resolver(smartdns::Server::CREATE_MODE_THREAD);
    ASSERT_TRUE(resolver.Start(config(62774, 62674, 62774)));
    dns_upstream_service_snapshot_v1 snapshot{};
    ASSERT_TRUE(await_pool(snapshot, [](const auto &s) { return s.endpoint_count == 1; }));
    EXPECT_STREQ(snapshot.selected_ips[0], "127.0.0.2");
    EXPECT_GE(snapshot.rejected_count, 1U);
    for (unsigned i = 0; i < 2; i++) ASSERT_TRUE(query_udp("no-self-loop-" + std::to_string(i) + ".example", 62774));
    EXPECT_EQ(sends.load(), 2U);
    ASSERT_TRUE(await_pool(snapshot, [](const auto &s) { return s.success_count == 2 && !s.in_flight; }));
    EXPECT_EQ(snapshot.attempt_count, 2U); EXPECT_EQ(snapshot.query_count, 2U);
}
}

TEST(UpstreamServiceDiscovery, RealBootstrapRrsetWireRoundRobinStableIdentityAndStats)
{
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    ASSERT_EXIT({ automatic_pool_case(); _exit(::testing::Test::HasFailure() ? 1 : 0); },
                ::testing::ExitedWithCode(0), "");
}
TEST(UpstreamServiceDiscovery, ExactListenerEndpointRejectedButOtherLoopbackEndpointWorks)
{
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    ASSERT_EXIT({ precise_listener_recursion_case(); _exit(::testing::Test::HasFailure() ? 1 : 0); },
                ::testing::ExitedWithCode(0), "");
}

TEST(UpstreamServiceDiscovery, GlobalServerAndExplicitEcsCannotLeakIntoBootstrap) {
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    ASSERT_EXIT({ bootstrap_ecs_isolation_case(); _exit(::testing::Test::HasFailure() ? 1 : 0); },
                ::testing::ExitedWithCode(0), "");
}
TEST(UpstreamServiceDiscovery, NumericBootstrapCannotMaskPendingAliasToSelf) {
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    ASSERT_EXIT({ pending_bootstrap_rejected_case(); _exit(::testing::Test::HasFailure() ? 1 : 0); },
                ::testing::ExitedWithCode(0), "");
}

namespace {
void canonical_cap_case(bool reverse) {
    std::atomic<bool> withdrawn{false}; std::atomic<unsigned> hits[3]{};
    smartdns::MockServer bootstrap, backends[3];
    ASSERT_TRUE(bootstrap.Start("udp://127.0.0.1:62683", [&](smartdns::ServerRequestContext *r) {
        std::vector<const char *> ips = withdrawn ? std::vector<const char *>{"127.0.0.3", "127.0.0.2"} :
            std::vector<const char *>{"127.0.0.3", "127.0.0.1", "127.0.0.2"};
        if (reverse) std::reverse(ips.begin(), ips.end());
        return bootstrap_reply(r, ips, 1);
    }));
    for (unsigned i = 0; i < 3; i++) ASSERT_TRUE(backends[i].Start("udp://127.0.0." + std::to_string(i+1) + ":62883",
        [&, i](smartdns::ServerRequestContext *r) {
            hits[i]++; dns_add_domain(r->response_packet, r->domain.c_str(), r->qtype, r->qclass);
            smartdns::MockServer::AddIP(r, r->domain, "192.0.2.83", 30); return smartdns::SERVER_REQUEST_OK;
        }));
    auto conf = config(62783, 62683, 62883);
    conf.insert(conf.find(" -upstream-ip-pool") + strlen(" -upstream-ip-pool"), " -max-upstream-backends 1");
    smartdns::Server resolver(smartdns::Server::CREATE_MODE_THREAD); ASSERT_TRUE(resolver.Start(conf));
    dns_upstream_service_snapshot_v1 s{};
    ASSERT_TRUE(await_pool(s, [](const auto &v) { return v.endpoint_count == 1; }));
    ASSERT_STREQ(s.selected_ips[0], "127.0.0.1"); ASSERT_TRUE(query_udp("canonical-before.example", 62783));
    withdrawn = true;
    ASSERT_TRUE(await_pool(s, [](const auto &v) { return v.endpoint_count == 1 && !strcmp(v.selected_ips[0], "127.0.0.2"); }));
    ASSERT_TRUE(query_udp("canonical-after.example", 62783));
    EXPECT_EQ(hits[0], 1U); EXPECT_EQ(hits[1], 1U); EXPECT_EQ(hits[2], 0U);
}

void listener_variant_case(unsigned variant) {
    // localhost is resolved with the same OS socket hints as the actual listener,
    // not assumed to mean IPv4; the DNS reply below independently targets it.
    std::string binding = variant == 0 ? ":62784" : variant == 1 ? "localhost:62784" : "[::ffff:127.0.0.1]:62784";
    std::string address = "127.0.0.1"; int family = AF_INET;
    if (variant == 1) {
        addrinfo hints{}, *result = nullptr; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP; hints.ai_flags = AI_PASSIVE;
        ASSERT_EQ(getaddrinfo("localhost", "62784", &hints, &result), 0); ASSERT_NE(result, nullptr);
        char text[INET6_ADDRSTRLEN]; family = result->ai_family;
        const void *binary = family == AF_INET ? static_cast<void *>(&reinterpret_cast<sockaddr_in *>(result->ai_addr)->sin_addr) :
            static_cast<void *>(&reinterpret_cast<sockaddr_in6 *>(result->ai_addr)->sin6_addr);
        ASSERT_NE(inet_ntop(family, binary, text, sizeof(text)), nullptr); address = text; freeaddrinfo(result);
    }
    smartdns::MockServer bootstrap;
    ASSERT_TRUE(bootstrap.Start("udp://127.0.0.1:62684", [&](smartdns::ServerRequestContext *r) {
        dns_add_domain(r->response_packet, r->domain.c_str(), r->qtype, r->qclass);
        if ((r->qtype == DNS_T_A && family == AF_INET) || (r->qtype == DNS_T_AAAA && family == AF_INET6))
            smartdns::MockServer::AddIP(r, r->domain, address, 30);
        else { dns_soa soa{}; strcpy(soa.mname, "ns.example"); strcpy(soa.rname, "hostmaster.example"); soa.minimum = 30;
            dns_add_SOA(r->response_packet, DNS_RRS_NS, "example", 30, &soa); }
        return smartdns::SERVER_REQUEST_OK;
    }));
    auto conf = config(62784, 62684, 62784);
    conf.replace(conf.find("127.0.0.1:62784"), strlen("127.0.0.1:62784"), binding);
    smartdns::Server resolver(smartdns::Server::CREATE_MODE_THREAD); ASSERT_TRUE(resolver.Start(conf));
    dns_upstream_service_snapshot_v1 s{};
    ASSERT_TRUE(await_pool(s, [](const auto &v) { return v.rejected_count >= 1; }));
    EXPECT_EQ(s.endpoint_count, 0U); EXPECT_EQ(s.attempt_count, 0U);
}

void different_transport_case() {
    smartdns::MockServer bootstrap, backend; std::atomic<unsigned> hits{0};
    ASSERT_TRUE(bootstrap.Start("udp://127.0.0.1:62685", [&](smartdns::ServerRequestContext *r) {
        return bootstrap_reply(r, {"127.0.0.1"}, 30);
    }));
    ASSERT_TRUE(backend.Start("udp://127.0.0.1:62885", [&](smartdns::ServerRequestContext *r) {
        hits++; dns_add_domain(r->response_packet, r->domain.c_str(), r->qtype, r->qclass);
        smartdns::MockServer::AddIP(r, r->domain, "192.0.2.85", 30); return smartdns::SERVER_REQUEST_OK;
    }));
    auto conf = config(62785, 62685, 62885) + "bind-tcp 127.0.0.1:62885\n";
    smartdns::Server resolver(smartdns::Server::CREATE_MODE_THREAD); ASSERT_TRUE(resolver.Start(conf));
    dns_upstream_service_snapshot_v1 s{};
    ASSERT_TRUE(await_pool(s, [](const auto &v) { return v.endpoint_count == 1; }));
    EXPECT_EQ(s.rejected_count, 0U); ASSERT_TRUE(query_udp("different-transport.example", 62785)); EXPECT_EQ(hits, 1U);
}

void bootstrap_rotation_case() {
    smartdns::MockServer silent, healthy, ordinary, fallback; std::atomic<unsigned> calls[4]{};
    ASSERT_TRUE(silent.Start("udp://127.0.0.1:62686", [&](smartdns::ServerRequestContext *) {
        calls[0]++; return smartdns::SERVER_REQUEST_NO_RESPONSE;
    }));
    ASSERT_TRUE(healthy.Start("udp://127.0.0.1:62687", [&](smartdns::ServerRequestContext *r) {
        calls[1]++; return bootstrap_reply(r, {"127.0.0.2"}, 30);
    }));
    ASSERT_TRUE(ordinary.Start("udp://127.0.0.1:62688", [&](smartdns::ServerRequestContext *) {
        calls[2]++; return smartdns::SERVER_REQUEST_ERROR;
    }));
    ASSERT_TRUE(fallback.Start("udp://127.0.0.1:62689", [&](smartdns::ServerRequestContext *) {
        calls[3]++; return smartdns::SERVER_REQUEST_ERROR;
    }));
    // Numeric group members are prepended: declare silent last to make it head.
    auto conf = config(62786, 62687, 62886) +
        "server udp://127.0.0.1:62686 -bootstrap-dns -exclude-default-group\n"
        "server udp://127.0.0.1:62688\nserver udp://127.0.0.1:62689 -fallback -exclude-default-group\n";
    smartdns::Server resolver(smartdns::Server::CREATE_MODE_THREAD);
    ASSERT_TRUE(resolver.Start(conf)); auto start = std::chrono::steady_clock::now();
    dns_upstream_service_snapshot_v1 s{};
    bool ready = false;
    do {
        if (read_pool(s) && s.endpoint_count == 1) { ready = true; break; }
        poll(nullptr, 0, 5);
    } while (std::chrono::steady_clock::now() - start < std::chrono::seconds(2));
    EXPECT_TRUE(ready); EXPECT_GT(calls[0], 0U); EXPECT_GT(calls[1], 0U);
    EXPECT_EQ(calls[2], 0U); EXPECT_EQ(calls[3], 0U);
}

void bootstrap_five_member_case(bool one_send_queries) {
    smartdns::MockServer servers[7]; std::atomic<unsigned> calls[7]{};
    for (unsigned i = 0; i < 7; ++i) {
        ASSERT_TRUE(servers[i].Start("udp://127.0.0.1:" + std::to_string(62690 + i), [&, i](smartdns::ServerRequestContext *r) {
            calls[i]++;
            if (i == 4) return bootstrap_reply(r, {"127.0.0.2"}, 30);
            return smartdns::SERVER_REQUEST_NO_RESPONSE;
        }));
    }
    std::string conf = "bind 127.0.0.1:62790\ncache-persist no\nspeed-check-mode none\n";
    // Prepend puts four blackholes ahead of the healthy final member.
    for (int i = 4; i >= 0; --i)
        conf += "server udp://127.0.0.1:" + std::to_string(62690 + i) + " -bootstrap-dns -exclude-default-group\n";
    conf += "server udp://127.0.0.1:62695\nserver udp://127.0.0.1:62696 -fallback -exclude-default-group\n";
    if (!one_send_queries)
        conf += std::string("server udp://") + authority + ":62890 -upstream-ip-pool\n";
    smartdns::Server resolver(smartdns::Server::CREATE_MODE_THREAD); ASSERT_TRUE(resolver.Start(conf));
    if (one_send_queries) {
        std::atomic<unsigned> ended{0}, results{0};
        struct State { std::atomic<unsigned> *ended, *results; } state{&ended, &results};
        auto callback = [](const char *, dns_result_type event, dns_server_info *, dns_packet *, unsigned char *, int, void *user) {
            auto *state = static_cast<State *>(user);
            if (event == DNS_QUERY_END) ++*state->ended;
            if (event == DNS_QUERY_RESULT) ++*state->results;
            return DNS_CLIENT_ACTION_OK;
        };
        for (unsigned i = 0; i < 5; ++i) {
            dns_query_options options{};
            options.enable_flag = DNS_QUEY_OPTION_BOOTSTRAP_ONLY | DNS_QUEY_OPTION_SINGLE_UPSTREAM | DNS_QUEY_OPTION_BUDGET;
            options.budget = dns_query_budget_new(1, 500);
            ASSERT_NE(options.budget, nullptr);
            ASSERT_EQ(dns_client_query(authority, DNS_T_A, callback, &state, "bootstrap-dns", &options), 0);
            dns_query_budget_put(options.budget);
            auto until = std::chrono::steady_clock::now() + std::chrono::seconds(1);
            while (ended <= i && std::chrono::steady_clock::now() < until) poll(nullptr, 0, 5);
            ASSERT_EQ(ended.load(), i + 1);
        }
        EXPECT_GE(results.load(), 1U);
        for (unsigned i = 0; i < 5; ++i) EXPECT_EQ(calls[i].load(), 1U);
    } else {
        // Across refreshes, not a longer per-query deadline: each query remains bounded at 2s.
        auto until = std::chrono::steady_clock::now() + std::chrono::seconds(6);
        dns_upstream_service_snapshot_v1 snapshot{}; bool ready = false;
        do {
            if (read_pool(snapshot) && snapshot.endpoint_count == 1) { ready = true; break; }
            poll(nullptr, 0, 5);
        } while (std::chrono::steady_clock::now() < until);
        EXPECT_TRUE(ready); EXPECT_GT(calls[4].load(), 0U);
        for (unsigned i = 0; i < 4; ++i) EXPECT_GT(calls[i].load(), 0U);
    }
    EXPECT_EQ(calls[5].load(), 0U); EXPECT_EQ(calls[6].load(), 0U);
}
} // namespace
#define DISCOVERY_RUNTIME_CASE(Name, Action) \
TEST(UpstreamServiceDiscovery, Name) { \
    ::testing::FLAGS_gtest_death_test_style = "threadsafe"; \
    ASSERT_EXIT({ Action; _exit(::testing::Test::HasFailure() ? 1 : 0); }, ::testing::ExitedWithCode(0), ""); \
}
DISCOVERY_RUNTIME_CASE(CanonicalCapIgnoresRrOrderAndWithdraws, canonical_cap_case(false))
DISCOVERY_RUNTIME_CASE(CanonicalCapIgnoresReverseRrOrderAndWithdraws, canonical_cap_case(true))
DISCOVERY_RUNTIME_CASE(WildcardListenerActualSocketRejectsSelf, listener_variant_case(0))
DISCOVERY_RUNTIME_CASE(LocalhostListenerActualSocketRejectsSelf, listener_variant_case(1))
DISCOVERY_RUNTIME_CASE(MappedListenerActualSocketRejectsSelf, listener_variant_case(2))
DISCOVERY_RUNTIME_CASE(SameAddressPortDifferentTransportRemainsUsable, different_transport_case())
DISCOVERY_RUNTIME_CASE(SilentFirstBootstrapRotatesWithoutDefaultOrFallback, bootstrap_rotation_case())
DISCOVERY_RUNTIME_CASE(FourSilentBootstrapMembersDoNotStarveFifth, bootstrap_five_member_case(false))
DISCOVERY_RUNTIME_CASE(FreshOneSendBootstrapQueriesAdvanceAcrossAllMembers, bootstrap_five_member_case(true))
#undef DISCOVERY_RUNTIME_CASE
