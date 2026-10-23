/* SOA-backed address negatives complete a provider, not the whole fanout. */
#include "server.h"
#include "smartdns/dns.h"
#include "smartdns/upstream_service.h"
#include "gtest/gtest.h"
extern "C" {
#include "dns_server/answer.h"
#include "dns_server/dns_server.h"
}
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
bool negative_packet(dns_packet *packet, size_t capacity, const char *question, int qtype,
                     const char *zone, bool authority = true, int qclass = DNS_C_IN)
{
    dns_head head{}; head.id = 14321; head.qr = DNS_QR_ANSWER; head.rd = head.ra = 1;
    if (dns_packet_init(packet, capacity, &head) || dns_add_domain(packet, question, qtype, qclass)) return false;
    if (zone) {
        dns_soa soa{}; strcpy(soa.mname, "ns.example"); strcpy(soa.rname, "hostmaster.example");
        soa.serial = 1; soa.refresh = 3600; soa.retry = 600; soa.expire = 86400; soa.minimum = 60;
        if (dns_add_SOA(packet, authority ? DNS_RRS_NS : DNS_RRS_NR, zone, 60, &soa)) return false;
    }
    // Round-trip the wire, including actual header section counts.
    unsigned char wire[DNS_IN_PACKSIZE];
    int n = dns_encode(wire, sizeof(wire), packet);
    return n > 0 && dns_decode(packet, capacity, wire, n) == 0;
}

bool ask(const std::string &name, int qtype, bool positive, int rcode = DNS_RC_NOERROR)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    timeval timeout{3, 0}; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    sockaddr_in to{}; to.sin_family = AF_INET; to.sin_port = htons(62791);
    inet_pton(AF_INET, "127.0.0.1", &to.sin_addr);
    alignas(dns_packet) unsigned char storage[DNS_PACKSIZE]; unsigned char wire[DNS_IN_PACKSIZE];
    auto *packet = reinterpret_cast<dns_packet *>(storage);
    dns_head head{}; head.id = 14321; head.rd = 1;
    dns_packet_init(packet, sizeof(storage), &head); dns_add_domain(packet, name.c_str(), qtype, DNS_C_IN);
    int n = dns_encode(wire, sizeof(wire), packet);
    bool ok = n > 0 && sendto(fd, wire, n, 0, reinterpret_cast<sockaddr *>(&to), sizeof(to)) == n;
    if (ok) {
        n = recv(fd, wire, sizeof(wire), 0);
        ok = n > 0 && !dns_decode(packet, sizeof(storage), wire, n) && packet->head.id == 14321 &&
            packet->head.rcode == rcode && packet->head.ancount == (positive ? 1 : 0) &&
            (positive || packet->head.nscount == 1);
    }
    close(fd); return ok;
}

void pool_case(unsigned rate, bool fallback, bool nxdomain = false)
{
    std::atomic<unsigned> sends[2]{}, other_sends{0};
    smartdns::MockServer first, second, other;
    auto respond = [&](unsigned backend, smartdns::ServerRequestContext *r) {
        sends[backend]++;
        dns_add_domain(r->response_packet, r->domain.c_str(), r->qtype, r->qclass);
        if (!fallback && !nxdomain && r->qtype == DNS_T_A) {
            smartdns::MockServer::AddIP(r, r->domain.c_str(), "192.0.2.89", 60);
        } else {
            dns_soa soa{}; strcpy(soa.mname, "ns.example"); strcpy(soa.rname, "hostmaster.example");
            soa.minimum = 60;
            dns_add_SOA(r->response_packet, DNS_RRS_NS, "example", 60, &soa);
            if (nxdomain) r->response_packet->head.rcode = DNS_RC_NXDOMAIN;
        }
        return smartdns::SERVER_REQUEST_OK;
    };
    ASSERT_TRUE(first.Start("udp://127.0.0.1:62891", [&](auto *r) { return respond(0, r); }));
    ASSERT_TRUE(second.Start("udp://127.0.0.2:62891", [&](auto *r) { return respond(1, r); }));
    if (fallback) ASSERT_TRUE(other.Start("udp://127.0.0.1:62892", [&](auto *r) {
        other_sends++;
        usleep(150000);
        dns_add_domain(r->response_packet, r->domain.c_str(), r->qtype, r->qclass);
        smartdns::MockServer::AddIP(r, r->domain.c_str(), "2001:db8::89", 60);
        return smartdns::SERVER_REQUEST_OK;
    }));
    smartdns::Server resolver(smartdns::Server::CREATE_MODE_THREAD);
    std::string conf = "bind 127.0.0.1:62791\nserver udp://resolver.example:62891 -upstream-ip-pool"
        " -host-ip 127.0.0.1,127.0.0.2 -max-query-rate " + std::to_string(rate) + " -query-burst 1\n";
    if (fallback) conf += "server udp://127.0.0.1:62892\n";
    conf += "cache-size 0\ncache-persist no\nprefetch-domain no\nserve-expired no\n"
        "dualstack-ip-selection no\n";
    conf += fallback ? "speed-check-mode ping\n" : "speed-check-mode none\n";
    conf += fallback ? "response-mode first-ping\n" : "response-mode fastest-response\n";
    if (fallback) resolver.MockPing(PING_TYPE_ICMP, "2001:db8::89", 64, 10);
    ASSERT_TRUE(resolver.Start(conf));
    unsigned queries = fallback || nxdomain ? 1 : 12;
    for (unsigned i = 0; i < queries; i++) {
        bool positive = fallback || (!nxdomain && i % 2 == 0);
        ASSERT_TRUE(ask("nodata-" + std::to_string(i) + ".example", positive && !fallback ? DNS_T_A : DNS_T_AAAA,
                        positive, nxdomain ? DNS_RC_NXDOMAIN : DNS_RC_NOERROR));
    }
    dns_upstream_service_snapshot_v1 stats{};
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    do {
        ASSERT_EQ(dns_client_get_service_snapshot_v1(&stats, 1), fallback ? 2 : 1);
        if (stats.success_count == queries && !stats.in_flight) break;
        poll(nullptr, 0, 5);
    } while (std::chrono::steady_clock::now() < deadline);
    std::cout << "NODATA pool: qps=" << rate << " queries=" << stats.query_count
        << " success=" << stats.success_count << " failure=" << stats.failure_count
        << " skipped=" << stats.skip_count << " active=" << stats.in_flight
        << " attempts=" << stats.attempt_count << " backends=" << sends[0].load() << ":" << sends[1].load()
        << std::endl;
    EXPECT_EQ(stats.query_count, queries); EXPECT_EQ(stats.success_count, queries);
    EXPECT_EQ(stats.failure_count, 0U); EXPECT_EQ(stats.skip_count, 0U); EXPECT_EQ(stats.in_flight, 0U);
    EXPECT_EQ(stats.attempt_count, queries); EXPECT_EQ(sends[0] + sends[1], queries);
    if (queries == 12) { EXPECT_EQ(sends[0], 6U); EXPECT_EQ(sends[1], 6U); }
    if (fallback) EXPECT_EQ(other_sends, 1U);
}
} // namespace

TEST(UpstreamNodata, RequiresMatchingCompleteInClassAuthorityProof)
{
    alignas(dns_packet) unsigned char storage[DNS_PACKSIZE];
    auto *packet = reinterpret_cast<dns_packet *>(storage);
    for (int qtype : {DNS_T_A, DNS_T_AAAA}) {
        for (const char *zone : {"example", "empty.example", "EXAMPLE", ""}) {
            ASSERT_TRUE(negative_packet(packet, sizeof(storage), "empty.example", qtype, zone));
            EXPECT_TRUE(_dns_server_is_nodata(packet, "empty.example", qtype)) << "zone=" << zone;
            packet->head.tc = 1;
            EXPECT_FALSE(_dns_server_is_nodata(packet, "empty.example", qtype));
            packet->head.tc = 0; packet->head.ancount = 1;
            EXPECT_FALSE(_dns_server_is_nodata(packet, "empty.example", qtype));
        }
        for (const char *zone : {"other.example", "ample", "unrelated", static_cast<const char *>(nullptr)}) {
            ASSERT_TRUE(negative_packet(packet, sizeof(storage), "empty.example", qtype, zone));
            EXPECT_FALSE(_dns_server_is_nodata(packet, "empty.example", qtype));
        }
        ASSERT_TRUE(negative_packet(packet, sizeof(storage), "empty.example", qtype, "example", false));
        EXPECT_FALSE(_dns_server_is_nodata(packet, "empty.example", qtype));
        ASSERT_TRUE(negative_packet(packet, sizeof(storage), "empty.example", qtype, "example"));
        EXPECT_FALSE(_dns_server_is_nodata(packet, "other.example", qtype));
        EXPECT_FALSE(_dns_server_is_nodata(packet, "empty.example", qtype == DNS_T_A ? DNS_T_AAAA : DNS_T_A));
        for (int rcode : {DNS_RC_SERVFAIL, DNS_RC_REFUSED, DNS_RC_NXDOMAIN}) {
            packet->head.rcode = rcode;
            EXPECT_FALSE(_dns_server_is_nodata(packet, "empty.example", qtype));
        }
        packet->head.rcode = DNS_RC_NOERROR; packet->head.opcode = DNS_OP_IQUERY;
        EXPECT_FALSE(_dns_server_is_nodata(packet, "empty.example", qtype));
    }
    ASSERT_TRUE(negative_packet(packet, sizeof(storage), "empty.example", DNS_T_AAAA, "example", true, 3));
    EXPECT_FALSE(_dns_server_is_nodata(packet, "empty.example", DNS_T_AAAA));
    ASSERT_TRUE(negative_packet(packet, sizeof(storage), "empty.example", DNS_T_AAAA, ""));
    int count = 0;
    auto *soa = dns_get_rrs_start(packet, DNS_RRS_NS, &count);
    ASSERT_NE(soa, nullptr); ASSERT_EQ(count, 1);
    // The decoded root owner is one zero octet, followed by type and class.
    ASSERT_EQ(soa->data[0], 0); soa->data[4] = 3;
    EXPECT_FALSE(_dns_server_is_nodata(packet, "empty.example", DNS_T_AAAA));
    soa->data[4] = DNS_C_IN; soa->len = 5;
    EXPECT_FALSE(_dns_server_is_nodata(packet, "empty.example", DNS_T_AAAA));
    ASSERT_TRUE(negative_packet(packet, sizeof(storage), "empty.example", DNS_T_HTTPS, "example"));
    EXPECT_TRUE(_dns_server_is_nodata(packet, "empty.example", DNS_T_HTTPS));
}

TEST(UpstreamNodata, CompleteHttpsNegativeDoesNotDependOnEarlierProviderRcode)
{
    alignas(dns_packet) unsigned char storage[DNS_PACKSIZE];
    auto *packet = reinterpret_cast<dns_packet *>(storage);
    dns_conf_group conf{};
    for (int qtype : {DNS_T_AAAA, DNS_T_HTTPS}) for (int rcode : {DNS_RC_NOERROR, DNS_RC_NXDOMAIN}) {
        ASSERT_TRUE(negative_packet(packet, sizeof(storage), "empty.example", qtype, "example"));
        packet->head.rcode = rcode;
        dns_request request{}; request.conf = &conf; request.qtype = static_cast<dns_type_t>(qtype);
        request.rcode = DNS_RC_NOERROR; strcpy(request.domain, "empty.example");
        // Another provider already supplied usable data. A negative reply must
        // remain a valid provider response without completing that whole race.
        atomic_set(&request.ip_map_num, 1);
        int passthrough = 0;
        EXPECT_EQ(_dns_server_process_answer(&request, "empty.example", packet, 0, &passthrough),
            DNS_CLIENT_ACTION_OK_WAIT) << "qtype=" << qtype << " rcode=" << rcode;
        packet->head.tc = 1;
        EXPECT_EQ(_dns_server_process_answer(&request, "empty.example", packet, 0, &passthrough),
            DNS_CLIENT_ACTION_MAY_RETRY);
        ASSERT_TRUE(negative_packet(packet, sizeof(storage), "empty.example", qtype, "unrelated.example"));
        packet->head.rcode = rcode;
        EXPECT_EQ(_dns_server_process_answer(&request, "empty.example", packet, 0, &passthrough),
            DNS_CLIENT_ACTION_MAY_RETRY);
    }
}

#define NODATA_RUNTIME_CASE(Name, Action) \
TEST(UpstreamNodata, Name) { \
    ::testing::FLAGS_gtest_death_test_style = "threadsafe"; \
    ASSERT_EXIT({ Action; _exit(::testing::Test::HasFailure() ? 1 : 0); }, ::testing::ExitedWithCode(0), ""); \
}
NODATA_RUNTIME_CASE(Pool20CountsNodataWithoutDuplicateAttempts, pool_case(20, false))
NODATA_RUNTIME_CASE(Pool40CountsNodataWithoutDuplicateAttempts, pool_case(40, false))
NODATA_RUNTIME_CASE(NodataDoesNotCancelOtherProvidersPositive, pool_case(20, true))
NODATA_RUNTIME_CASE(NxdomainRemainsSuccessfulWithoutDuplicateAttempts, pool_case(20, false, true))
#undef NODATA_RUNTIME_CASE
