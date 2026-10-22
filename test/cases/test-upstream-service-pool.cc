/* Bounded loopback integration, never performance or public-provider probes. */
#include "server.h"
#include "smartdns/dns.h"
#include "smartdns/upstream_service.h"
#include "gtest/gtest.h"
#include <atomic>
#include <chrono>
#include <thread>
#include <vector>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace {
bool query_loopback(const std::string &name, int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    struct timeval timeout = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    unsigned char storage[DNS_PACKSIZE], wire[DNS_IN_PACKSIZE];
    dns_packet *packet = reinterpret_cast<dns_packet *>(storage);
    dns_head head{}; head.id = 123; head.rd = 1;
    dns_packet_init(packet, sizeof(storage), &head);
    dns_add_domain(packet, name.c_str(), DNS_T_A, DNS_C_IN);
    int size = dns_encode(wire, sizeof(wire), packet);
    bool ok = size > 0 && sendto(fd, wire, size, 0, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == size;
    if (ok) {
        size = recv(fd, wire, sizeof(wire), 0);
        ok = size > 0 && !dns_decode(packet, sizeof(storage), wire, size) &&
            packet->head.rcode == DNS_RC_NOERROR && packet->head.ancount == 1;
    }
    close(fd); return ok;
}
}


TEST(UpstreamServicePool, StaticTwoBackendsOneRuntimeServiceAndWireRoundRobin) {
    std::atomic<unsigned> sent[2]{};
    smartdns::MockServer a, b;
    auto response = [&](int index, smartdns::ServerRequestContext *r) {
        if (r->qtype != DNS_T_A) return smartdns::SERVER_REQUEST_SOA;
        sent[index]++;
        smartdns::MockServer::AddIP(r, r->domain.c_str(), "192.0.2.17", 60);
        return smartdns::SERVER_REQUEST_OK;
    };
    ASSERT_TRUE(a.Start("udp://127.0.0.1:62863", [&](smartdns::ServerRequestContext *r) { return response(0, r); }));
    ASSERT_TRUE(b.Start("udp://127.0.0.2:62863", [&](smartdns::ServerRequestContext *r) { return response(1, r); }));
    smartdns::Server resolver;
    ASSERT_TRUE(resolver.Start(R"(bind 127.0.0.1:62763
server udp://resolver.example:62863 -upstream-ip-pool -host-ip 127.0.0.1,127.0.0.2
cache-size 0
cache-persist no
prefetch-domain no
serve-expired no
dualstack-ip-selection no
speed-check-mode none
response-mode fastest-response
)"));
    for (int i = 0; i < 4; i++)
        ASSERT_TRUE(query_loopback("pool-" + std::to_string(i) + ".example", 62763));
    EXPECT_EQ(sent[0].load(), 2U); EXPECT_EQ(sent[1].load(), 2U);
    // Smartdns::Server may isolate the resolver process; copied C snapshots are
    // asserted by the native plugin REST test in that same process, not fabricated here.
}
