#include "client.h"
#include "server.h"
#include "smartdns/dns.h"
#include "gtest/gtest.h"
#include <atomic>

TEST(UpstreamObservability, SameNameDifferentTypesAreDistinctAndCacheHitsDoNotReachMock) {
    std::atomic<unsigned> a{0}, aaaa{0}, https{0};
    smartdns::MockServer upstream;
    ASSERT_TRUE(upstream.Start("udp://127.0.0.1:62853", [&](smartdns::ServerRequestContext *r) {
        if (r->qtype == DNS_T_A) {
            a++; unsigned char ip[4] = {192, 0, 2, 1};
            dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 300, ip);
        } else if (r->qtype == DNS_T_AAAA) {
            aaaa++; unsigned char ip[16] = {0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
            dns_add_AAAA(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 300, ip);
        } else if (r->qtype == DNS_T_HTTPS) {
            https++; dns_rr_nested rr;
            dns_add_HTTPS_start(&rr, r->response_packet, DNS_RRS_AN, r->domain.c_str(), 300, 1, ".");
            dns_add_HTTPS_end(&rr);
        } else return smartdns::SERVER_REQUEST_SOA;
        return smartdns::SERVER_REQUEST_OK;
    }));
    smartdns::Server resolver;
    ASSERT_TRUE(resolver.Start(R"(bind 127.0.0.1:62753
server 127.0.0.1:62853
cache-size 16
cache-persist no
prefetch-domain no
serve-expired no
dualstack-ip-selection no
speed-check-mode none
response-mode fastest-response
)"));
    smartdns::Client client;
    for (const char *type : {"A", "AAAA", "HTTPS"}) {
        ASSERT_TRUE(client.Query(std::string("one-name.mock.example ") + type + " +time=2 +tries=1", 62753, "127.0.0.1"));
        ASSERT_EQ(client.GetStatus(), "NOERROR"); ASSERT_EQ(client.GetAnswerNum(), 1);
    }
    EXPECT_EQ(a.load(), 1u); EXPECT_EQ(aaaa.load(), 1u); EXPECT_EQ(https.load(), 1u);
    for (const char *type : {"A", "AAAA", "HTTPS"}) {
        ASSERT_TRUE(client.Query(std::string("one-name.mock.example ") + type + " +time=2 +tries=1", 62753, "127.0.0.1"));
        ASSERT_EQ(client.GetStatus(), "NOERROR"); ASSERT_EQ(client.GetAnswerNum(), 1);
    }
    EXPECT_EQ(a.load(), 1u); EXPECT_EQ(aaaa.load(), 1u); EXPECT_EQ(https.load(), 1u);
}
