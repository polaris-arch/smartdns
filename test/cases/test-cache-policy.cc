#include "client.h"
#include "server.h"
#include "gtest/gtest.h"
#include "smartdns/dns.h"
#include <atomic>
#include <unistd.h>

TEST(CachePolicy, ServeExpiredNoKeepsFreshAnswerTTL)
{
    smartdns::MockServer upstream;
    smartdns::Server server;
    ASSERT_TRUE(upstream.Start("udp://0.0.0.0:61053", [](smartdns::ServerRequestContext *request) {
        if (request->qtype != DNS_T_A) return smartdns::SERVER_REQUEST_SOA;
        smartdns::MockServer::AddIP(request, request->domain.c_str(), "192.0.2.10", 120);
        return smartdns::SERVER_REQUEST_OK;
    }));
    server.MockPing(PING_TYPE_ICMP, "192.0.2.10", 60, 10);
    ASSERT_TRUE(server.Start("bind [::]:60053\nserver 127.0.0.1:61053\n"
                            "speed-check-mode ping\ndualstack-ip-selection no\n"
                            "serve-expired no\ncache-persist no\n"));
    smartdns::Client client;
    ASSERT_TRUE(client.Query("fresh-ttl.example A", 60053));
    ASSERT_EQ(client.GetAnswerNum(), 1);
    EXPECT_GT(client.GetAnswer()[0].GetTTL(), 3);
}

TEST(CachePolicy, ServeExpiredNoDoesNotServeExpiredPacket)
{
    std::atomic<int> queries{0};
    smartdns::MockServer upstream;
    smartdns::Server server;
    ASSERT_TRUE(upstream.Start("udp://0.0.0.0:61053", [&](smartdns::ServerRequestContext *request) {
        if (request->qtype != DNS_T_A) return smartdns::SERVER_REQUEST_SOA;
        queries++;
        smartdns::MockServer::AddIP(request, request->domain.c_str(), "192.0.2.20", 2);
        return smartdns::SERVER_REQUEST_OK;
    }));
    ASSERT_TRUE(server.Start("bind [::]:60053\nserver 127.0.0.1:61053\n"
                            "speed-check-mode none\ndualstack-ip-selection no\n"
                            "serve-expired no\nprefetch-domain no\ncache-persist no\n"
                            "rr-ttl-min 1\nrr-ttl-max 2\n"));
    smartdns::Client client;
    ASSERT_TRUE(client.Query("expired-packet.example A", 60053));
    ASSERT_EQ(client.GetAnswerNum(), 1);
    int before = queries.load();
    sleep(4);
    ASSERT_TRUE(client.Query("expired-packet.example A", 60053));
    ASSERT_EQ(client.GetAnswerNum(), 1);
    EXPECT_GT(queries.load(), before);
}
