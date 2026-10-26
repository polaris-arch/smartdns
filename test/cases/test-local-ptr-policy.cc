#include "client.h"
#include "server.h"
#include "smartdns/dns.h"
#include "gtest/gtest.h"
#include <atomic>

class LocalPtrPolicy : public ::testing::Test {};

TEST_F(LocalPtrPolicy, ReservedPtrPolicyPreservesStaticPublicAndOtherQtypes)
{
	std::atomic<int> sent{0};
	smartdns::MockServer upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://0.0.0.0:61053", [&](smartdns::ServerRequestContext *r) {
		sent++;
		if (r->qtype == DNS_T_PTR) {
			dns_add_PTR(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 30, "upstream.example");
			return smartdns::SERVER_REQUEST_OK;
		}
		if (r->qtype == DNS_T_A || r->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(r, r->domain.c_str(), r->qtype == DNS_T_A ? "1.2.3.4" : "2001:4860::1");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	}));
	ASSERT_TRUE(server.Start(R"(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053
cache-size 0
speed-check-mode none
dualstack-ip-selection no
domain-rules /0.0.192.in-addr.arpa/ -ptr-soa yes
domain-rules /8.e.f.ip6.arpa/ -ptr-soa yes
domain-rules /168.192.in-addr.arpa/ -ptr-soa yes
domain-rules /9.0.0.192.in-addr.arpa/ -ptr-soa no
expand-ptr-from-address yes
address /known.example/192.0.0.7
)"));
	smartdns::Client client;
	for (const char *label : {"b", "db", "r", "dr", "lb", "LB"}) {
		for (const char *transport : {"", " +tcp"}) {
			int before = sent;
			auto query = std::string(label) + "._dns-sd._udp.6.0.0.192.in-addr.arpa PTR" + transport;
			ASSERT_TRUE(client.Query(query, 60053));
			EXPECT_EQ(client.GetStatus(), "NOERROR");
			EXPECT_EQ(client.GetAnswerNum(), 0);
			EXPECT_EQ(client.GetAuthorityNum(), 1);
			EXPECT_EQ(sent, before) << query;
		}
	}
	std::string private6 = "lb._dns-sd._udp.";
	for (int i = 0; i < 29; i++) private6 += "0.";
	private6 += "8.e.f.ip6.arpa PTR";
	int before = sent;
	ASSERT_TRUE(client.Query(private6, 60053));
	EXPECT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(sent, before);
	ASSERT_TRUE(client.Query("7.0.0.192.in-addr.arpa PTR", 60053));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_NE(client.GetAnswer()[0].GetData().find("known.example"), std::string::npos);
	EXPECT_EQ(sent, before);
	for (const char *query : {"6.0.0.192.in-addr.arpa PTR", "other._dns-sd._udp.6.0.0.192.in-addr.arpa PTR", "5.1.168.192.in-addr.arpa PTR"}) {
		before = sent;
		ASSERT_TRUE(client.Query(query, 60053));
		EXPECT_EQ(client.GetAnswerNum(), 0);
		EXPECT_EQ(client.GetAuthorityNum(), 1);
		EXPECT_EQ(sent, before);
	}
	for (const char *query : {
		"8.8.8.8.in-addr.arpa PTR",
		"1.0.0.2.ip6.arpa PTR",
		"lb._dns-sd._udp.9.0.0.192.in-addr.arpa PTR",
		"lb._dns-sd._udp.example.test PTR",
		"lb._dns-sd._udp.8.8.8.8.in-addr.arpa PTR",
		"lb._dns-sd._udp.1.0.0.2.ip6.arpa PTR",
		"lb._dns-sd._udp.6.0.0.192.in-addr.arpa A",
		"lb._dns-sd._udp.6.0.0.192.in-addr.arpa AAAA"}) {
		before = sent;
		ASSERT_TRUE(client.Query(query, 60053)) << query;
		EXPECT_EQ(client.GetAnswerNum(), 1) << query;
		EXPECT_GT(sent.load(), before) << query;
	}
}

TEST_F(LocalPtrPolicy, SpecificOverridesAndInheritedGroupPolicyRemainIndependent)
{
	std::atomic<int> sent{0};
	smartdns::MockServer upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://0.0.0.0:61053", [&](smartdns::ServerRequestContext *r) {
		sent++;
		dns_add_PTR(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 30, "upstream.example");
		return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(R"(bind [::]:60053
bind [::]:60054 -g child
server 127.0.0.1:61053
cache-size 0
speed-check-mode none
dualstack-ip-selection no
domain-rules /0.0.192.in-addr.arpa/ -ptr-soa yes
domain-rules /6.0.0.192.in-addr.arpa/ -ptr-soa no
domain-rules /lb._dns-sd._udp.6.0.0.192.in-addr.arpa/ -ptr-soa yes
group-begin child -inherit default
domain-rules /0.0.192.in-addr.arpa/ -ptr-soa no
domain-rules /lb._dns-sd._udp.6.0.0.192.in-addr.arpa/ -ptr-soa no
group-end
)"));
	smartdns::Client client;
	int before = sent;
	ASSERT_TRUE(client.Query("lb._dns-sd._udp.6.0.0.192.in-addr.arpa PTR", 60053));
	EXPECT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(sent, before);
	ASSERT_TRUE(client.Query("b._dns-sd._udp.6.0.0.192.in-addr.arpa PTR", 60053));
	EXPECT_EQ(client.GetAnswerNum(), 1);
	EXPECT_GT(sent.load(), before);
	before = sent;
	ASSERT_TRUE(client.Query("lb._dns-sd._udp.6.0.0.192.in-addr.arpa PTR", 60054));
	EXPECT_EQ(client.GetAnswerNum(), 1);
	EXPECT_GT(sent.load(), before);
	before = sent;
	ASSERT_TRUE(client.Query("lb._dns-sd._udp.6.0.0.192.in-addr.arpa PTR", 60053));
	EXPECT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(sent, before);
}
