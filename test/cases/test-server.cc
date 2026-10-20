/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cstdio>
#include "client.h"
#include "smartdns/dns.h"
#include "include/utils.h"
#include "server.h"
#include "gtest/gtest.h"
#include <atomic>

class Server : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(Server, all_unreach)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		EXPECT_EQ(request->domain, "e.com");
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "2001::", 128, 10000);
	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server tls://255.255.255.255
server https://255.255.255.255
server tcp://255.255.255.255
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	EXPECT_EQ(client.GetStatus(), "SERVFAIL");
	EXPECT_EQ(client.GetAnswerNum(), 0);

	/* server should not crash */
	ASSERT_TRUE(client.Query("a.com +tcp", 60053));
	std::cout << client.GetResult() << std::endl;
	EXPECT_EQ(client.GetStatus(), "SERVFAIL");
	EXPECT_EQ(client.GetAnswerNum(), 0);
}

TEST_F(Server, one_nxdomain)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream1;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		usleep(50000);

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream1.Start("udp://0.0.0.0:62053",
						   [](struct smartdns::ServerRequestContext *request) { return smartdns::SERVER_REQUEST_SOA; });

	server.MockPing(PING_TYPE_ICMP, "2001::", 128, 10000);
	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053
server 127.0.0.1:62053
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Server, retry_no_result_with_NOERROR)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream1;
	smartdns::Server server;
	int count = 0;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		if (count++ < 2) {
			dns_add_domain(request->response_packet, request->domain.c_str(), request->qtype, request->qclass);
			request->response_packet->head.tc = 1;
			return smartdns::SERVER_REQUEST_OK;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Server, retry_no_response)
{
	std::atomic<int> count{0};
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream1;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		count++;
		return smartdns::SERVER_REQUEST_NO_RESPONSE;
	});

	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "SERVFAIL");
	EXPECT_GE(client.GetQueryTime(), 1500);
	EXPECT_EQ(count.load(), 4); // initial send plus all three retries, no duplicate fanout
}

TEST_F(Server, max_queries)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream1;
	smartdns::Server server;
	int count = 0;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		sleep(1);
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 128, 10);

	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
max-query-limit 2
)""");

	std::vector<std::thread> threads;
	int success_num = 0;
	int refused_num = 0;
	for (int i = 0; i < 5; i++) {
		auto t = std::thread([&]() {
			smartdns::Client client;
			ASSERT_TRUE(client.Query("a.com", 60053));
			if (client.GetStatus() == "NOERROR") {
				success_num++;
				EXPECT_EQ(client.GetStatus(), "NOERROR");
				ASSERT_EQ(client.GetAnswerNum(), 1);
				EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
				EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
			} else if (client.GetStatus() == "REFUSED") {
				refused_num++;
			} else {
				FAIL();
			}
		});
		threads.push_back(std::move(t));
	}

	for (auto &t : threads) {
		t.join();
	}

	EXPECT_EQ(success_num, 2);
	EXPECT_EQ(refused_num, 3);

	for (int i = 0; i < 5; i++) {
		smartdns::Client client;
		ASSERT_TRUE(client.Query("a.com", 60053));
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		ASSERT_EQ(client.GetAnswerNum(), 1);
		EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
		EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
	}
}

TEST_F(Server, interface)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "2001::", 128, 10000);
	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053 -interface lo
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Server, refused)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream1;
	smartdns::Server server;
	int count = 0;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		request->response_packet->head.rcode = DNS_RC_REFUSED;
		dns_add_domain(request->response_packet, request->domain.c_str(), request->qtype, request->qclass);
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "REFUSED");
	EXPECT_LT(client.GetQueryTime(), 100);
}

TEST_F(Server, fallback)
{
    std::atomic<int> primary_count{0}, fallback_count{0};
    std::atomic<bool> fallback_before_primary{false};
	smartdns::MockServer server_upstream;
	smartdns::Server server;
    smartdns::MockServer primary;
    // Keep the primary alive but silent. A closed port would instead exercise
    // immediate transport failure/prohibition and cannot establish timeout order.
    ASSERT_TRUE(primary.Start("udp://127.0.0.1:61054", [&](struct smartdns::ServerRequestContext *request) {
        primary_count++;
        return smartdns::SERVER_REQUEST_NO_RESPONSE;
    }));

	ASSERT_TRUE(server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		fallback_count++;
        if (primary_count.load() == 0) fallback_before_primary = true;
        if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		return smartdns::SERVER_REQUEST_OK;
	}));

	server.MockPing(PING_TYPE_ICMP, "2001::", 128, 10000);
	ASSERT_TRUE(server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053 -fallback
server 127.0.0.1:61054
dualstack-ip-selection no
speed-check-mode none
)"""));
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	// Fallback is eligible after the first 500 ms retry interval, not after
    // the incidental one-second idle scan delay of the old worker loop.
    EXPECT_GE(client.GetQueryTime(), 500);
    EXPECT_GE(primary_count.load(), 1);
    EXPECT_LE(primary_count.load(), 2); // initial primary, at most one retry
    EXPECT_EQ(fallback_count.load(), 1);
    EXPECT_FALSE(fallback_before_primary.load());
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Server, fallback_group)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "2001::", 128, 10000);
	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053 -e -group fallback
server 127.0.0.1:61054
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_GE(client.GetQueryTime(), 1000);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Server, groups)
{
	smartdns::MockServer server_upstream1;
	smartdns::MockServer server_upstream2;
	smartdns::MockServer server_upstream3;
	smartdns::Server server;

	server_upstream1.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream2.Start("udp://0.0.0.0:61054", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.5", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream3.Start("udp://0.0.0.0:61055", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.6", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 128, 10);
	server.MockPing(PING_TYPE_ICMP, "1.2.3.5", 128, 10);
	server.MockPing(PING_TYPE_ICMP, "1.2.3.6", 128, 10);
	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053 
server 127.0.0.1:61054 -e -group a -group b
server 127.0.0.1:61055 -e -group c -group d
nameserver /a.com/a
nameserver /b.com/b
nameserver /c.com/c
nameserver /d.com/d
nameserver /e.com/unknown
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.5");

	ASSERT_TRUE(client.Query("b.com", 60053));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "b.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.5");

	ASSERT_TRUE(client.Query("c.com", 60053));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "c.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.6");

	ASSERT_TRUE(client.Query("d.com", 60053));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "d.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.6");

	ASSERT_TRUE(client.Query("e.com", 60053));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "e.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	ASSERT_TRUE(client.Query("f.com", 60053));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "f.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Server, repeat_group)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		static int count = 0;
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		count++;
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		if (count > 1) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.5", 611);
		}
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "2001::", 128, 10000);
	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053 -e -group a -group a
nameserver /a.com/a
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	usleep(100000);
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}


TEST_F(Server, bad_block_ip)
{
	smartdns::MockServer server_upstream1;
	smartdns::MockServer server_upstream2;
	smartdns::MockServer server_upstream3;
	smartdns::Server server;

	server_upstream1.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "127.0.0.1", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream2.Start("udp://0.0.0.0:61054", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "::", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream3.Start("udp://0.0.0.0:61055", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		usleep(100000); 
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.6", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 128, 10);
	server.MockPing(PING_TYPE_ICMP, "1.2.3.5", 128, 10);
	server.MockPing(PING_TYPE_ICMP, "1.2.3.6", 128, 10);
	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053 
server 127.0.0.1:61054 
server 127.0.0.1:61055
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.6");
}

TEST_F(Server, bad_block_ip_no_check_speed)
{
	smartdns::MockServer server_upstream1;
	smartdns::MockServer server_upstream2;
	smartdns::MockServer server_upstream3;
	smartdns::Server server;

	server_upstream1.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "127.0.0.1", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream2.Start("udp://0.0.0.0:61054", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "::", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream3.Start("udp://0.0.0.0:61055", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		usleep(100000); 
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.6", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 128, 10);
	server.MockPing(PING_TYPE_ICMP, "1.2.3.5", 128, 10);
	server.MockPing(PING_TYPE_ICMP, "1.2.3.6", 128, 10);
	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053 
server 127.0.0.1:61054 
server 127.0.0.1:61055
speed-check-mode none
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.6");
}

TEST_F(Server, case_insensitive)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		usleep(100000);
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 128, 1000);
	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053 
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	ASSERT_TRUE(client.Query("A.cOm", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_LE(client.GetQueryTime(), 5);
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "A.cOm");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}
TEST_F(Server, StartupFailureNotificationIsNotReady)
{
    smartdns::Server server;
    EXPECT_FALSE(server.Start("bind 127.0.0.1:60053\nany-response-mode invalid-mode\n"));
    EXPECT_FALSE(server.IsRunning());
}

TEST_F(Server, FixtureChildRejectsMalformedArguments)
{
    auto rejected = [](std::vector<std::string> args) {
        std::vector<char *> argv;
        for (auto &arg : args) argv.push_back(const_cast<char *>(arg.c_str()));
        argv.push_back(nullptr);
        return smartdns::Server::RunFixtureChild(args.size(), argv.data());
    };
    EXPECT_EQ(rejected({"test.bin", "--smartdns-fixture-child"}), 2);
    EXPECT_EQ(rejected({"test.bin", "--smartdns-fixture-child", ""}), 2);
    EXPECT_EQ(rejected({"test.bin", "--smartdns-fixture-child", "/unused", "1"}), 2);
    EXPECT_EQ(rejected({"test.bin", "--smartdns-fixture-child", "/unused", "0", "127.0.0.1", "60", "0.125"}), 2);
    EXPECT_EQ(rejected({"test.bin", "--smartdns-fixture-child", "/unused", "1x", "127.0.0.1", "60", "0.125"}), 2);
    EXPECT_EQ(rejected({"test.bin", "--smartdns-fixture-child", "/unused", "1", "", "60", "0.125"}), 2);
    EXPECT_EQ(rejected({"test.bin", "--smartdns-fixture-child", "/unused", "1", "127.0.0.1", "60x", "0.125"}), 2);
    EXPECT_EQ(rejected({"test.bin", "--smartdns-fixture-child", "/unused", "1", "127.0.0.1", "60", "0.125x"}), 2);
    EXPECT_EQ(rejected({"test.bin", "--smartdns-fixture-child", "/unused", "1", "127.0.0.1", "60", "nan"}), 2);
}

TEST_F(Server, MockUpstreamIdleShutdownWithReadableStdin)
{
	// A mock upstream may be idle when local rules answer every DNS query.
	// Keep fd 0 readable, exercising the former prepublication poll hazard.
	int saved_stdin = dup(STDIN_FILENO);
	ASSERT_GE(saved_stdin, 0);
	Defer { EXPECT_EQ(dup2(saved_stdin, STDIN_FILENO), STDIN_FILENO); close(saved_stdin); };
	FILE *input = fopen("/dev/null", "r");
	ASSERT_NE(input, nullptr);
	Defer { fclose(input); };
	ASSERT_EQ(dup2(fileno(input), STDIN_FILENO), STDIN_FILENO);
	std::atomic<int> callbacks{0};
	for (int i = 0; i < 16; i++) {
		smartdns::MockServer upstream;
		ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *) {
			callbacks++; return smartdns::SERVER_REQUEST_NO_RESPONSE;
		}));
		usleep(1000);
		upstream.Stop();
		EXPECT_FALSE(upstream.IsRunning());
	}
	EXPECT_EQ(callbacks, 0);
}
