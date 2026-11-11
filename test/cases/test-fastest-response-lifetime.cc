#include "gtest/gtest.h"
#include "client.h"
#include "include/utils.h"
#include "server.h"
extern "C" {
#include "dns_server/address.h"
#include "dns_server/context.h"
#include "dns_server/dns_server.h"
#include "dns_server/request.h"
}
#include <array>
#include <arpa/inet.h>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <mutex>
#include <vector>

namespace {
struct {
	std::mutex lock;
	std::condition_variable ready;
	bool armed = false, resume = false, timed_out = false;
	dns_request *request = nullptr;
	dns_ip_address *node = nullptr;
} lookup;
}

extern "C" dns_ip_address *__real__dns_ip_address_get(dns_request *, unsigned char *, dns_type_t);
extern "C" dns_ip_address *__wrap__dns_ip_address_get(dns_request *request, unsigned char *addr, dns_type_t type)
{
	auto *node = __real__dns_ip_address_get(request, addr, type);
	std::unique_lock<std::mutex> lock(lookup.lock);
	if (lookup.armed && !lookup.request && node && strcmp(request->domain, "retained.example") == 0) {
		// Pause after lookup has released ip_map_lock, before its caller uses the node.
		_dns_server_request_get(request);
		lookup.request = request;
		lookup.node = node;
		lookup.ready.notify_all();
		lookup.timed_out = !lookup.ready.wait_for(lock, std::chrono::seconds(5), [] { return lookup.resume; });
	}
	return node;
}

TEST(FastestResponseLifetime, FirstReplyKeepsOutstandingSpeedCheckNodes)
{
	for (int type : {DNS_T_A, DNS_T_AAAA}) {
		SCOPED_TRACE(type);
		const char *x = type == DNS_T_A ? "192.0.2.20" : "2001:db8::20";
		const char *y = type == DNS_T_A ? "192.0.2.254" : "2001:db8::ffff";
		const char *z = type == DNS_T_A ? "192.0.2.30" : "2001:db8::30";
		{
			std::lock_guard<std::mutex> lock(lookup.lock);
			lookup.armed = true; lookup.resume = lookup.timed_out = false;
			lookup.request = nullptr; lookup.node = nullptr;
		}
		smartdns::MockServer first, second;
		smartdns::Server resolver(smartdns::Server::CREATE_MODE_THREAD);
		Defer {
			dns_request *held;
			{
				std::lock_guard<std::mutex> lock(lookup.lock);
				lookup.armed = false; lookup.resume = true; held = lookup.request;
			}
			lookup.ready.notify_all();
			if (held) _dns_server_request_release(held);
		};
		ASSERT_TRUE(first.Start("udp://127.0.0.1:62153", [&](auto *r) {
			if (r->qtype != type) return smartdns::SERVER_REQUEST_SOA;
			if (r->domain == "retained.example") {
				smartdns::MockServer::AddIP(r, r->domain.c_str(), x);
				smartdns::MockServer::AddIP(r, r->domain.c_str(), y);
			} else smartdns::MockServer::AddIP(r, r->domain.c_str(), z);
			return smartdns::SERVER_REQUEST_OK;
		}));
		ASSERT_TRUE(second.Start("udp://127.0.0.1:62253", [&](auto *r) {
			if (r->qtype != type) return smartdns::SERVER_REQUEST_SOA;
			if (r->domain == "retained.example") {
				std::unique_lock<std::mutex> lock(lookup.lock);
				if (!lookup.ready.wait_for(lock, std::chrono::seconds(5), [] { return lookup.request != nullptr; }))
					return smartdns::SERVER_REQUEST_SOA;
			}
			smartdns::MockServer::AddIP(r, r->domain.c_str(), z);
			return smartdns::SERVER_REQUEST_OK;
		}));
		resolver.MockPing(PING_TYPE_ICMP, x, 60, 1);
		resolver.MockPing(PING_TYPE_ICMP, z, 60, 1);
		ASSERT_TRUE(resolver.Start(std::string("bind [::]:60053\nserver 127.0.0.1:62153\n") +
			"server 127.0.0.1:62253\nresponse-mode fastest-response\ndualstack-ip-selection no\n"
			"speed-check-mode ping\nignore-ip " + y + "\n"));
		smartdns::Client client;
		ASSERT_TRUE(client.Query(std::string("retained.example ") + (type == DNS_T_A ? "A" : "AAAA"), 60053));
		ASSERT_EQ(client.GetAnswerNum(), 1);
		EXPECT_EQ(client.GetAnswer()[0].GetData(), z);
		// A new upstream completion proves the earlier first-reply callback has returned.
		ASSERT_TRUE(client.Query(std::string("barrier.example ") + (type == DNS_T_A ? "A" : "AAAA"), 60053));
		dns_request *held;
		dns_ip_address *node;
		{
			std::lock_guard<std::mutex> lock(lookup.lock);
			held = lookup.request; node = lookup.node;
			ASSERT_NE(held, nullptr); EXPECT_FALSE(lookup.timed_out);
		}
		unsigned char address[16] = {};
		ASSERT_EQ(inet_pton(type == DNS_T_A ? AF_INET : AF_INET6, x, address), 1);
		EXPECT_EQ(__real__dns_ip_address_get(held, address, static_cast<dns_type_t>(type)), node);
		EXPECT_EQ(atomic_read(&held->ip_map_num), 2);
		{
			std::lock_guard<std::mutex> lock(lookup.lock);
			lookup.resume = true;
		}
		lookup.ready.notify_all();
		auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
		while (atomic_read(&held->refcnt) != 1 && std::chrono::steady_clock::now() < deadline) usleep(1000);
		ASSERT_EQ(atomic_read(&held->refcnt), 1);
		EXPECT_EQ(__real__dns_ip_address_get(held, address, static_cast<dns_type_t>(type)), node);
		EXPECT_GT(node->ping_time, 0);
	}
}

TEST(FastestResponseLifetime, ReplyOwnsBoundedAddressValuesWithoutChangingCandidates)
{
	for (int type : {DNS_T_A, DNS_T_AAAA}) {
		for (bool skip_map : {false, true}) {
			SCOPED_TRACE(type); SCOPED_TRACE(skip_map);
			dns_conf_group conf{};
			dns_request request{};
			request.conf = &conf; request.qtype = static_cast<dns_type_t>(type);
			strcpy(request.domain, "values.example");
			ASSERT_EQ(pthread_mutex_init(&request.ip_map_lock, nullptr), 0);
			hash_init(request.ip_map);
			Defer {
				dns_ip_address *node; hlist_node *tmp; unsigned bucket;
				hash_for_each_safe(request.ip_map, bucket, tmp, node, node) { hash_del(&node->node); free(node); }
				pthread_mutex_destroy(&request.ip_map_lock);
			};
			unsigned char previous[16] = {0}; previous[0] = 0x11;
			dns_ip_address *existing = nullptr;
			ASSERT_EQ(_dns_ip_address_check_add(&request, request.domain, previous, request.qtype, -1, &existing), 0);
			alignas(dns_packet) unsigned char storage[DNS_PACKSIZE];
			auto *packet = reinterpret_cast<dns_packet *>(storage);
			dns_head head{}; head.qr = DNS_QR_ANSWER;
			ASSERT_EQ(dns_packet_init(packet, sizeof(storage), &head), 0);
			ASSERT_EQ(dns_add_CNAME(packet, DNS_RRS_AN, request.domain, 60, "alias.example"), 0);
			std::vector<std::array<unsigned char, 16>> expected;
			for (int i = 1; i <= MAX_IP_NUM + 2; i++) {
				std::array<unsigned char, 16> addr{};
				ASSERT_EQ(inet_pton(type == DNS_T_A ? AF_INET : AF_INET6,
					type == DNS_T_A ? "192.0.2.0" : "2001:db8::", addr.data()), 1);
				addr[type == DNS_T_A ? 3 : 15] = i;
				ASSERT_EQ(type == DNS_T_A ? dns_add_A(packet, DNS_RRS_AN, "alias.example", 60, addr.data()) :
					dns_add_AAAA(packet, DNS_RRS_AN, "alias.example", 60, addr.data()), 0);
				expected.push_back(addr);
			}
			dns_server_post_context context{};
			_dns_server_post_context_init_from(&context, &request, packet, nullptr, 0);
			context.no_check_add_ip = skip_map;
			ASSERT_EQ(_dns_server_get_answer(&context), 0);
			EXPECT_EQ(context.ip_num, MAX_IP_NUM + 2);
			EXPECT_EQ(atomic_read(&request.ip_map_num), skip_map ? 1 : MAX_IP_NUM + 3);
			EXPECT_EQ(_dns_ip_address_get(&request, previous, request.qtype), existing);
			memset(storage, 0xa5, sizeof(storage));
			for (int i = 0; i < MAX_IP_NUM; i++) EXPECT_EQ(memcmp(context.ip_addr[i], expected[i].data(), 16), 0);
		}
	}
}
