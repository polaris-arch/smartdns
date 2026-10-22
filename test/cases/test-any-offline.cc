/* Local UDP/TCP mock only. No public DNS or provider endpoints. */
#include "gtest/gtest.h"
#include "server.h"
#include "smartdns/dns.h"
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <functional>
#include <cstring>
#include <string>
#include <thread>
#include <vector>
#include <sys/socket.h>
#include <unistd.h>

namespace {
std::vector<unsigned char> local_query(int type, bool tcp = false, bool do_bit = false, bool cd = false, bool cancel = false, bool ecs = false, int port = 60053, const char *domain = "any-offline.test", const std::function<void()> &after_send = {})
{
	unsigned char parsed[DNS_PACKSIZE], request[DNS_IN_PACKSIZE], reply[DNS_IN_PACKSIZE + 2];
	dns_packet *packet = (dns_packet *)parsed;
	dns_head head{}; head.id = 0x7432; head.rd = 1; head.cd = cd;
	if (dns_packet_init(packet, sizeof(parsed), &head) || dns_add_domain(packet, domain, type, DNS_C_IN)) return {};
	if (do_bit) { dns_set_OPT_payload_size(packet, 1232); dns_set_OPT_option(packet, DNS_OPT_FLAG_DO); }
	if (ecs) {
		dns_opt_ecs subnet{}; subnet.family = DNS_OPT_ECS_FAMILY_IPV4; subnet.source_prefix = 24;
		subnet.addr[0] = 192; subnet.addr[1] = 0; subnet.addr[2] = 2;
		dns_set_OPT_payload_size(packet, 1232); dns_add_OPT_ECS(packet, &subnet);
	}
	int len = dns_encode(request, sizeof(request), packet);
	if (len <= 0) return {};
	int fd = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
	if (fd < 0) return {};
	timeval timeout{3, 0}; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port); addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(fd, (sockaddr *)&addr, sizeof(addr))) { close(fd); return {}; }
	if (tcp) {
		unsigned char size[2] = {(unsigned char)(len >> 8), (unsigned char)len};
		if (send(fd, size, 2, 0) != 2 || send(fd, request, len, 0) != len) { close(fd); return {}; }
		if (after_send) after_send();
		if (cancel) { usleep(30000); shutdown(fd, SHUT_RDWR); close(fd); return {}; }
		if (recv(fd, size, 2, MSG_WAITALL) != 2) { close(fd); return {}; }
		len = (size[0] << 8) | size[1];
		if (len > DNS_IN_PACKSIZE || recv(fd, reply, len, MSG_WAITALL) != len) len = -1;
	} else {
		if (send(fd, request, len, 0) != len) { close(fd); return {}; }
		len = recv(fd, reply, sizeof(reply), 0);
	}
	close(fd);
	return len > 0 ? std::vector<unsigned char>(reply, reply + len) : std::vector<unsigned char>{};
}
/* MockServer starts an empty response. Every successful callback must echo the
 * exact question so both client correlation and the coordinator are exercised. */
void response_question(smartdns::ServerRequestContext *r)
{
	EXPECT_EQ(dns_add_domain(r->response_packet, r->domain.c_str(), r->qtype, r->qclass), 0);
}
bool wait_until(const std::function<bool()> &condition, int milliseconds = 1000)
{
	auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
	while (!condition() && std::chrono::steady_clock::now() < deadline) usleep(1000);
	return condition();
}
::testing::AssertionResult response_is(const std::vector<unsigned char> &wire, int rcode, int answers,
	bool tc = false, int qtype = DNS_T_ANY, const char *domain = "any-offline.test")
{
	unsigned char parsed[DNS_PACKSIZE]; dns_packet *packet = (dns_packet *)parsed;
	if (wire.size() < 12 || dns_decode(packet, sizeof(parsed), (unsigned char *)wire.data(), wire.size()))
		return ::testing::AssertionFailure() << "invalid DNS response, bytes=" << wire.size();
	if (packet->head.id != 0x7432 || packet->head.qr != DNS_QR_ANSWER || packet->head.opcode != DNS_OP_QUERY ||
		packet->head.rcode != rcode || packet->head.tc != tc || packet->head.ancount != answers)
		return ::testing::AssertionFailure() << "unexpected header: rcode=" << packet->head.rcode
			<< " answers=" << packet->head.ancount << " tc=" << packet->head.tc;
	int count = 0, type = 0, qclass = 0; char name[DNS_MAX_CNAME_LEN];
	dns_rrs *question = dns_get_rrs_start(packet, DNS_RRS_QD, &count);
	if (count != 1 || !question || dns_get_domain(question, name, sizeof(name), &type, &qclass) ||
		strcmp(name, domain) || type != qtype || qclass != DNS_C_IN)
		return ::testing::AssertionFailure() << "response question does not match request";
	return ::testing::AssertionSuccess();
}
/* Decode fixture RDATA directly: dns_get_TXT is an upstream stub. This also
 * verifies on-wire text lengths/content instead of accepting a packet by size. */
bool read_wire_name(const std::vector<unsigned char> &wire, size_t &offset, std::string &name)
{
	size_t at = offset; bool jumped = false; name.clear();
	for (unsigned int hops = 0; hops < 128 && at < wire.size(); hops++) {
		unsigned int size = wire[at++];
		if ((size & 0xc0) == 0xc0) {
			if (at >= wire.size()) return false;
			unsigned int target = ((size & 0x3f) << 8) | wire[at++];
			if (target < 12 || target >= at - 2) return false;
			if (!jumped) offset = at;
			jumped = true; at = target; continue;
		}
		if (size > 63 || at + size > wire.size()) return false;
		if (!size) { if (!jumped) offset = at; return true; }
		if (!name.empty()) name += '.';
		name.append((const char *)wire.data() + at, size); at += size;
	}
	return false;
}
::testing::AssertionResult answer_is(const std::vector<unsigned char> &wire,
	const std::vector<std::string> &addresses, const std::vector<std::string> &texts = {},
	int qtype = DNS_T_ANY, const char *domain = "any-offline.test")
{
	auto valid = response_is(wire, DNS_RC_NOERROR, addresses.size() + texts.size(), false, qtype, domain);
	if (!valid) return valid;
	size_t offset = 12; std::string name;
	if (!read_wire_name(wire, offset, name) || offset + 4 > wire.size()) return ::testing::AssertionFailure();
	offset += 4;
	std::vector<std::string> actual_addresses, actual_texts;
	for (size_t i = 0; i < addresses.size() + texts.size(); i++) {
		if (!read_wire_name(wire, offset, name) || name != domain || offset + 10 > wire.size())
			return ::testing::AssertionFailure() << "invalid answer owner/header";
		unsigned int type = (wire[offset] << 8) | wire[offset + 1];
		unsigned int qclass = (wire[offset + 2] << 8) | wire[offset + 3];
		uint32_t ttl = ((uint32_t)wire[offset + 4] << 24) | ((uint32_t)wire[offset + 5] << 16) |
			(wire[offset + 6] << 8) | wire[offset + 7];
		unsigned int size = (wire[offset + 8] << 8) | wire[offset + 9]; offset += 10;
		if (qclass != DNS_C_IN || !ttl || offset + size > wire.size())
			return ::testing::AssertionFailure() << "invalid answer class/TTL/length";
		if (type == DNS_T_A && size == 4) {
			char text[INET_ADDRSTRLEN];
			if (!inet_ntop(AF_INET, wire.data() + offset, text, sizeof(text))) return ::testing::AssertionFailure();
			actual_addresses.emplace_back(text);
		} else if (type == DNS_T_TXT) {
			std::string text;
			for (size_t at = offset; at < offset + size;) {
				unsigned int segment = wire[at++];
				if (at + segment > offset + size) return ::testing::AssertionFailure() << "invalid TXT segment";
				text.append((const char *)wire.data() + at, segment); at += segment;
			}
			actual_texts.push_back(text);
		} else return ::testing::AssertionFailure() << "unexpected answer type " << type;
		offset += size;
	}
	if (actual_addresses != addresses || actual_texts != texts)
		return ::testing::AssertionFailure() << "answer RDATA differs";
	return ::testing::AssertionSuccess();
}
std::string configuration(const std::string &extra = "", const std::string &server_options = "")
{
	return "bind 127.0.0.1:60053\nbind-tcp 127.0.0.1:60053\nserver 127.0.0.1:61053" + server_options + "\ncache-size 256\n"
		"resolv-hostname no\nlocal-ptr-enable no\nspeed-check-mode none\ndualstack-ip-selection no\n" + extra;
}
std::string aggregate(const std::string &extra = "")
{
	return configuration("any-response-mode aggregate\nany-aggregate-types A,TXT\n" + extra);
}
}

TEST(AnyOffline, DefaultPassthroughDoesNotExpandRefused)
{
	std::atomic<int> any{0}, typed{0}; smartdns::MockServer upstream; smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		if (r->qtype == DNS_T_ANY) any++; else typed++;
		r->response_packet->head.rcode = DNS_RC_REFUSED; return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(configuration())); auto result = local_query(DNS_T_ANY);
	EXPECT_TRUE(response_is(result, DNS_RC_REFUSED, 0)); EXPECT_EQ(any, 1); EXPECT_EQ(typed, 0);
}

TEST(AnyOffline, MinimalSuccessStopsAndExactCacheAvoidsSecondProbe)
{
	std::atomic<int> any{0}, typed{0}; smartdns::MockServer upstream; smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		if (r->qtype == DNS_T_ANY) any++; else typed++;
		unsigned char ip[4] = {1, 2, 3, 4}; dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, ip);
		return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(aggregate("cache-size -1\n")));
	EXPECT_TRUE(answer_is(local_query(DNS_T_ANY), {"1.2.3.4"})); EXPECT_TRUE(answer_is(local_query(DNS_T_ANY), {"1.2.3.4"}));
	EXPECT_EQ(any, 1); EXPECT_EQ(typed, 0);
}

TEST(AnyOffline, RefusedExpandsExactlyConfiguredTypesAndCaches)
{
	std::atomic<int> any{0}, a{0}, txt{0}, other{0}; smartdns::MockServer upstream; smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		if (r->qtype == DNS_T_ANY) { any++; r->response_packet->head.rcode = DNS_RC_REFUSED; }
		else if (r->qtype == DNS_T_A) { a++; unsigned char ip[4] = {1, 2, 3, 4}; dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, ip); }
		else if (r->qtype == DNS_T_TXT) { txt++; dns_add_TXT(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 90, "local"); }
		else other++;
		return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(aggregate())); auto result = local_query(DNS_T_ANY);
	ASSERT_TRUE(answer_is(result, {"1.2.3.4"}, {"local"})); EXPECT_EQ(result[3] & 32, 0);
	EXPECT_TRUE(answer_is(local_query(DNS_T_ANY), {"1.2.3.4"}, {"local"}));
	EXPECT_EQ(any, 1); EXPECT_EQ(a, 1); EXPECT_EQ(txt, 1); EXPECT_EQ(other, 0);
}

/* Exercise the last bounded payload slot as well as passthrough with dormant
 * configured types. The coordinator must not allocate/use typed buffers there. */
TEST(AnyOffline, PayloadStorageCoversMaximumTypesAndPassthrough)
{
	for (bool expand : {false, true}) {
		SCOPED_TRACE(expand ? "eight typed payloads" : "one probe payload");
		std::atomic<int> probes{0}, typed{0}; smartdns::MockServer upstream; smartdns::Server server;
		ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
			response_question(r);
			if (r->qtype == DNS_T_ANY) { probes++; r->response_packet->head.rcode = DNS_RC_REFUSED; }
			else {
				typed++; r->response_packet->head.rcode = DNS_RC_NXDOMAIN;
				dns_soa soa{};
				std::strcpy(soa.mname, "ns.any-offline.test");
				std::strcpy(soa.rname, "hostmaster.any-offline.test");
				soa.serial = 1; soa.minimum = 60;
				EXPECT_EQ(dns_add_SOA(r->response_packet, DNS_RRS_NS, "any-offline.test", 60, &soa), 0);
			}
			return smartdns::SERVER_REQUEST_OK;
		}));
		ASSERT_TRUE(server.Start(configuration(std::string("cache-size 0\nany-response-mode ") +
			(expand ? "aggregate" : "passthrough") +
			"\nany-aggregate-types A,AAAA,NS,SOA,PTR,MX,TXT,SRV\n"
			"any-aggregate-max-attempts 16\nany-aggregate-concurrency 8\nany-aggregate-timeout-ms 950\n")));
		EXPECT_TRUE(response_is(local_query(DNS_T_ANY), expand ? DNS_RC_NXDOMAIN : DNS_RC_REFUSED, 0));
		EXPECT_EQ(probes, 1); EXPECT_EQ(typed, expand ? 8 : 0);
	}
}

TEST(AnyOffline, CacheSizeZeroRepeatsPassthroughUpstreamLookup)
{
	std::atomic<int> any{0}, other{0}; smartdns::MockServer upstream; smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		if (r->qtype == DNS_T_ANY) any++; else other++;
		unsigned char ip[4] = {1, 2, 3, 4}; dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, ip);
		return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(configuration("cache-size 0\n")));
	for (int expected = 1; expected <= 2; expected++) {
		ASSERT_TRUE(answer_is(local_query(DNS_T_ANY), {"1.2.3.4"}));
		EXPECT_EQ(any, expected); EXPECT_EQ(other, 0);
	}
}

TEST(AnyOffline, CacheSizeZeroRepeatsAggregateProbeAndChildren)
{
	std::atomic<int> any{0}, a{0}, txt{0}, other{0}; smartdns::MockServer upstream; smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		if (r->qtype == DNS_T_ANY) { any++; r->response_packet->head.rcode = DNS_RC_REFUSED; }
		else if (r->qtype == DNS_T_A) { a++; unsigned char ip[4] = {1, 2, 3, 4}; dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, ip); }
		else if (r->qtype == DNS_T_TXT) { txt++; dns_add_TXT(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 90, "local"); }
		else other++;
		return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(aggregate("cache-size 0\nany-aggregate-timeout-ms 250\n")));
	for (int expected = 1; expected <= 2; expected++) {
		// Let the existing 100 ms loop enter its one-second idle wait. END
		// notifications must resume the three-send aggregate inside its own
		// 250 ms budget, without waiting for that previously armed idle timer.
		usleep(250000);
		ASSERT_TRUE(answer_is(local_query(DNS_T_ANY), {"1.2.3.4"}, {"local"}));
		EXPECT_EQ(any, expected); EXPECT_EQ(a, expected); EXPECT_EQ(txt, expected); EXPECT_EQ(other, 0);
	}
}

TEST(AnyOffline, OneSendBudgetIncludesProbeAndCannotStartTypedWireWork)
{
	std::atomic<int> sent{0}; smartdns::MockServer upstream; smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		sent++; r->response_packet->head.rcode = DNS_RC_REFUSED; return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(aggregate("any-aggregate-max-attempts 1\n"))); auto result = local_query(DNS_T_ANY);
	EXPECT_TRUE(response_is(result, DNS_RC_SERVFAIL, 0)); EXPECT_EQ(sent, 1);
}

TEST(AnyOffline, DoAndCdBypassNewAggregationAndSharing)
{
	std::atomic<int> any{0}, typed{0}, saw_do{0}, saw_cd{0}; smartdns::MockServer upstream; smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		if (r->qtype == DNS_T_ANY) any++; else typed++;
		if (dns_get_OPT_option(r->packet) & DNS_OPT_FLAG_DO) saw_do++;
		if (r->packet->head.cd) saw_cd++;
		unsigned char ip[4] = {1, 2, 3, 4}; dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, ip);
		return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(aggregate()));
	for (int i = 0; i < 2; i++) {
		EXPECT_TRUE(answer_is(local_query(DNS_T_ANY, false, true), {"1.2.3.4"}));
		EXPECT_TRUE(answer_is(local_query(DNS_T_ANY, false, false, true), {"1.2.3.4"}));
	}
	EXPECT_EQ(any, 4); EXPECT_EQ(typed, 0); EXPECT_EQ(saw_do, 2); EXPECT_EQ(saw_cd, 2);
}

TEST(AnyOffline, OrdinaryAQueryHasNoAnyExpansion)
{
	std::atomic<int> a{0}, other{0}; smartdns::MockServer upstream; smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		if (r->qtype == DNS_T_A) a++; else other++;
		unsigned char ip[4] = {1, 2, 3, 4}; dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, ip); return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(aggregate())); EXPECT_TRUE(answer_is(local_query(DNS_T_A), {"1.2.3.4"}, {}, DNS_T_A)); EXPECT_EQ(a, 1); EXPECT_EQ(other, 0);
}

TEST(AnyOffline, DuplicateCallersShareOneBoundedOperation)
{
	std::atomic<int> any{0}; smartdns::MockServer upstream; smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		if (r->qtype == DNS_T_ANY) any++;
		usleep(50000); unsigned char ip[4] = {1, 2, 3, 4}; dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, ip); return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(aggregate("cache-size 0\n"))); std::vector<std::thread> threads; std::atomic<int> replies{0};
	for (int i = 0; i < 8; i++) threads.emplace_back([&] { auto result = local_query(DNS_T_ANY); EXPECT_TRUE(answer_is(result, {"1.2.3.4"})); if (answer_is(result, {"1.2.3.4"})) replies++; });
	for (auto &thread : threads) thread.join(); EXPECT_EQ(replies, 8); EXPECT_EQ(any, 1);
	// Disabling completed-result caching must not disable in-flight coalescing.
	EXPECT_TRUE(answer_is(local_query(DNS_T_ANY), {"1.2.3.4"})); EXPECT_EQ(any, 2);
}

TEST(AnyOffline, UdpTcAndTcpRetryUseTheSameCompleteSnapshot)
{
	std::atomic<int> sends{0}; smartdns::MockServer upstream; smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		sends++;
		if (r->qtype == DNS_T_ANY) r->response_packet->head.rcode = DNS_RC_NOTIMP;
		else if (r->qtype == DNS_T_A) { unsigned char ip[4] = {1, 2, 3, 4}; dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, ip); }
		else for (int i = 0; i < 8; i++) { std::string value(100, 'a' + i); dns_add_TXT(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, value.c_str()); }
		return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(aggregate())); auto udp = local_query(DNS_T_ANY);
	EXPECT_TRUE(response_is(udp, DNS_RC_NOERROR, 0, true)); EXPECT_LE(udp.size(), 512U);
	auto tcp = local_query(DNS_T_ANY, true); ASSERT_GT(tcp.size(), 512U);
	std::vector<std::string> texts; for (int i = 0; i < 8; i++) texts.emplace_back(100, 'a' + i);
	EXPECT_TRUE(answer_is(tcp, {"1.2.3.4"}, texts)); EXPECT_EQ(sends, 3);
}

TEST(AnyOffline, CancelledTcpWaiterDoesNotCancelSharedUdpWork)
{
	std::atomic<int> any{0}; smartdns::MockServer upstream; smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		if (r->qtype == DNS_T_ANY) any++;
		usleep(100000); unsigned char ip[4] = {1, 2, 3, 4}; dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, ip); return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(aggregate())); std::vector<unsigned char> response;
	std::thread waiter([&] { response = local_query(DNS_T_ANY); });
	EXPECT_TRUE(wait_until([&] { return any.load() == 1; }));
	bool submitted = false;
	local_query(DNS_T_ANY, true, false, false, true, false, 60053, "any-offline.test", [&] { submitted = true; });
	waiter.join(); EXPECT_TRUE(submitted);
	EXPECT_TRUE(answer_is(response, {"1.2.3.4"})); EXPECT_EQ(any, 1);
}

TEST(AnyOffline, LastWaiterCancellationDoesNotStartTypedFallback)
{
	std::atomic<int> any{0}, typed{0}; smartdns::MockServer upstream; smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		if (r->qtype == DNS_T_ANY) any++; else typed++;
		usleep(100000); r->response_packet->head.rcode = DNS_RC_REFUSED; return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(aggregate()));
	local_query(DNS_T_ANY, true, false, false, true, false, 60053, "any-offline.test", [&] {
		EXPECT_TRUE(wait_until([&] { return any.load() == 1; }));
	});
	usleep(300000);
	EXPECT_EQ(any, 1); EXPECT_EQ(typed, 0);
}

TEST(AnyOffline, EcsRequestBypassesAggregateAndSharedCache)
{
	std::atomic<int> any{0}, typed{0}; smartdns::MockServer upstream; smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		if (r->qtype == DNS_T_ANY) any++; else typed++;
		unsigned char ip[4] = {1, 2, 3, 4}; dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, ip);
		return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(aggregate()));
	EXPECT_TRUE(answer_is(local_query(DNS_T_ANY, false, false, false, false, true), {"1.2.3.4"}));
	EXPECT_TRUE(answer_is(local_query(DNS_T_ANY, false, false, false, false, true), {"1.2.3.4"}));
	EXPECT_EQ(typed, 0); EXPECT_EQ(any, 2);
}

TEST(AnyOffline, SameQuestionOnDifferentRoutesCannotShareCachedAnswer)
{
	std::atomic<int> first{0}, second{0}; smartdns::MockServer one, two; smartdns::Server server;
	ASSERT_TRUE(one.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		first++; unsigned char ip[4] = {1, 2, 3, 4}; dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, ip); return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(two.Start("udp://127.0.0.1:61054", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		second++; unsigned char ip[4] = {5, 6, 7, 8}; dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, ip); return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start("bind 127.0.0.1:60053 -group one\nbind 127.0.0.1:60054 -group two\n"
		"server 127.0.0.1:61053 -group one -exclude-default-group\nserver 127.0.0.1:61054 -group two -exclude-default-group\n"
		"cache-size 256\nresolv-hostname no\nlocal-ptr-enable no\nspeed-check-mode none\ndualstack-ip-selection no\n"));
	auto a = local_query(DNS_T_ANY), b = local_query(DNS_T_ANY, false, false, false, false, false, 60054);
	EXPECT_TRUE(answer_is(a, {"1.2.3.4"})); EXPECT_TRUE(answer_is(b, {"5.6.7.8"}));
	EXPECT_EQ(first, 1); EXPECT_EQ(second, 1);
}

TEST(AnyOffline, SlowProbeConsumesTheTypedFallbackDeadline)
{
	std::atomic<int> probes{0}, typed{0}; smartdns::MockServer upstream; smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		if (r->qtype == DNS_T_ANY) probes++; else typed++;
		usleep(150000); r->response_packet->head.rcode = DNS_RC_REFUSED; return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(aggregate("any-aggregate-timeout-ms 50\n")));
	auto result = local_query(DNS_T_ANY); EXPECT_TRUE(response_is(result, DNS_RC_SERVFAIL, 0));
	usleep(200000); EXPECT_EQ(probes, 1); EXPECT_EQ(typed, 0);
}

TEST(AnyOffline, OneClientCannotOwnAllCoordinatorSlots)
{
	std::atomic<int> sends{0}, ready{0}; std::atomic<bool> go{false};
	smartdns::MockServer upstream; smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		if (r->qtype == DNS_T_ANY) sends++;
		/* Count every admitted datagram immediately; sleeping in this serial
		 * mock would hide excess sends in its socket queue. */
		return smartdns::SERVER_REQUEST_NO_RESPONSE;
	}));
	ASSERT_TRUE(server.Start(aggregate("any-aggregate-max-attempts 1\n")));
	std::vector<std::thread> threads; std::atomic<int> replies{0}, rejected{0};
	for (int i = 0; i < 12; i++) threads.emplace_back([&, i] {
		ready++; while (!go) std::this_thread::yield();
		std::string domain = "name" + std::to_string(i) + ".any-offline.test";
		auto response = local_query(DNS_T_ANY, false, false, false, false, false, 60053, domain.c_str());
		bool positive = answer_is(response, {"1.2.3.4"}, {}, DNS_T_ANY, domain.c_str());
		bool failure = response_is(response, DNS_RC_SERVFAIL, 0, false, DNS_T_ANY, domain.c_str());
		EXPECT_TRUE(positive || failure); if (positive || failure) replies++; if (failure) rejected++;
	});
	while (ready != 12) std::this_thread::yield(); go = true;
	for (auto &thread : threads) thread.join();
	EXPECT_EQ(replies, 12); EXPECT_EQ(rejected, 12); EXPECT_EQ(sends, 8);
}


TEST(AnyOffline, DefaultFailureFirstCannotMaskHealthySibling)
{
	for (int failure : {DNS_RC_REFUSED, DNS_RC_SERVFAIL, DNS_RC_NOTIMP}) {
		SCOPED_TRACE(failure);
		std::atomic<int> failed{0}, healthy{0}, typed{0};
		smartdns::MockServer one, two; smartdns::Server server;
		ASSERT_TRUE(one.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
			response_question(r); failed++; if (r->qtype != DNS_T_ANY) typed++;
			r->response_packet->head.rcode = failure; return smartdns::SERVER_REQUEST_OK;
		}));
		ASSERT_TRUE(two.Start("udp://127.0.0.1:61054", [&](smartdns::ServerRequestContext *r) {
			response_question(r); healthy++; if (r->qtype != DNS_T_ANY) typed++;
			usleep(100000); unsigned char ip[4] = {1, 2, 3, 4};
			dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, ip);
			return smartdns::SERVER_REQUEST_OK;
		}));
		ASSERT_TRUE(server.Start(configuration("server 127.0.0.1:61054\n")));
		EXPECT_TRUE(answer_is(local_query(DNS_T_ANY), {"1.2.3.4"}));
		EXPECT_TRUE(answer_is(local_query(DNS_T_ANY), {"1.2.3.4"}));
		EXPECT_EQ(failed, 1); EXPECT_EQ(healthy, 1); EXPECT_EQ(typed, 0);
	}
}

TEST(AnyOffline, DefaultAllFailuresRetainTheFirstBoundedResponse)
{
	std::atomic<int> first{0}, second{0}; smartdns::MockServer one, two; smartdns::Server server;
	ASSERT_TRUE(one.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r); first++; r->response_packet->head.rcode = DNS_RC_REFUSED;
		return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(two.Start("udp://127.0.0.1:61054", [&](smartdns::ServerRequestContext *r) {
		response_question(r); second++; usleep(100000); r->response_packet->head.rcode = DNS_RC_SERVFAIL;
		return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(configuration("server 127.0.0.1:61054\n")));
	EXPECT_TRUE(response_is(local_query(DNS_T_ANY), DNS_RC_REFUSED, 0));
	EXPECT_EQ(first, 1); EXPECT_EQ(second, 1);
}

TEST(AnyOffline, DefaultLastWaiterCancellationStopsDeferredAdmission)
{
	std::atomic<int> warm{0}, cancelled{0}, live{0}; smartdns::MockServer upstream; smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		if (r->domain == "warm.any-offline.test") warm++;
		else if (r->domain == "cancel.any-offline.test") cancelled++;
		else live++;
		unsigned char ip[4] = {1, 2, 3, 4}; dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, ip);
		return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(configuration("", " -max-query-rate 1 -query-burst 1")));
	EXPECT_TRUE(answer_is(local_query(DNS_T_ANY, false, false, false, false, false, 60053, "warm.any-offline.test"),
		{"1.2.3.4"}, {}, DNS_T_ANY, "warm.any-offline.test"));
	ASSERT_EQ(warm, 1);
	bool submitted = false;
	local_query(DNS_T_ANY, true, false, false, true, false, 60053, "cancel.any-offline.test", [&] { submitted = true; });
	ASSERT_TRUE(submitted);
	usleep(1200000); /* token refills well before the ordinary 2s query deadline */
	EXPECT_EQ(cancelled, 0);
	EXPECT_TRUE(answer_is(local_query(DNS_T_ANY, false, false, false, false, false, 60053, "live.any-offline.test"),
		{"1.2.3.4"}, {}, DNS_T_ANY, "live.any-offline.test"));
	EXPECT_EQ(live, 1); EXPECT_EQ(cancelled, 0);
}

TEST(AnyOffline, DefaultLastWaiterCancellationStopsRetry)
{
	std::atomic<int> cancelled{0}, live{0}; smartdns::MockServer upstream; smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r);
		if (r->domain == "cancel.any-offline.test") { cancelled++; return smartdns::SERVER_REQUEST_NO_RESPONSE; }
		live++; unsigned char ip[4] = {1, 2, 3, 4}; dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, ip);
		return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(configuration()));
	local_query(DNS_T_ANY, true, false, false, true, false, 60053, "cancel.any-offline.test", [&] {
		EXPECT_TRUE(wait_until([&] { return cancelled.load() == 1; }));
	});
	usleep(1200000); /* spans two ordinary 500ms retry opportunities */
	EXPECT_EQ(cancelled, 1);
	EXPECT_TRUE(answer_is(local_query(DNS_T_ANY, false, false, false, false, false, 60053, "live.any-offline.test"),
		{"1.2.3.4"}, {}, DNS_T_ANY, "live.any-offline.test"));
	EXPECT_EQ(live, 1);
}


TEST(AnyOffline, DefaultFailureWaitsForDeferredHealthySibling)
{
	std::atomic<int> failed{0}, healthy{0}; smartdns::MockServer one, two; smartdns::Server server;
	ASSERT_TRUE(one.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r); failed++; r->response_packet->head.rcode = DNS_RC_REFUSED;
		return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(two.Start("udp://127.0.0.1:61054", [&](smartdns::ServerRequestContext *r) {
		response_question(r); healthy++; unsigned char ip[4] = {1, 2, 3, 4};
		dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, ip);
		return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(configuration("server 127.0.0.1:61054 -group warm -max-query-rate 2 -query-burst 1\n"
		"nameserver /warm.any-offline.test/warm\n")));
	EXPECT_TRUE(answer_is(local_query(DNS_T_ANY, false, false, false, false, false, 60053, "warm.any-offline.test"),
		{"1.2.3.4"}, {}, DNS_T_ANY, "warm.any-offline.test"));
	ASSERT_EQ(healthy, 1); ASSERT_EQ(failed, 0);
	/* The second endpoint's token is empty; failure from the first cannot end
	 * the operation before that healthy sibling becomes admissible. */
	EXPECT_TRUE(answer_is(local_query(DNS_T_ANY), {"1.2.3.4"}));
	EXPECT_EQ(healthy, 2); EXPECT_EQ(failed, 1);
}

TEST(AnyOffline, DefaultRefusalCannotMaskMinimalHinfoSibling)
{
	std::atomic<int> failed{0}, healthy{0}, typed{0}; smartdns::MockServer one, two; smartdns::Server server;
	ASSERT_TRUE(one.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		response_question(r); failed++; if (r->qtype != DNS_T_ANY) typed++;
		r->response_packet->head.rcode = DNS_RC_REFUSED; return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(two.Start("udp://127.0.0.1:61054", [&](smartdns::ServerRequestContext *r) {
		response_question(r); healthy++; if (r->qtype != DNS_T_ANY) typed++; usleep(100000);
		/* SmartDNS has no HINFO builder. Encode the correlated question and
		 * append a standard RFC8482-style HINFO RR with two character strings. */
		int len = dns_encode(r->response_data, r->response_data_max_len, r->response_packet);
		const unsigned char hinfo[] = {0xc0, 0x0c, 0, 13, 0, 1, 0, 0, 0, 60, 0, 9,
			7, 'R', 'F', 'C', '8', '4', '8', '2', 0};
		if (len < 12 || len + (int)sizeof(hinfo) > r->response_data_max_len) return smartdns::SERVER_REQUEST_ERROR;
		memcpy(r->response_data + len, hinfo, sizeof(hinfo)); r->response_data[7] = 1;
		r->response_data_len = len + sizeof(hinfo); return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start(configuration("server 127.0.0.1:61054\n")));
	auto response = local_query(DNS_T_ANY); ASSERT_TRUE(response_is(response, DNS_RC_NOERROR, 1));
	size_t offset = 12; std::string name;
	ASSERT_TRUE(read_wire_name(response, offset, name)); offset += 4;
	ASSERT_TRUE(read_wire_name(response, offset, name)); ASSERT_EQ(name, "any-offline.test");
	const std::vector<unsigned char> expected = {0, 13, 0, 1, 0, 0, 0, 60, 0, 9, 7, 'R', 'F', 'C', '8', '4', '8', '2', 0};
	EXPECT_EQ(std::vector<unsigned char>(response.begin() + offset, response.end()), expected);
	EXPECT_EQ(failed, 1); EXPECT_EQ(healthy, 1); EXPECT_EQ(typed, 0);
}

namespace {
void default_passthrough_burst(bool unique)
{
	constexpr int count = 40; // Exceeds both the 8-operation and 32-waiter coordinator caps.
	std::atomic<int> submitted{0};
	std::atomic<bool> first{true};
	smartdns::MockServer upstream; smartdns::Server server;
	ASSERT_TRUE(upstream.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) {
		EXPECT_TRUE(wait_until([&] { return submitted.load() == count; }));
		// Keep the first reply pending while the server admits the queued burst.
		if (first.exchange(false)) usleep(25000);
		response_question(r);
		unsigned char ip[4] = {1, 2, 3, 4};
		dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, ip);
		return smartdns::SERVER_REQUEST_OK;
	}));
	ASSERT_TRUE(server.Start("bind 127.0.0.1:60053\nserver 127.0.0.1:61053\ncache-size 0\n"));
	std::vector<int> sockets;
	std::vector<std::string> domains;
	// Publish the entire burst before receiving anything. Separate sockets keep
	// response IDs identical to the existing exact-response assertion helper.
	for (int i = 0; i < count; i++) {
		std::string domain = unique ? "burst-" + std::to_string(i) + ".test" : "burst-duplicate.test";
		unsigned char parsed[DNS_PACKSIZE], wire[DNS_IN_PACKSIZE];
		dns_packet *packet = (dns_packet *)parsed;
		dns_head head{}; head.id = 0x7432; head.rd = 1;
		EXPECT_EQ(dns_packet_init(packet, sizeof(parsed), &head), 0);
		EXPECT_EQ(dns_add_domain(packet, domain.c_str(), DNS_T_ANY, DNS_C_IN), 0);
		int len = dns_encode(wire, sizeof(wire), packet);
		int fd = socket(AF_INET, SOCK_DGRAM, 0);
		EXPECT_GE(fd, 0); EXPECT_GT(len, 0);
		if (fd < 0) { submitted++; continue; }
		timeval timeout{3, 0};
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		sockaddr_in address{}; address.sin_family = AF_INET;
		address.sin_port = htons(60053); address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		EXPECT_EQ(connect(fd, (sockaddr *)&address, sizeof(address)), 0);
		if (len > 0) EXPECT_EQ(send(fd, wire, len, 0), len);
		sockets.push_back(fd); domains.push_back(domain); submitted++;
	}
	EXPECT_EQ(sockets.size(), count);
	for (size_t i = 0; i < sockets.size(); i++) {
		unsigned char wire[DNS_IN_PACKSIZE];
		int len = recv(sockets[i], wire, sizeof(wire), 0);
		close(sockets[i]);
		std::vector<unsigned char> response;
		if (len > 0) response.assign(wire, wire + len);
		EXPECT_TRUE(response_is(response, DNS_RC_NOERROR, 1, false, DNS_T_ANY, domains[i].c_str()));
	}
}
} // namespace

TEST(AnyOffline, DefaultDuplicateBurstFallsBackToNativeWhenCoordinatorFull)
{
	default_passthrough_burst(false);
}

TEST(AnyOffline, DefaultUniqueBurstFallsBackToNativeWhenCoordinatorFull)
{
	default_passthrough_burst(true);
}

TEST(UpstreamRoundRobinWire, TwoBackendSerialFairnessAndLegacyFanout) {
    for (int cap : {0, 1, 2}) for (bool compatibility : {false, true}) {
        if (!cap && compatibility) continue;
        SCOPED_TRACE(cap);
        SCOPED_TRACE(compatibility);
        std::atomic<int> a{0}, b{0};
        std::atomic<int> first_port{0}, second_port{0};
        smartdns::MockServer first, second;
        smartdns::Server server;
        auto reply = [&](smartdns::ServerRequestContext *r, std::atomic<int> &counter,
                         std::atomic<int> &previous_port) {
            EXPECT_EQ(r->from->ss_family, AF_INET);
            const int port = ntohs(reinterpret_cast<sockaddr_in *>(r->from)->sin_port);
            EXPECT_GT(port, 0);
            const int previous = previous_port.exchange(port);
            // Two physical slots retain each endpoint's UDP socket. With one
            // slot, idle eviction is expected; do not confuse slots with IP count.
            if (previous && cap != 1) EXPECT_EQ(port, previous);
            counter++;
            response_question(r);
            unsigned char ip[4] = {192, 0, 2, 9};
            EXPECT_EQ(dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), 60, ip), 0);
            return smartdns::SERVER_REQUEST_OK;
        };
        ASSERT_TRUE(first.Start("udp://127.0.0.1:61053", [&](smartdns::ServerRequestContext *r) { return reply(r, a, first_port); }));
        ASSERT_TRUE(second.Start("udp://127.0.0.2:61053", [&](smartdns::ServerRequestContext *r) { return reply(r, b, second_port); }));
        std::string upstreams;
        if (!cap) {
            upstreams = "server 127.0.0.1:61053 -quota-group wire-rr\n"
                        "server 127.0.0.2:61053 -quota-group wire-rr\n";
        } else if (compatibility) {
            const std::string options = " -quota-group wire-rr -upstream-round-robin -max-upstream-connections " + std::to_string(cap);
            upstreams = "server rr-provider.test:61053 -host-ip 127.0.0.1" + options + "\n"
                        "server rr-provider.test:61053 -host-ip 127.0.0.2" + options + "\n";
        } else {
            upstreams = "server rr-provider.test:61053 -upstream-ip-pool -host-ip 127.0.0.1,127.0.0.2"
                        " -max-upstream-connections " + std::to_string(cap) + "\n";
        }
        ASSERT_TRUE(server.Start("bind 127.0.0.1:60053\ncache-size 0\nprefetch-domain no\n"
            "speed-check-mode none\ndualstack-ip-selection no\n" + upstreams));
        for (int i = 0; i < 6; i++) {
            auto name = "rr-" + std::to_string(i) + ".test";
            auto answer = local_query(DNS_T_A, false, false, false, false, false, 60053, name.c_str());
            ASSERT_TRUE(response_is(answer, DNS_RC_NOERROR, 1, false, DNS_T_A, name.c_str()));
            if (cap) {
                EXPECT_EQ(a + b, i + 1);
                EXPECT_LE(abs(a.load() - b.load()), 1);
            } else ASSERT_TRUE(wait_until([&] { return a == i + 1 && b == i + 1; }));
        }
        EXPECT_EQ(a, cap ? 3 : 6); EXPECT_EQ(b, cap ? 3 : 6);
    }
}

TEST(UpstreamRoundRobinWire, AmbiguousNumericLegacyConfigurationRequiresExplicitMigration) {
    smartdns::Server server;
    EXPECT_FALSE(server.Start("bind 127.0.0.1:60053\n"
        "server 127.0.0.1:61053 -quota-group wire-rr -upstream-round-robin -max-upstream-connections 1\n"
        "server 127.0.0.1:61054 -quota-group wire-rr -upstream-round-robin -max-upstream-connections 1\n"));
}
