/* Address-mode regressions use loopback DNS fixtures only. No public DNS,
 * provider endpoints, dig, subprocess sleeps, or network-dependent assertions.
 *
 * This file deliberately parses both A and AAAA RDATA. Counting answers or
 * reusing the aggregate A/TXT helper would miss the single-family regression. */
#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>
#include "gtest/gtest.h"
#include "server.h"
#include "smartdns/dns.h"
#include "smartdns/dns_cache.h"

namespace {
using Wire = std::vector<unsigned char>;
constexpr int kClientPort = 60055;
constexpr int kUpstreamPort = 61055;
constexpr uint16_t kQueryId = 0x6a71;
const char *const kDomain = "address-mode.test";
const char *const kMarker = "barrier.address-mode.test";
const char *const kIPv4 = "192.0.2.17";
const char *const kIPv6 = "2001:db8::17";
const char *const kSlowIPv4 = "192.0.2.18";
const char *const kSlowIPv6 = "2001:db8::18";

uint16_t u16(const Wire &wire, size_t at)
{
	return (static_cast<uint16_t>(wire[at]) << 8) | wire[at + 1];
}

uint32_t u32(const Wire &wire, size_t at)
{
	return (static_cast<uint32_t>(wire[at]) << 24) | (static_cast<uint32_t>(wire[at + 1]) << 16) |
		(static_cast<uint32_t>(wire[at + 2]) << 8) | wire[at + 3];
}

bool wire_name(const Wire &wire, size_t &offset, std::string &name)
{
	size_t at = offset;
	bool jumped = false;
	name.clear();
	for (unsigned int hops = 0; hops < 128 && at < wire.size(); ++hops) {
		unsigned int length = wire[at++];
		if ((length & 0xc0) == 0xc0) {
			if (at >= wire.size()) return false;
			size_t target = ((length & 0x3f) << 8) | wire[at++];
			if (target < 12 || target >= at - 2) return false;
			if (!jumped) offset = at;
			jumped = true;
			at = target;
			continue;
		}
		if (length > 63 || at + length > wire.size()) return false;
		if (!length) {
			if (!jumped) offset = at;
			return name.size() < DNS_MAX_CNAME_LEN;
		}
		if (!name.empty()) name += '.';
		name.append(reinterpret_cast<const char *>(wire.data() + at), length);
		at += length;
	}
	return false;
}

/* Canonical strings compare RR sets without imposing A-before-AAAA ordering.
 * Duplicates remain visible because this is a vector, rather than a set. */
std::string address_rr(int type, const std::string &owner = kDomain)
{
	return owner + (type == DNS_T_A ? " A " : " AAAA ") + (type == DNS_T_A ? kIPv4 : kIPv6);
}

std::string cname_rr(const std::string &owner, const std::string &target)
{
	return owner + " CNAME " + target;
}

::testing::AssertionResult response_is(const Wire &wire, int rcode, std::vector<std::string> answers,
	int authority = 0, uint16_t id = kQueryId, int qtype = DNS_T_ANY, const std::string &domain = kDomain,
	uint32_t min_address_ttl = 1, uint32_t max_address_ttl = UINT32_MAX, const Wire &expected_options = {},
	bool local_soa = false)
{
	if (wire.size() < 12) return ::testing::AssertionFailure() << "missing DNS response: " << wire.size() << " bytes";
	/* All bits are checked: QR, opcode, AA, TC, RD, RA, Z, AD, CD and rcode. */
	const uint16_t flags = 0x8180 | rcode;
	if (u16(wire, 0) != id || u16(wire, 2) != flags || u16(wire, 4) != 1 ||
		u16(wire, 6) != answers.size() || u16(wire, 8) != authority ||
		(!expected_options.empty() && u16(wire, 10) != 1))
		return ::testing::AssertionFailure() << "unexpected header: id=" << u16(wire, 0)
			<< " flags=" << u16(wire, 2) << " answers=" << u16(wire, 6)
			<< " authority=" << u16(wire, 8);
	size_t offset = 12;
	std::string owner;
	if (!wire_name(wire, offset, owner) || owner != domain || offset + 4 > wire.size() ||
		u16(wire, offset) != qtype || u16(wire, offset + 2) != DNS_C_IN)
		return ::testing::AssertionFailure() << "question does not exactly match the request";
	offset += 4;
	std::vector<std::string> actual;
	int soa_count = 0;
	for (int section = 0; section < 3; ++section) {
		const unsigned int count = u16(wire, 6 + 2 * section);
		for (unsigned int i = 0; i < count; ++i) {
			if (!wire_name(wire, offset, owner) || offset + 10 > wire.size())
				return ::testing::AssertionFailure() << "invalid record header";
			const unsigned int type = u16(wire, offset), rrclass = u16(wire, offset + 2);
			const uint32_t ttl = u32(wire, offset + 4);
			const size_t length = u16(wire, offset + 8);
			offset += 10;
			const size_t end = offset + length;
			if (end > wire.size()) return ::testing::AssertionFailure() << "record overflows packet";
			if (section == 2) {
				/* Ordinary ECS warmers explicitly name their exact echoed
				 * option. Plain address replies still require empty OPT. */
				if (type != DNS_T_OPT || !owner.empty() || ttl != 0 || length != expected_options.size() ||
					rrclass < 512 || count != 1 ||
					!std::equal(expected_options.begin(), expected_options.end(), wire.begin() + offset))
					return ::testing::AssertionFailure() << "unexpected additional record";
			} else if (rrclass != DNS_C_IN || ttl == 0) {
				return ::testing::AssertionFailure() << "wrong RR class or nonpositive TTL";
			} else if (section == 0 && (type == DNS_T_A || type == DNS_T_AAAA)) {
				const int family = type == DNS_T_A ? AF_INET : AF_INET6;
				if (length != (type == DNS_T_A ? 4U : 16U))
					return ::testing::AssertionFailure() << "wrong address RDATA length";
				if (ttl < min_address_ttl || ttl > max_address_ttl)
					return ::testing::AssertionFailure() << "address TTL " << ttl
						<< " is outside ordinary response policy [" << min_address_ttl << ", " << max_address_ttl << "]";
				char text[INET6_ADDRSTRLEN];
				if (!inet_ntop(family, wire.data() + offset, text, sizeof(text)))
					return ::testing::AssertionFailure() << "invalid address RDATA";
				actual.push_back(owner + (type == DNS_T_A ? " A " : " AAAA ") + text);
			} else if (section == 0 && type == DNS_T_CNAME) {
				size_t at = offset;
				std::string target;
				if (!wire_name(wire, at, target) || at != end)
					return ::testing::AssertionFailure() << "invalid CNAME RDATA";
				actual.push_back(cname_rr(owner, target));
			} else if (section == 0 && type == 13) {
				const Wire expected{7, 'R', 'F', 'C', '8', '4', '8', '2', 0};
				if (length != expected.size() ||
					!std::equal(expected.begin(), expected.end(), wire.begin() + offset))
					return ::testing::AssertionFailure() << "unexpected HINFO RDATA";
				actual.push_back(owner + " HINFO RFC8482/");
			} else if (section == 1 && type == DNS_T_SOA) {
				size_t at = offset;
				std::string mname, rname;
				if (owner != kDomain || !wire_name(wire, at, mname) || !wire_name(wire, at, rname) ||
					at + 20 != end || mname != (local_soa ? "a.gtld-servers.net" : "ns.address-mode.test") ||
					rname != (local_soa ? "nstld.verisign-grs.com" : "hostmaster.address-mode.test") ||
					u32(wire, at) != (local_soa ? 1800u : 7u) ||
					u32(wire, at + 4) != (local_soa ? 1800u : 60u) ||
					u32(wire, at + 8) != (local_soa ? 900u : 60u) ||
					u32(wire, at + 12) != (local_soa ? 604800u : 600u) ||
					u32(wire, at + 16) != (local_soa ? 86400u : 60u))
					return ::testing::AssertionFailure() << "SOA differs from its expected policy/upstream source";
				++soa_count;
			} else {
				return ::testing::AssertionFailure() << "unexpected RR type " << type << " in section " << section;
			}
			offset = end;
		}
	}
	std::sort(actual.begin(), actual.end());
	std::sort(answers.begin(), answers.end());
	if (actual != answers || soa_count != authority || offset != wire.size())
		return ::testing::AssertionFailure() << "actual RR sets, SOA count, or complete packet length differ";
	return ::testing::AssertionSuccess();
}

Wire query_wire(int type = DNS_T_ANY, uint16_t id = kQueryId, const std::string &domain = kDomain,
	bool do_bit = false, bool cd = false, bool ecs = false, bool ad = false)
{
	unsigned char storage[DNS_PACKSIZE], encoded[DNS_IN_PACKSIZE];
	dns_packet *packet = reinterpret_cast<dns_packet *>(storage);
	dns_head head{};
	head.id = id;
	head.rd = 1;
	head.cd = cd;
	head.ad = ad;
	if (dns_packet_init(packet, sizeof(storage), &head) ||
		dns_add_domain(packet, domain.c_str(), type, DNS_C_IN)) return {};
	if (do_bit) {
		dns_set_OPT_payload_size(packet, 1232);
		dns_set_OPT_option(packet, DNS_OPT_FLAG_DO);
	}
	if (ecs) {
		dns_opt_ecs subnet{};
		subnet.family = DNS_OPT_ECS_FAMILY_IPV4;
		subnet.source_prefix = 24;
		subnet.addr[0] = 192; subnet.addr[1] = 0; subnet.addr[2] = 2;
		dns_set_OPT_payload_size(packet, 1232);
		if (dns_add_OPT_ECS(packet, &subnet)) return {};
	}
	int length = dns_encode(encoded, sizeof(encoded), packet);
	return length > 0 ? Wire(encoded, encoded + length) : Wire{};
}

class LocalConnection {
public:
	explicit LocalConnection(bool tcp, int port = kClientPort) : tcp_(tcp)
	{
		fd_ = socket(AF_INET, (tcp ? SOCK_STREAM : SOCK_DGRAM) | SOCK_CLOEXEC, 0);
		if (fd_ < 0) return;
		timeval timeout{2, 0};
		if (setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
			setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) {
			close(fd_); fd_ = -1; return;
		}
		sockaddr_in address{};
		address.sin_family = AF_INET;
		address.sin_port = htons(port);
		address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (connect(fd_, reinterpret_cast<sockaddr *>(&address), sizeof(address))) {
			close(fd_); fd_ = -1;
		}
	}
	~LocalConnection() { if (fd_ >= 0) close(fd_); }
	LocalConnection(const LocalConnection &) = delete;
	LocalConnection &operator=(const LocalConnection &) = delete;
	bool valid() const { return fd_ >= 0; }
	bool send_query(int type = DNS_T_ANY, uint16_t id = kQueryId, const std::string &domain = kDomain,
		bool do_bit = false, bool cd = false, bool ecs = false, bool ad = false)
	{
		Wire wire = query_wire(type, id, domain, do_bit, cd, ecs, ad);
		return send_wire(wire);
	}
	bool send_wire(const Wire &wire)
	{
		if (fd_ < 0 || wire.empty()) return false;
		if (tcp_) {
			Wire framed{static_cast<unsigned char>(wire.size() >> 8), static_cast<unsigned char>(wire.size())};
			framed.insert(framed.end(), wire.begin(), wire.end());
			size_t at = 0;
			while (at < framed.size()) {
				ssize_t n = send(fd_, framed.data() + at, framed.size() - at, MSG_NOSIGNAL);
				if (n < 0 && errno == EINTR) continue;
				if (n <= 0) return false;
				at += n;
			}
			return true;
		}
		return send(fd_, wire.data(), wire.size(), MSG_NOSIGNAL) == static_cast<ssize_t>(wire.size());
	}
	Wire receive()
	{
		unsigned char bytes[DNS_IN_PACKSIZE];
		if (fd_ < 0) return {};
		int length;
		if (tcp_) {
			unsigned char size[2];
			if (!receive_exact(size, sizeof(size))) return {};
			length = (size[0] << 8) | size[1];
			if (length > static_cast<int>(sizeof(bytes)) || !receive_exact(bytes, length)) return {};
		} else {
			length = recv(fd_, bytes, sizeof(bytes), 0);
		}
		return length > 0 ? Wire(bytes, bytes + length) : Wire{};
	}
	bool cancel_and_observe_peer_close()
	{
		if (!tcp_ || fd_ < 0 || shutdown(fd_, SHUT_WR)) return false;
		unsigned char stray;
		ssize_t length;
		do { length = recv(fd_, &stray, 1, 0); } while (length < 0 && errno == EINTR);
		/* A timeout/reset is not the required barrier, and even one answer
		 * byte would mean the held operation replied instead of canceling. */
		return length == 0;
	}
private:
	bool receive_exact(unsigned char *bytes, size_t length)
	{
		size_t at = 0;
		while (at < length) {
			ssize_t n = recv(fd_, bytes + at, length - at, 0);
			if (n < 0 && errno == EINTR) continue;
			if (n <= 0) return false;
			at += n;
		}
		return true;
	}
	int fd_ = -1;
	bool tcp_;
};

Wire query(int type = DNS_T_ANY, bool tcp = false, int port = kClientPort,
	bool do_bit = false, bool cd = false, bool ecs = false, bool ad = false)
{
	LocalConnection client(tcp, port);
	return client.send_query(type, kQueryId, kDomain, do_bit, cd, ecs, ad) ? client.receive() : Wire{};
}

enum class Outcome {
	Positive, Nodata, Nxdomain, Refused, Servfail, Empty, Drop, UnrelatedSoa,
	TruncatedPositive, AdditionalPositive
};
enum class Gate { None, BothFamilies, BothFamiliesAndMarker };

struct Family {
	Outcome outcome = Outcome::Positive;
	std::vector<std::string> aliases;
	unsigned int soa_serial = 7;
	bool add_slower_address = false;
};

/* Unlike MockServer's synchronous callback, this fixture can retain replies and
 * continue receiving requests. Observing both families before releasing either
 * proves concurrency; a TCP pipeline marker proves all preceding ANY queries
 * were admitted before the cache-zero coalescing replies are released. */
class AddressUpstream {
public:
	Family ipv4, ipv6;
	std::string expected_domain = kDomain;
	Gate gate = Gate::None;
	bool authoritative_authenticated = false;
	std::atomic<int> a{0}, aaaa{0}, any{0}, other{0}, marker{0};
	std::atomic<int> invalid{0}, io_errors{0}, releases{0};
	~AddressUpstream()
	{
		if (thread_.joinable()) {
			stopping_ = true;
			const char byte = 1;
			ssize_t written;
			do { written = write(wake_[1], &byte, 1); } while (written < 0 && errno == EINTR);
			if (written != 1) ++io_errors;
			thread_.join();
		}
		if (fd_ >= 0) close(fd_);
		for (int fd : wake_) if (fd >= 0) close(fd);
	}
	bool start(int port = kUpstreamPort)
	{
		fd_ = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (fd_ < 0 || pipe2(wake_, O_CLOEXEC)) return false;
		sockaddr_in address{};
		address.sin_family = AF_INET;
		address.sin_port = htons(port);
		address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (bind(fd_, reinterpret_cast<sockaddr *>(&address), sizeof(address))) return false;
		thread_ = std::thread([this] { run(); });
		return true;
	}
	bool wait_for_families(int ipv4_count, int ipv6_count)
	{
		std::unique_lock<std::mutex> lock(progress_lock_);
		return progress_.wait_for(lock, std::chrono::milliseconds(800),
			[&] { return a >= ipv4_count && aaaa >= ipv6_count; });
	}
	bool wait_for_release()
	{
		std::unique_lock<std::mutex> lock(progress_lock_);
		return progress_.wait_for(lock, std::chrono::milliseconds(800), [&] { return releases > 0; });
	}
private:
	struct Pending {
		Wire wire;
		sockaddr_storage peer{};
		socklen_t peer_length = 0;
	};
	void send_response(const Pending &pending)
	{
		if (sendto(fd_, pending.wire.data(), pending.wire.size(), MSG_NOSIGNAL,
			reinterpret_cast<const sockaddr *>(&pending.peer), pending.peer_length) !=
			static_cast<ssize_t>(pending.wire.size())) ++io_errors;
	}
	Wire response(uint16_t id, int type, const std::string &domain, const Family &family)
	{
		if (family.outcome == Outcome::Drop) return {};
		unsigned char storage[DNS_PACKSIZE], encoded[DNS_IN_PACKSIZE];
		dns_packet *packet = reinterpret_cast<dns_packet *>(storage);
		dns_head head{};
		head.id = id; head.qr = DNS_QR_ANSWER; head.rd = 1; head.ra = 1;
		head.aa = authoritative_authenticated; head.ad = authoritative_authenticated;
		head.tc = family.outcome == Outcome::TruncatedPositive;
		if (family.outcome == Outcome::Nxdomain) head.rcode = DNS_RC_NXDOMAIN;
		if (family.outcome == Outcome::Refused) head.rcode = DNS_RC_REFUSED;
		if (family.outcome == Outcome::Servfail) head.rcode = DNS_RC_SERVFAIL;
		if (dns_packet_init(packet, sizeof(storage), &head) || dns_add_domain(packet, domain.c_str(), type, DNS_C_IN))
			return {};
		std::string owner = domain;
		for (const auto &target : family.aliases) {
			if (dns_add_CNAME(packet, DNS_RRS_AN, owner.c_str(), 90, target.c_str())) return {};
			owner = target;
		}
		if ((family.outcome == Outcome::Positive || family.outcome == Outcome::TruncatedPositive ||
			family.outcome == Outcome::AdditionalPositive) && (type == DNS_T_A || type == DNS_T_AAAA)) {
			unsigned char address[16]{};
			if (family.add_slower_address) {
				/* Slow first: selection must not simply return the first RR. */
				if (inet_pton(type == DNS_T_A ? AF_INET : AF_INET6,
					type == DNS_T_A ? kSlowIPv4 : kSlowIPv6, address) != 1) return {};
				int rc = type == DNS_T_A ? dns_add_A(packet, DNS_RRS_AN, owner.c_str(), 60, address) :
					dns_add_AAAA(packet, DNS_RRS_AN, owner.c_str(), 60, address);
				if (rc) return {};
			}
			if (inet_pton(type == DNS_T_A ? AF_INET : AF_INET6, type == DNS_T_A ? kIPv4 : kIPv6, address) != 1)
				return {};
			const auto section = family.outcome == Outcome::AdditionalPositive ? DNS_RRS_NR : DNS_RRS_AN;
			int rc = type == DNS_T_A ? dns_add_A(packet, section, owner.c_str(), 60, address) :
				dns_add_AAAA(packet, section, owner.c_str(), 60, address);
			if (rc) return {};
		}
		if (family.outcome == Outcome::Nodata || family.outcome == Outcome::Nxdomain ||
			family.outcome == Outcome::UnrelatedSoa) {
			dns_soa soa{};
			std::strcpy(soa.mname, "ns.address-mode.test");
			std::strcpy(soa.rname, "hostmaster.address-mode.test");
			soa.serial = family.soa_serial; soa.refresh = 60; soa.retry = 60; soa.expire = 600; soa.minimum = 60;
			if (dns_add_SOA(packet, DNS_RRS_NS, family.outcome == Outcome::UnrelatedSoa ?
				"unrelated.test" : kDomain, 120, &soa)) return {};
		}
		int length = dns_encode(encoded, sizeof(encoded), packet);
		if (length <= 0) return {};
		Wire wire(encoded, encoded + length);
		if (type == DNS_T_ANY) {
			/* An accidental ANY probe gets a real RFC 8482 minimal answer,
			 * so it cannot pass by being refused and subsequently expanded. */
			const unsigned char hinfo[] = {0xc0, 0x0c, 0, 13, 0, 1, 0, 0, 0, 60, 0, 9,
				7, 'R', 'F', 'C', '8', '4', '8', '2', 0};
			wire[6] = 0; wire[7] = 1;
			wire.insert(wire.end(), hinfo, hinfo + sizeof(hinfo));
		}
		return wire;
	}
	void run()
	{
		std::vector<Pending> held;
		bool opened = gate == Gate::None;
		while (!stopping_) {
			pollfd descriptors[2] = {{fd_, POLLIN, 0}, {wake_[0], POLLIN, 0}};
			/* The pipe normally wakes teardown immediately; the finite poll
			 * also bounds teardown if the wake write itself fails. */
			int ready = poll(descriptors, 2, 100);
			if (ready < 0 && errno == EINTR) continue;
			if (ready < 0) { ++io_errors; return; }
			if (ready == 0) continue;
			if (descriptors[1].revents) return;
			if (!(descriptors[0].revents & POLLIN)) { ++io_errors; return; }
			unsigned char bytes[DNS_IN_PACKSIZE];
			Pending pending;
			pending.peer_length = sizeof(pending.peer);
			ssize_t length = recvfrom(fd_, bytes, sizeof(bytes), 0,
				reinterpret_cast<sockaddr *>(&pending.peer), &pending.peer_length);
			if (length <= 0) { ++io_errors; continue; }
			Wire request(bytes, bytes + length);
			size_t offset = 12;
			std::string domain;
			if (request.size() < 12 || u16(request, 4) != 1 || (u16(request, 2) & 0xf800) ||
				!wire_name(request, offset, domain) || offset + 4 > request.size() ||
				u16(request, offset + 2) != DNS_C_IN) { ++invalid; continue; }
			int type = u16(request, offset);
			if (domain == kMarker && type == DNS_T_A) {
				++marker;
				pending.wire = response(u16(request, 0), type, domain, Family{});
				if (!pending.wire.empty()) send_response(pending);
			} else {
				if (domain != expected_domain) ++invalid;
				if (type == DNS_T_A) ++a;
				else if (type == DNS_T_AAAA) ++aaaa;
				else if (type == DNS_T_ANY) ++any;
				else ++other;
				pending.wire = response(u16(request, 0), type, domain, type == DNS_T_AAAA ? ipv6 : ipv4);
				if (!pending.wire.empty()) {
					if (opened) send_response(pending);
					else if (held.size() < 64) held.push_back(std::move(pending));
					else ++invalid;
				}
			}
			if (!opened && a > 0 && aaaa > 0 && (gate != Gate::BothFamiliesAndMarker || marker > 0)) {
				opened = true;
				for (const auto &reply : held) send_response(reply);
				held.clear();
				++releases;
			}
			/* Pair notification with the predicate's mutex to avoid a lost
			 * wake between a waiter's predicate check and its actual wait. */
			std::lock_guard<std::mutex> lock(progress_lock_);
			progress_.notify_all();
		}
	}
	int fd_ = -1;
	int wake_[2] = {-1, -1};
	std::atomic<bool> stopping_{false};
	std::mutex progress_lock_;
	std::condition_variable progress_;
	std::thread thread_;
};

std::string config(const std::string &extra = "")
{
	return "bind 127.0.0.1:" + std::to_string(kClientPort) +
		"\nbind-tcp 127.0.0.1:" + std::to_string(kClientPort) +
		"\nserver 127.0.0.1:" + std::to_string(kUpstreamPort) +
		"\nresolv-hostname no\nlocal-ptr-enable no\nspeed-check-mode none\n"
		"dualstack-ip-selection no\nprefetch-domain no\nserve-expired no\ncache-size 128\n"
		"any-response-mode address\n" + extra;
}

void expect_workload(const AddressUpstream &upstream, int a, int aaaa, int marker = 0)
{
	EXPECT_EQ(upstream.a.load(), a) << "upstream A workload";
	EXPECT_EQ(upstream.aaaa.load(), aaaa) << "upstream AAAA workload";
	EXPECT_EQ(upstream.any.load(), 0) << "address mode must never send upstream ANY";
	EXPECT_EQ(upstream.other.load(), 0) << "address mode must not enumerate other types";
	EXPECT_EQ(upstream.marker.load(), marker);
	EXPECT_EQ(upstream.invalid.load(), 0);
	EXPECT_EQ(upstream.io_errors.load(), 0);
}

void run_outcomes(Outcome ipv4, Outcome ipv6, int rcode, const std::vector<std::string> &answers,
	int authority = 0)
{
	AddressUpstream upstream;
	upstream.ipv4.outcome = ipv4; upstream.ipv6.outcome = ipv6;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("cache-size 0\nany-aggregate-partial yes\n"
		"any-aggregate-timeout-ms 250\nany-aggregate-max-attempts 2\n")));
	EXPECT_TRUE(response_is(query(), rcode, answers, authority));
	expect_workload(upstream, 1, 1);
}
} // namespace

TEST(AnyAddress, DualFamilyOverUdpAndTcpNeverProbesHinfoCapableUpstream)
{
	AddressUpstream upstream;
	upstream.authoritative_authenticated = true;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("cache-size 0\n")));
	for (bool tcp : {false, true}) {
		SCOPED_TRACE(tcp ? "TCP" : "UDP");
		EXPECT_TRUE(response_is(query(DNS_T_ANY, tcp), DNS_RC_NOERROR,
			{address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	}
	expect_workload(upstream, 2, 2);
}

TEST(AnyAddress, FixedFamiliesAndConcurrencyIgnoreLegacyAggregateSelection)
{
	AddressUpstream upstream;
	upstream.gate = Gate::BothFamilies;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("any-aggregate-types TXT\nany-aggregate-concurrency 1\n"
		"any-aggregate-partial yes\nany-aggregate-max-attempts 2\nany-aggregate-timeout-ms 950\n")));
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	EXPECT_EQ(upstream.releases.load(), 1) << "both families must arrive before either response is released";
	expect_workload(upstream, 1, 1);
}

TEST(AnyAddress, NormalSpeedSelectionPreservesBothFamiliesAndPolicyTtls)
{
	AddressUpstream upstream;
	upstream.ipv4.add_slower_address = upstream.ipv6.add_slower_address = true;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	/* Two addresses per family avoid the native single-address fast path.
	 * The slow address precedes the selected one in the upstream packet;
	 * exact answers below must exclude it and retain both selected families. */
	server.MockPing(PING_TYPE_ICMP, kIPv4, 60, 30);
	server.MockPing(PING_TYPE_ICMP, kIPv6, 60, 120);
	server.MockPing(PING_TYPE_ICMP, kSlowIPv4, 60, 1000);
	server.MockPing(PING_TYPE_ICMP, kSlowIPv6, 60, 1000);
	ASSERT_TRUE(server.Start(config("speed-check-mode ping\nresponse-mode first-ping\n"
		"dualstack-ip-selection yes\nrr-ttl 60\nserve-expired-reply-ttl 17\n"
		"any-aggregate-timeout-ms 950\n")));
	/* Global serve-expired no does not set the bind/domain no_serve_expired
	 * request flag. The native speed-check reply policy therefore selects
	 * the explicitly configured 17-second reply TTL, not rr-ttl 60.
	 * Merging may conservatively age the earlier child by one second. */
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)},
		0, kQueryId, DNS_T_ANY, kDomain, 16, 17));
	expect_workload(upstream, 1, 1);
}

TEST(AnyAddress, DoAndCdFailClosedWithoutAnyProbe)
{
	AddressUpstream upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config()));
	for (bool tcp : {false, true}) {
		SCOPED_TRACE(tcp ? "TCP" : "UDP");
		EXPECT_TRUE(response_is(query(DNS_T_ANY, tcp, kClientPort, true, false), DNS_RC_SERVFAIL, {}));
		EXPECT_TRUE(response_is(query(DNS_T_ANY, tcp, kClientPort, false, true), DNS_RC_SERVFAIL, {}));
		EXPECT_TRUE(response_is(query(DNS_T_ANY, tcp, kClientPort, true, true), DNS_RC_SERVFAIL, {}));
	}
	expect_workload(upstream, 0, 0);
}

TEST(AnyAddress, ParentForcedSoaRetainsNativePolicyPrecedence)
{
	AddressUpstream upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("force-qtype-SOA 255\n")));
	for (bool tcp : {false, true})
		EXPECT_TRUE(response_is(query(DNS_T_ANY, tcp), DNS_RC_NOERROR, {}, 1, kQueryId,
			DNS_T_ANY, kDomain, 1, UINT32_MAX, {}, true));
	expect_workload(upstream, 0, 0);
}

TEST(AnyAddress, ParentLocalBlockRetainsNativeNxdomain)
{
	AddressUpstream upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("address /address-mode.test/#\n")));
	for (bool tcp : {false, true})
		EXPECT_TRUE(response_is(query(DNS_T_ANY, tcp), DNS_RC_NXDOMAIN, {}, 1, kQueryId,
			DNS_T_ANY, kDomain, 1, UINT32_MAX, {}, true));
	expect_workload(upstream, 0, 0);
}

TEST(AnyAddress, ChildForcedSoaRetainsPolicyWithoutClaimingUpstreamNodata)
{
	AddressUpstream upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("force-qtype-SOA 28\n")));
	/* Warming the permitted family makes wire counts independent of whether
	 * native child scheduling observes the local AAAA policy failure first. */
	ASSERT_TRUE(response_is(query(DNS_T_A), DNS_RC_NOERROR, {address_rr(DNS_T_A)},
		0, kQueryId, DNS_T_A));
	expect_workload(upstream, 1, 0);
	/* An explicit policy suppression is distinct from upstream absence. */
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A)}));
	expect_workload(upstream, 1, 0);
}

TEST(AnyAddress, GroupsInheritAddressAndCanExplicitlyOverridePassthrough)
{
	AddressUpstream upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("cache-size 0\n"
		"bind 127.0.0.1:60056 -g inherited-address\n"
		"bind 127.0.0.1:60057 -g explicit-passthrough\n"
		"group-begin inherited-address\n"
		"group-end\n"
		"group-begin explicit-passthrough\n"
		"any-response-mode passthrough\n"
		"group-end\n")));
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	EXPECT_TRUE(response_is(query(DNS_T_ANY, false, 60056), DNS_RC_NOERROR,
		{address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	expect_workload(upstream, 2, 2);
	/* This exact legacy override must retain transparent HINFO passthrough,
	 * and its result must not contaminate either address-mode context. */
	EXPECT_TRUE(response_is(query(DNS_T_ANY, false, 60057), DNS_RC_NOERROR,
		{std::string(kDomain) + " HINFO RFC8482/"}));
	EXPECT_EQ(upstream.any.load(), 1);
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	EXPECT_EQ(upstream.a.load(), 3);
	EXPECT_EQ(upstream.aaaa.load(), 3);
	EXPECT_EQ(upstream.any.load(), 1);
	EXPECT_EQ(upstream.other.load(), 0);
	EXPECT_EQ(upstream.marker.load(), 0);
	EXPECT_EQ(upstream.invalid.load(), 0);
	EXPECT_EQ(upstream.io_errors.load(), 0);
}

TEST(AnyAddress, IPv4OnlyRequiresGenuineIpv6Nodata)
{
	run_outcomes(Outcome::Positive, Outcome::Nodata, DNS_RC_NOERROR, {address_rr(DNS_T_A)});
}

TEST(AnyAddress, IPv6OnlyRequiresGenuineIpv4Nodata)
{
	run_outcomes(Outcome::Nodata, Outcome::Positive, DNS_RC_NOERROR, {address_rr(DNS_T_AAAA)});
}

TEST(AnyAddress, TimeoutCannotBecomeSingleStackEvenWithPartialYes)
{
	for (bool missing_ipv6 : {true, false}) {
		SCOPED_TRACE(missing_ipv6 ? "AAAA timeout" : "A timeout");
		AddressUpstream upstream;
		upstream.ipv4.outcome = missing_ipv6 ? Outcome::Positive : Outcome::Drop;
		upstream.ipv6.outcome = missing_ipv6 ? Outcome::Drop : Outcome::Positive;
		smartdns::Server server;
		ASSERT_TRUE(upstream.start());
		ASSERT_TRUE(server.Start(config("cache-size 0\nany-aggregate-partial yes\n"
			"any-aggregate-timeout-ms 250\nany-aggregate-max-attempts 2\n")));
		auto start = std::chrono::steady_clock::now();
		Wire result = query();
		const auto elapsed = std::chrono::steady_clock::now() - start;
		EXPECT_TRUE(response_is(result, DNS_RC_SERVFAIL, {}));
		/* Measure only the query. Allow event-loop/scheduler margin beyond
		 * the 250 ms budget, but do not accept the ordinary 2 s timeout. */
		EXPECT_LT(elapsed, std::chrono::milliseconds(1500));
		expect_workload(upstream, 1, 1);
	}
}

TEST(AnyAddress, RefusedAndServfailCannotBecomeSingleStack)
{
	for (Outcome failure : {Outcome::Refused, Outcome::Servfail}) {
		SCOPED_TRACE(static_cast<int>(failure));
		run_outcomes(Outcome::Positive, failure, DNS_RC_SERVFAIL, {});
		run_outcomes(failure, Outcome::Positive, DNS_RC_SERVFAIL, {});
	}
}

TEST(AnyAddress, EmptyNoerrorAndUnrelatedSoaAreNotProofOfNodata)
{
	for (Outcome incomplete : {Outcome::Empty, Outcome::UnrelatedSoa}) {
		SCOPED_TRACE(static_cast<int>(incomplete));
		run_outcomes(Outcome::Positive, incomplete, DNS_RC_SERVFAIL, {});
		run_outcomes(incomplete, Outcome::Positive, DNS_RC_SERVFAIL, {});
	}
}

TEST(AnyAddress, CoherentBothNodataRetainsGenuineSoa)
{
	run_outcomes(Outcome::Nodata, Outcome::Nodata, DNS_RC_NOERROR, {}, 1);
}

TEST(AnyAddress, CoherentBothNxdomainRetainsGenuineSoa)
{
	run_outcomes(Outcome::Nxdomain, Outcome::Nxdomain, DNS_RC_NXDOMAIN, {}, 1);
}

TEST(AnyAddress, ContradictoryNxdomainCannotBecomePositiveOrNodata)
{
	for (Outcome opposite : {Outcome::Positive, Outcome::Nodata}) {
		SCOPED_TRACE(static_cast<int>(opposite));
		run_outcomes(Outcome::Nxdomain, opposite, DNS_RC_SERVFAIL, {});
		run_outcomes(opposite, Outcome::Nxdomain, DNS_RC_SERVFAIL, {});
	}
}

TEST(AnyAddress, InconsistentNegativeSoaFailsStrictly)
{
	AddressUpstream upstream;
	upstream.ipv4.outcome = upstream.ipv6.outcome = Outcome::Nodata;
	upstream.ipv6.soa_serial = 8;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("any-aggregate-partial yes\n")));
	EXPECT_TRUE(response_is(query(), DNS_RC_SERVFAIL, {}));
	expect_workload(upstream, 1, 1);
}

TEST(AnyAddress, MatchingCnameChainsAreEmittedOnceWithBothAddresses)
{
	AddressUpstream upstream;
	upstream.ipv4.aliases = upstream.ipv6.aliases =
		{"hop.address-mode.test", "target.address-mode.test"};
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config()));
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {
		cname_rr(kDomain, "hop.address-mode.test"),
		cname_rr("hop.address-mode.test", "target.address-mode.test"),
		address_rr(DNS_T_A, "target.address-mode.test"),
		address_rr(DNS_T_AAAA, "target.address-mode.test")}));
	expect_workload(upstream, 1, 1);
}

TEST(AnyAddress, ConflictingCnameTargetsCannotBecomePartialAnswers)
{
	AddressUpstream upstream;
	upstream.ipv4.aliases = {"one.address-mode.test"};
	upstream.ipv6.aliases = {"two.address-mode.test"};
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("any-aggregate-partial yes\n")));
	EXPECT_TRUE(response_is(query(), DNS_RC_SERVFAIL, {}));
	expect_workload(upstream, 1, 1);
}

TEST(AnyAddress, DifferentCnamePathsToSameTerminalStillConflict)
{
	AddressUpstream upstream;
	upstream.ipv4.aliases = {"hop.address-mode.test", "target.address-mode.test"};
	upstream.ipv6.aliases = {"target.address-mode.test"};
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config()));
	EXPECT_TRUE(response_is(query(), DNS_RC_SERVFAIL, {}));
	expect_workload(upstream, 1, 1);
}

TEST(AnyAddress, MatchingCnameWithOppositeFamilyNodataReturnsOneAddress)
{
	AddressUpstream upstream;
	upstream.ipv4.aliases = upstream.ipv6.aliases = {"target.address-mode.test"};
	upstream.ipv6.outcome = Outcome::Nodata;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config()));
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {
		cname_rr(kDomain, "target.address-mode.test"), address_rr(DNS_T_A, "target.address-mode.test")}));
	expect_workload(upstream, 1, 1);
}

TEST(AnyAddress, FreshOrdinaryAAndAaaaCacheEntriesAvoidAllAddressUpstreamSends)
{
	AddressUpstream upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config()));
	ASSERT_TRUE(response_is(query(DNS_T_A), DNS_RC_NOERROR, {address_rr(DNS_T_A)}, 0, kQueryId, DNS_T_A));
	ASSERT_TRUE(response_is(query(DNS_T_AAAA), DNS_RC_NOERROR, {address_rr(DNS_T_AAAA)}, 0, kQueryId, DNS_T_AAAA));
	expect_workload(upstream, 1, 1);
	/* No ANY request has run before this one, so an exact ANY cache cannot
	 * explain zero additional wire work. Both native family caches are used. */
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	expect_workload(upstream, 1, 1);
}

TEST(AnyAddress, OrdinaryNegativeCacheIsRevalidatedWhileFreshPositiveCacheIsReused)
{
	AddressUpstream upstream;
	upstream.ipv6.outcome = Outcome::Nodata;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config()));
	ASSERT_TRUE(response_is(query(DNS_T_A), DNS_RC_NOERROR, {address_rr(DNS_T_A)},
		0, kQueryId, DNS_T_A));
	ASSERT_TRUE(response_is(query(DNS_T_AAAA), DNS_RC_NOERROR, {}, 1, kQueryId, DNS_T_AAAA));
	expect_workload(upstream, 1, 1);
	/* Legacy negative cache entries do not retain enough origin/provenance
	 * to prove that a missing family is genuine. Keep the fresh positive A,
	 * but obtain a new SOA-backed AAAA NODATA before returning single-stack. */
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A)}));
	expect_workload(upstream, 1, 2);
}

TEST(AnyAddress, EcsOriginCacheCannotSupplyPlainAddressCompletion)
{
	AddressUpstream upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config()));
	/* The ordinary request carries ECS, but the fixture response contains
	 * no OPT. Response-only inspection cannot establish safe cache origin. */
	ASSERT_TRUE(response_is(query(DNS_T_A, false, kClientPort, false, false, true),
		DNS_RC_NOERROR, {address_rr(DNS_T_A)}, 0, kQueryId, DNS_T_A, kDomain, 1, UINT32_MAX,
		{0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2}));
	expect_workload(upstream, 1, 0);
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	expect_workload(upstream, 2, 1);
}

TEST(AnyAddress, DoOriginCacheCannotSupplyPlainAddressCompletion)
{
	AddressUpstream upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config()));
	ASSERT_TRUE(response_is(query(DNS_T_A, false, kClientPort, true, false),
		DNS_RC_NOERROR, {address_rr(DNS_T_A)}, 0, kQueryId, DNS_T_A));
	expect_workload(upstream, 1, 0);
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	expect_workload(upstream, 2, 1);
}

TEST(AnyAddress, CdAndAdOriginsCannotSupplyPlainAddressCompletion)
{
	for (bool ad : {false, true}) {
		SCOPED_TRACE(ad ? "AD origin" : "CD origin");
		AddressUpstream upstream;
		smartdns::Server server;
		ASSERT_TRUE(upstream.start());
		ASSERT_TRUE(server.Start(config()));
		ASSERT_TRUE(response_is(query(DNS_T_A, false, kClientPort, false, !ad, false, ad),
			DNS_RC_NOERROR, {address_rr(DNS_T_A)}, 0, kQueryId, DNS_T_A));
		expect_workload(upstream, 1, 0);
		EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
		expect_workload(upstream, 2, 1);
	}
}

static void legacy_and_metadata_cache_replacement_case()
{
	std::cout << "Cache-origin fixture: starting isolated in-process resolver" << std::endl;
	AddressUpstream upstream;
	/* Cache APIs and the resolver must share a process. The enclosing
	 * threadsafe death test keeps this in-process fixture's global state
	 * isolated from the main test runner. */
	smartdns::Server server(smartdns::Server::CREATE_MODE_THREAD);
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config()));
	std::cout << "Cache-origin fixture: resolver ready; warming native cache" << std::endl;
	ASSERT_TRUE(response_is(query(DNS_T_A), DNS_RC_NOERROR, {address_rr(DNS_T_A)}, 0, kQueryId, DNS_T_A));
	dns_cache_key key{kDomain, DNS_T_A, "", 0};
	using CacheRef = std::unique_ptr<dns_cache, decltype(&dns_cache_release)>;
	using DataRef = std::unique_ptr<dns_cache_data, decltype(&dns_cache_data_put)>;
	CacheRef entry(dns_cache_lookup(&key), dns_cache_release);
	ASSERT_NE(entry.get(), nullptr);
	dns_cache_info info{};
	DataRef snapshot(dns_cache_get_data_with_origin(entry.get(), DNS_CACHE_ORIGIN_PLAIN, &info),
		dns_cache_data_put);
	ASSERT_NE(snapshot.get(), nullptr);
	std::cout << "Cache-origin fixture: native snapshot retained; replacing packet" << std::endl;
	const auto old_size = snapshot->head.size;
	const Wire old_packet(snapshot->data, snapshot->data + old_size);
	const int old_speed = info.speed;

	/* A new packet supplied through the legacy API has unknown provenance,
	 * even if the previous entry was safe. Retained snapshots must keep the
	 * old packet and its metadata rather than observe the replacement. */
	DataRef replacement(dns_cache_new_data_packet(snapshot->data, old_size), dns_cache_data_put);
	ASSERT_NE(replacement.get(), nullptr);
	ASSERT_EQ(dns_cache_replace(&key, DNS_RC_NOERROR, 60, old_speed + 17, 60, 1,
		replacement.get()), 0);
	replacement.release();
	DataRef unsafe(dns_cache_get_data_with_origin(entry.get(), DNS_CACHE_ORIGIN_PLAIN, &info),
		dns_cache_data_put);
	EXPECT_EQ(unsafe.get(), nullptr);
	EXPECT_EQ(snapshot->head.size, old_size);
	EXPECT_EQ(Wire(snapshot->data, snapshot->data + old_size), old_packet);
	EXPECT_EQ(info.speed, old_speed) << "failed admission must not modify the retained snapshot metadata";
	entry.reset();
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	expect_workload(upstream, 2, 1);
	std::cout << "Cache-origin fixture: legacy replacement verified; replacing metadata" << std::endl;

	/* Metadata-only replacement must also revoke the flag rather than lend
	 * a fresh lifetime to provenance that has no replacement packet. */
	ASSERT_EQ(dns_cache_replace_with_origin(&key, DNS_RC_NOERROR, 60, -1, 60, 1,
		nullptr, DNS_CACHE_ORIGIN_PLAIN), 0);
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	expect_workload(upstream, 3, 1);
	std::cout << "Cache-origin fixture: metadata replacement verified; releasing fixture" << std::endl;
}

TEST(AnyAddress, LegacyAndMetadataOnlyReplacementRevokeCacheOrigin)
{
	/* Re-exec before creating either fixture thread: no unsafe post-fork
	 * C++/OpenSSL initialization, nor signal/getopt/global-cache changes in
	 * the main test process. Preserve every assertion as an exit failure. */
	::testing::FLAGS_gtest_death_test_style = "threadsafe";
	ASSERT_EXIT({
		legacy_and_metadata_cache_replacement_case();
		_exit(::testing::Test::HasFailure() ? 1 : 0);
	}, ::testing::ExitedWithCode(0), "");
}

static void incomplete_native_cache_case(Outcome incomplete)
{
	for (bool warm_with_address : {false, true}) {
		SCOPED_TRACE(warm_with_address ? "failed address warmer" : "ordinary A warmer");
		AddressUpstream upstream;
		upstream.ipv4.outcome = incomplete;
		smartdns::Server server;
		ASSERT_TRUE(upstream.start());
		ASSERT_TRUE(server.Start(config()));
		if (warm_with_address) {
			ASSERT_TRUE(response_is(query(), DNS_RC_SERVFAIL, {}));
			expect_workload(upstream, 1, 1);
		} else {
			/* The legacy ordinary pipeline reconstructs this incomplete
			 * source as an Answer. Do not change that behavior here. */
			ASSERT_TRUE(response_is(query(DNS_T_A), DNS_RC_NOERROR,
				{address_rr(DNS_T_A)}, 0, kQueryId, DNS_T_A));
			expect_workload(upstream, 1, 0);
		}
		/* A clean-looking native cache packet is not complete upstream
		 * evidence. Refetch A and fail again; retain healthy AAAA reuse. */
		EXPECT_TRUE(response_is(query(), DNS_RC_SERVFAIL, {}));
		expect_workload(upstream, 2, 1);
		EXPECT_TRUE(response_is(query(), DNS_RC_SERVFAIL, {}));
		expect_workload(upstream, 3, 1);
	}
}

TEST(AnyAddress, TruncatedNativeWarmCacheCannotSupplyAddressCompletion)
{
	incomplete_native_cache_case(Outcome::TruncatedPositive);
}

TEST(AnyAddress, AdditionalOnlyNativeWarmCacheCannotSupplyAddressCompletion)
{
	incomplete_native_cache_case(Outcome::AdditionalPositive);
}

TEST(AnyAddress, OneFreshOrdinaryFamilyCacheOnlyFetchesTheMissingFamily)
{
	for (int warmed : {DNS_T_A, DNS_T_AAAA}) {
		SCOPED_TRACE(warmed);
		AddressUpstream upstream;
		smartdns::Server server;
		ASSERT_TRUE(upstream.start());
		ASSERT_TRUE(server.Start(config("any-aggregate-max-attempts 1\n")));
		ASSERT_TRUE(response_is(query(warmed), DNS_RC_NOERROR, {address_rr(warmed)}, 0, kQueryId, warmed));
		EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
		expect_workload(upstream, 1, 1);
	}
}

TEST(AnyAddress, OneSendBudgetFailsRatherThanExposingOneSuccessfulFamily)
{
	AddressUpstream upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("cache-size 0\nany-aggregate-max-attempts 1\nany-aggregate-partial yes\n")));
	EXPECT_TRUE(response_is(query(), DNS_RC_SERVFAIL, {}));
	EXPECT_EQ(upstream.a.load() + upstream.aaaa.load(), 1) << "budget must cover actual typed sends";
	EXPECT_EQ(upstream.any.load(), 0);
	EXPECT_EQ(upstream.other.load(), 0);
	EXPECT_EQ(upstream.invalid.load(), 0);
	EXPECT_EQ(upstream.io_errors.load(), 0);
}

TEST(AnyAddress, CacheZeroCoalescesAdmittedTcpWaitersThenFetchesAgain)
{
	AddressUpstream upstream;
	upstream.gate = Gate::BothFamiliesAndMarker;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("cache-size 0\nany-aggregate-timeout-ms 950\n"
		"any-aggregate-max-attempts 2\n")));
	LocalConnection clients(true);
	ASSERT_TRUE(clients.valid());
	constexpr int callers = 8;
	for (int i = 0; i < callers; ++i) ASSERT_TRUE(clients.send_query(DNS_T_ANY, kQueryId + i));
	/* TCP frame ordering supplies an admission barrier without timing sleeps.
	 * This ordinary, distinct-name A request is not part of the ANY budget. */
	ASSERT_TRUE(clients.send_query(DNS_T_A, kQueryId + callers, kMarker));
	std::map<uint16_t, Wire> responses;
	for (int i = 0; i <= callers; ++i) {
		Wire wire = clients.receive();
		ASSERT_GE(wire.size(), 12U);
		EXPECT_TRUE(responses.emplace(u16(wire, 0), wire).second) << "duplicate reply ID";
	}
	for (int i = 0; i < callers; ++i) {
		auto reply = responses.find(kQueryId + i);
		ASSERT_NE(reply, responses.end());
		EXPECT_TRUE(response_is(reply->second, DNS_RC_NOERROR,
			{address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}, 0, kQueryId + i));
	}
	auto marker = responses.find(kQueryId + callers);
	ASSERT_NE(marker, responses.end());
	EXPECT_TRUE(response_is(marker->second, DNS_RC_NOERROR, {address_rr(DNS_T_A, kMarker)},
		0, kQueryId + callers, DNS_T_A, kMarker));
	EXPECT_EQ(upstream.releases.load(), 1);
	expect_workload(upstream, 1, 1, 1);
	/* A post-completion caller cannot reuse a completed result or native
	 * family entry when cache-size is zero. In-flight sharing still worked. */
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	expect_workload(upstream, 2, 2, 1);
}

TEST(AnyAddress, LastTcpWaiterCancellationReleasesNativeChildrenWithoutPoisoningRetry)
{
	AddressUpstream upstream;
	upstream.gate = Gate::BothFamiliesAndMarker;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("cache-size 0\nany-aggregate-timeout-ms 950\n")));
	LocalConnection cancelled(true);
	ASSERT_TRUE(cancelled.valid());
	ASSERT_TRUE(cancelled.send_query());
	ASSERT_TRUE(upstream.wait_for_families(1, 1));
	expect_workload(upstream, 1, 1);
	ASSERT_EQ(upstream.releases.load(), 0) << "both native child responses must still be held";
	/* _dns_server_client_close cancels ANY waiters before releasing the
	 * server connection. Peer EOF is therefore an observable cancellation
	 * barrier, rather than guessing when an asynchronous close is handled. */
	ASSERT_TRUE(cancelled.cancel_and_observe_peer_close());

	LocalConnection control(true);
	ASSERT_TRUE(control.valid());
	ASSERT_TRUE(control.send_query(DNS_T_A, kQueryId + 20, kMarker));
	EXPECT_TRUE(response_is(control.receive(), DNS_RC_NOERROR, {address_rr(DNS_T_A, kMarker)},
		0, kQueryId + 20, DNS_T_A, kMarker));
	ASSERT_TRUE(upstream.wait_for_release());
	expect_workload(upstream, 1, 1, 1);
	/* These are late responses to the canceled native requests. A new
	 * equivalent client must neither inherit their canceled budget nor join
	 * a terminal ANY operation. Its distinct ID also detects stray replies. */
	LocalConnection fresh(true);
	ASSERT_TRUE(fresh.valid());
	ASSERT_TRUE(fresh.send_query(DNS_T_ANY, kQueryId + 21));
	EXPECT_TRUE(response_is(fresh.receive(), DNS_RC_NOERROR,
		{address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}, 0, kQueryId + 21));
	expect_workload(upstream, 2, 2, 1);
	EXPECT_TRUE(server.IsRunning());
}

TEST(AnyAddress, DefaultDigAdHintCompletesOverUdpAndTcpWithoutAssertingAd)
{
	AddressUpstream upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("cache-size 0\n")));
	for (bool tcp : {false, true})
		EXPECT_TRUE(response_is(query(DNS_T_ANY, tcp, kClientPort, false, false, false, true),
			DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	expect_workload(upstream, 2, 2);
}

TEST(AnyAddress, CookieAndPaddingDoNotSelectAnUnprovenDnsView)
{
	AddressUpstream upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config()));
	for (bool tcp : {false, true}) {
		for (int option : {int(DNS_OPT_T_COOKIE), int(DNS_OPT_T_PADDING), int(DNS_OPT_T_TCP_KEEPALIVE), 65001}) {
			Wire wire = query_wire(DNS_T_ANY, kQueryId, kDomain, false, false, false, true);
			wire[11] = 1;
			/* One root OPT: payload 1232 and a benign hop option or an unknown option. */
			int size = option == DNS_OPT_T_TCP_KEEPALIVE ? 2 : 8;
			Wire opt{0, 0, 41, 4, 208, 0, 0, 0, 0, 0, static_cast<unsigned char>(size + 4),
				static_cast<unsigned char>(option >> 8), static_cast<unsigned char>(option), 0, static_cast<unsigned char>(size)};
			opt.resize(opt.size() + size, 0);
			wire.insert(wire.end(), opt.begin(), opt.end());
			LocalConnection client(tcp);
			ASSERT_TRUE(client.send_wire(wire));
			EXPECT_TRUE(response_is(client.receive(), option == 65001 ? DNS_RC_SERVFAIL : DNS_RC_NOERROR,
				option == 65001 ? std::vector<std::string>{} :
				std::vector<std::string>{address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
		}
	}
	expect_workload(upstream, 6, 6);
}

TEST(AnyAddress, GlobalCnameSuppressionPreservesBothFamiliesAfterAliasValidation)
{
	AddressUpstream upstream;
	upstream.ipv4.aliases = upstream.ipv6.aliases = {"hop.address-mode.test", "target.address-mode.test"};
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("force-no-CNAME yes\n")));
	for (bool tcp : {false, true})
		EXPECT_TRUE(response_is(query(DNS_T_ANY, tcp), DNS_RC_NOERROR,
			{address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	expect_workload(upstream, 2, 2);
}

TEST(AnyAddress, CnameSuppressionComposesIndependentValidatedNativeAliases)
{
	AddressUpstream upstream;
	upstream.ipv4.aliases = {"one.address-mode.test"};
	upstream.ipv6.aliases = {"two.address-mode.test"};
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("force-no-CNAME yes\n")));
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	expect_workload(upstream, 1, 1);
}

TEST(AnyAddress, ProductionDualstackAndSpeedFlagsComposeWithAddressMode)
{
	AddressUpstream upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("force-no-CNAME yes\n"
		"domain-rules /address-mode.test/ -dualstack-ip-selection yes -speed-check-mode none\n")));
	EXPECT_TRUE(response_is(query(DNS_T_ANY, false, kClientPort, false, false, false, true),
		DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	expect_workload(upstream, 1, 1);
}

TEST(AnyAddress, Ipv6PolicySuppressionComposesWithAnIpv4Alias)
{
	AddressUpstream upstream;
	upstream.ipv4.aliases = {"target.address-mode.test"};
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("domain-rules /address-mode.test/ -address #6\n")));
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR,
		{cname_rr(kDomain, "target.address-mode.test"), address_rr(DNS_T_A, "target.address-mode.test")}));
	expect_workload(upstream, 1, 0);
}

TEST(AnyAddress, ProductionIpv6SuppressionAndCnameFlatteningCompose)
{
	AddressUpstream upstream;
	upstream.ipv4.aliases = {"target.address-mode.test"};
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("force-no-CNAME yes\n"
		"domain-rules /address-mode.test/ -address #6 -dualstack-ip-selection no -speed-check-mode none\n")));
	EXPECT_TRUE(response_is(query(DNS_T_ANY, true, kClientPort, false, false, false, true),
		DNS_RC_NOERROR, {address_rr(DNS_T_A)}));
	expect_workload(upstream, 1, 0);
}

TEST(AnyAddress, Ipv4PolicySuppressionPreservesIpv6)
{
	AddressUpstream upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("address /address-mode.test/#4\n")));
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_AAAA)}));
	expect_workload(upstream, 0, 1);
}

TEST(AnyAddress, LocalDualFamilyAddressesDoNotRequireUpstreamProof)
{
	AddressUpstream upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("address /address-mode.test/192.0.2.17,2001:db8::17\n")));
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	expect_workload(upstream, 0, 0);
}

TEST(AnyAddress, LocalSingleFamilyAddressRetainsNativeMissingFamilyPolicy)
{
	AddressUpstream upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("address /address-mode.test/192.0.2.17\n")));
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A)}));
	expect_workload(upstream, 0, 0);
}

TEST(AnyAddress, ConfiguredAliasRebasesTargetEvidenceWithoutLosingItsBudget)
{
	AddressUpstream upstream;
	upstream.expected_domain = "target.address-mode.test";
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("cname /address-mode.test/target.address-mode.test\n")));
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR,
		{cname_rr(kDomain, "target.address-mode.test"), address_rr(DNS_T_A, "target.address-mode.test"),
			address_rr(DNS_T_AAAA, "target.address-mode.test")}));
	expect_workload(upstream, 1, 1);
}

TEST(AnyAddress, ConfiguredAliasAlsoHonorsGlobalCnameSuppression)
{
	AddressUpstream upstream;
	upstream.expected_domain = "target.address-mode.test";
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("force-no-CNAME yes\ncname /address-mode.test/target.address-mode.test\n")));
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	expect_workload(upstream, 1, 1);
}

TEST(AnyAddress, NftsetPolicyUsesTheNativeTypedPipeline)
{
	AddressUpstream upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("domain-rules /address-mode.test/ "
		"-nftset #4:inet#smartdns_any_test#v4,#6:inet#smartdns_any_test#v6\n")));
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	expect_workload(upstream, 1, 1);
}

TEST(AnyAddress, NoCacheBindFlagStillAllowsIndependentTypedResolution)
{
	AddressUpstream upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	std::string cfg = config();
	const std::string bind = "bind 127.0.0.1:" + std::to_string(kClientPort);
	cfg.replace(cfg.find(bind), bind.size(), bind + " -no-cache");
	ASSERT_TRUE(server.Start(cfg));
	for (int n = 0; n < 2; n++)
		EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	expect_workload(upstream, 2, 2);
}

TEST(AnyAddress, PolicySuppressionCannotTurnARealTransportFailureIntoSuccess)
{
	AddressUpstream upstream;
	upstream.ipv4.outcome = Outcome::Servfail;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("force-no-CNAME yes\naddress /address-mode.test/#6\nany-aggregate-max-attempts 1\n")));
	EXPECT_TRUE(response_is(query(), DNS_RC_SERVFAIL, {}));
	expect_workload(upstream, 1, 0);
}

TEST(AnyAddress, APlainCallerCannotJoinANonplainOperation)
{
	AddressUpstream upstream;
	upstream.gate = Gate::BothFamiliesAndMarker;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("cache-size 0\n")));
	LocalConnection hinted(true), plain(true), marker(true);
	ASSERT_TRUE(hinted.send_query(DNS_T_ANY, kQueryId, kDomain, false, false, false, true));
	ASSERT_TRUE(upstream.wait_for_families(1, 1));
	ASSERT_TRUE(plain.send_query(DNS_T_ANY, kQueryId + 1));
	ASSERT_TRUE(upstream.wait_for_families(2, 2));
	ASSERT_TRUE(marker.send_query(DNS_T_A, kQueryId + 2, kMarker));
	EXPECT_TRUE(response_is(marker.receive(), DNS_RC_NOERROR, {address_rr(DNS_T_A, kMarker)},
		0, kQueryId + 2, DNS_T_A, kMarker));
	EXPECT_TRUE(response_is(hinted.receive(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	EXPECT_TRUE(response_is(plain.receive(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)},
		0, kQueryId + 1));
	expect_workload(upstream, 2, 2, 1);
}

TEST(AnyAddress, CnameSuppressionRetainsGenuineUpstreamNodata)
{
	AddressUpstream upstream;
	upstream.ipv4.aliases = upstream.ipv6.aliases = {"target.address-mode.test"};
	upstream.ipv6.outcome = Outcome::Nodata;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("force-no-CNAME yes\n")));
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A)}));
	expect_workload(upstream, 1, 1);
}

TEST(AnyAddress, ConfiguredAliasRetainsTheTargetsFurtherUpstreamAliases)
{
	AddressUpstream upstream;
	upstream.expected_domain = "target.address-mode.test";
	upstream.ipv4.aliases = upstream.ipv6.aliases = {"canonical.address-mode.test"};
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config("cname /address-mode.test/target.address-mode.test\n")));
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR,
		{cname_rr(kDomain, "target.address-mode.test"),
			cname_rr("target.address-mode.test", "canonical.address-mode.test"),
			address_rr(DNS_T_A, "canonical.address-mode.test"), address_rr(DNS_T_AAAA, "canonical.address-mode.test")}));
	expect_workload(upstream, 1, 1);
}

TEST(AnyAddress, UnknownEdnsOriginCannotSupplyPlainAddressCompletion)
{
	AddressUpstream upstream;
	smartdns::Server server;
	ASSERT_TRUE(upstream.start());
	ASSERT_TRUE(server.Start(config()));
	Wire wire = query_wire(DNS_T_A);
	wire[11] = 1;
	Wire opt{0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 4, 253, 233, 0, 0};
	wire.insert(wire.end(), opt.begin(), opt.end());
	LocalConnection client(false);
	ASSERT_TRUE(client.send_wire(wire));
	ASSERT_TRUE(response_is(client.receive(), DNS_RC_NOERROR, {address_rr(DNS_T_A)}, 0, kQueryId, DNS_T_A));
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	expect_workload(upstream, 2, 1);
}

TEST(AnyAddress, MultipleUpstreamAliasesFollowTheNativeSelectedAddress)
{
	AddressUpstream first, second;
	first.ipv4.aliases = {"first.address-mode.test"};
	second.ipv4.aliases = {"second.address-mode.test"};
	first.ipv4.add_slower_address = second.ipv4.add_slower_address = true;
	smartdns::Server server;
	ASSERT_TRUE(first.start()); ASSERT_TRUE(second.start(kUpstreamPort + 1));
	server.MockPing(PING_TYPE_ICMP, kIPv4, 60, 30);
	server.MockPing(PING_TYPE_ICMP, kSlowIPv4, 60, 1000);
	ASSERT_TRUE(server.Start(config("server 127.0.0.1:"+std::to_string(kUpstreamPort+1)+"\n"
		"domain-rules /address-mode.test/ -address #6\nspeed-check-mode ping\nresponse-mode first-ping\n")));
	Wire result = query();
	EXPECT_TRUE(response_is(result, DNS_RC_NOERROR, {cname_rr(kDomain, "first.address-mode.test"), address_rr(DNS_T_A, "first.address-mode.test")}) ||
		response_is(result, DNS_RC_NOERROR, {cname_rr(kDomain, "second.address-mode.test"), address_rr(DNS_T_A, "second.address-mode.test")}));
	expect_workload(first, 1, 0); expect_workload(second, 1, 0);
}

TEST(AnyAddress, CnameSuppressionPreservesNativeSelectionAcrossMultipleUpstreams)
{
	AddressUpstream first, second;
	first.ipv4.aliases = first.ipv6.aliases = {"first.address-mode.test"};
	second.ipv4.aliases = second.ipv6.aliases = {"second.address-mode.test"};
	first.ipv4.add_slower_address = first.ipv6.add_slower_address = true;
	second.ipv4.add_slower_address = second.ipv6.add_slower_address = true;
	smartdns::Server server;
	ASSERT_TRUE(first.start()); ASSERT_TRUE(second.start(kUpstreamPort + 1));
	server.MockPing(PING_TYPE_ICMP, kIPv4, 60, 30);
	server.MockPing(PING_TYPE_ICMP, kIPv6, 60, 30);
	server.MockPing(PING_TYPE_ICMP, kSlowIPv4, 60, 1000);
	server.MockPing(PING_TYPE_ICMP, kSlowIPv6, 60, 1000);
	ASSERT_TRUE(server.Start(config("server 127.0.0.1:"+std::to_string(kUpstreamPort+1)+"\n"
		"force-no-CNAME yes\nany-aggregate-max-attempts 4\nspeed-check-mode ping\nresponse-mode first-ping\n")));
	EXPECT_TRUE(response_is(query(), DNS_RC_NOERROR, {address_rr(DNS_T_A), address_rr(DNS_T_AAAA)}));
	expect_workload(first, 1, 1); expect_workload(second, 1, 1);
}
