/* Bounded correctness fixtures only: no public DNS, load, or benchmarks. */
#include "gtest/gtest.h"
extern "C" {
#include "dns_client/upstream_policy.h"
#include "dns_client/client_socket.h"
#include "dns_client/client_udp.h"
#include "dns_client/proxy.h"
#include "smartdns/util.h"
}
#include <arpa/inet.h>
#include <atomic>
#include <cstring>
#include <thread>
#include <vector>
#include <unistd.h>
#include <chrono>
#include <sys/epoll.h>
#include <poll.h>

namespace {
struct PlainEndpoint {
    dns_server_info s{};
    explicit PlainEndpoint(int port) {
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr); pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&s.lock, &attr); pthread_mutexattr_destroy(&attr);
        INIT_LIST_HEAD(&s.conn_stream_list); atomic_set(&s.refcnt, 1);
        s.fd = -1; s.type = DNS_SERVER_UDP; s.ai_family = AF_INET;
        s.in.sin_family = AF_INET; s.in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        s.in.sin_port = htons(port); s.ai_addrlen = sizeof(s.in); s.so_mark = -1;
        EXPECT_EQ(_dns_policy_attach(&s), 0);
    }
    ~PlainEndpoint() { _dns_policy_detach(&s); pthread_mutex_destroy(&s.lock); }
};
}

TEST(UpstreamRoundRobin, ProxyConnectingEnqueuesWholeFramesUnderEndpointLock) {
    PlainEndpoint endpoint(1);
    auto &s = endpoint.s;
    s.fd = 123; // CONNECTING enqueue never uses the descriptor/proxy object
    s.proxy = reinterpret_cast<proxy_conn *>(1);
    s.status = DNS_SERVER_STATUS_CONNECTING;
    unsigned char first[] = {1, 2, 3, 4, 5}, second[] = {6, 7, 8, 9, 10, 11, 12};
    std::atomic<int> started{0}, done{0};
    pthread_mutex_lock(&s.lock);
    std::thread a([&] { started++; EXPECT_EQ(_dns_client_send_udp(&s, first, sizeof(first)), 0); done++; });
    std::thread b([&] { started++; EXPECT_EQ(_dns_client_send_udp(&s, second, sizeof(second)), 0); done++; });
    while (started != 2) std::this_thread::yield();
    // Bounded blocking assertion: both producers must obey the endpoint mutex.
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_EQ(done, 0);
    pthread_mutex_unlock(&s.lock);
    a.join(); b.join();
    EXPECT_EQ(s.send_buff.len, int(sizeof(first) + sizeof(second) + 2 * sizeof(int)));
    int offset = 0; bool seen_first = false, seen_second = false;
    for (int i = 0; i < 2; i++) {
        int length = 0; memcpy(&length, s.send_buff.data + offset, sizeof(length)); offset += sizeof(length);
        if (length == sizeof(first)) { EXPECT_EQ(memcmp(s.send_buff.data + offset, first, length), 0); seen_first = true; }
        else if (length == sizeof(second)) { EXPECT_EQ(memcmp(s.send_buff.data + offset, second, length), 0); seen_second = true; }
        else { ADD_FAILURE() << "interleaved frame length " << length; break; }
        offset += length;
    }
    EXPECT_TRUE(seen_first && seen_second);
    // Header space alone is insufficient: failure cannot leave a partial record.
    s.send_buff.len = DNS_TCP_BUFFER - sizeof(int);
    unsigned char tail[sizeof(int)]; memcpy(tail, s.send_buff.data + s.send_buff.len, sizeof(tail));
    EXPECT_EQ(_dns_client_send_udp(&s, first, sizeof(first)), -1);
    EXPECT_EQ(s.send_buff.len, int(DNS_TCP_BUFFER - sizeof(int)));
    EXPECT_EQ(memcmp(tail, s.send_buff.data + s.send_buff.len, sizeof(tail)), 0);
    s.proxy = nullptr; s.fd = -1; s.send_buff.len = 0;
}

TEST(UpstreamRoundRobin, LoopbackSocks5HandshakeDrainsCompleteQueuedDatagrams) {
    // Use the existing production proxy and UDP entry points with a tiny local
    // SOCKS5 peer. Two datagrams only; no load loop or performance measurement.
    struct Fd { int value = -1; ~Fd() { if (value >= 0) close(value); } } listener, relay, peer;
    listener.value = socket(AF_INET, SOCK_STREAM, 0);
    relay.value = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(listener.value, 0); ASSERT_GE(relay.value, 0);
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(bind(listener.value, reinterpret_cast<sockaddr *>(&address), sizeof(address)), 0);
    ASSERT_EQ(listen(listener.value, 1), 0);
    socklen_t addrlen = sizeof(address);
    ASSERT_EQ(getsockname(listener.value, reinterpret_cast<sockaddr *>(&address), &addrlen), 0);
    proxy_info info{}; info.type = PROXY_SOCKS5; strcpy(info.server, "127.0.0.1"); info.port = ntohs(address.sin_port);
    address.sin_port = 0;
    ASSERT_EQ(bind(relay.value, reinterpret_cast<sockaddr *>(&address), sizeof(address)), 0);
    ASSERT_EQ(getsockname(relay.value, reinterpret_cast<sockaddr *>(&address), &addrlen), 0);
    timeval timeout{1, 0}; setsockopt(relay.value, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ASSERT_EQ(proxy_init(), 0);
    PlainEndpoint endpoint(5300);
    struct Cleanup {
        dns_server_info *s; int previous_epoll;
        ~Cleanup() { _dns_client_close_socket(s); proxy_exit(); if (client.epoll_fd >= 0) close(client.epoll_fd); client.epoll_fd = previous_epoll; }
    } cleanup{&endpoint.s, client.epoll_fd};
    client.epoll_fd = epoll_create1(EPOLL_CLOEXEC); ASSERT_GE(client.epoll_fd, 0);
    ASSERT_EQ(proxy_add("rr-local-socks", &info), 0);
    auto &s = endpoint.s;
    s.type = DNS_SERVER_UDP; s.ai_family = AF_INET; s.so_mark = -1;
    strcpy(s.ip, "127.0.0.1"); s.port = 5300; strcpy(s.proxy_name, "rr-local-socks");
    ASSERT_EQ(_dns_client_create_socket(&s), 0);
    pollfd ready{listener.value, POLLIN, 0}; ASSERT_EQ(poll(&ready, 1, 1000), 1);
    peer.value = accept(listener.value, nullptr, nullptr); ASSERT_GE(peer.value, 0);
    setsockopt(peer.value, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    unsigned char first[] = {0x11, 0x22, 0x33}, second[] = {0x44, 0x55, 0x66, 0x77, 0x88};
    ASSERT_EQ(_dns_client_send_udp(&s, first, sizeof(first)), 0);
    ASSERT_EQ(_dns_client_send_udp(&s, second, sizeof(second)), 0);
    EXPECT_EQ(s.send_buff.len, int(sizeof(first) + sizeof(second) + 2 * sizeof(int)));
    epoll_event event{}; event.events = EPOLLOUT; event.data.ptr = &s;
    _dns_proxy_handshake(&s, &event, get_tick_count());
    unsigned char bytes[64]{};
    ASSERT_EQ(recv(peer.value, bytes, 4, MSG_WAITALL), 4);
    EXPECT_EQ(bytes[0], 5); EXPECT_EQ(bytes[1], 2);
    unsigned char auth[] = {5, 0}; ASSERT_EQ(send(peer.value, auth, sizeof(auth), MSG_NOSIGNAL), sizeof(auth));
    event.events = EPOLLIN; _dns_proxy_handshake(&s, &event, get_tick_count());
    ASSERT_EQ(recv(peer.value, bytes, 10, MSG_WAITALL), 10);
    EXPECT_EQ(bytes[0], 5); EXPECT_EQ(bytes[1], 3); EXPECT_EQ(bytes[3], 1);
    unsigned char associated[] = {5, 0, 0, 1, 127, 0, 0, 1, 0, 0};
    memcpy(associated + 8, &address.sin_port, 2);
    ASSERT_EQ(send(peer.value, associated, sizeof(associated), MSG_NOSIGNAL), sizeof(associated));
    event.events = EPOLLIN; EXPECT_EQ(_dns_proxy_handshake(&s, &event, get_tick_count()), 0);
    ASSERT_EQ(s.status, DNS_SERVER_STATUS_CONNECTED);
    event.events = EPOLLOUT;
    ASSERT_EQ(_dns_client_process_udp(&s, &event, get_tick_count()), 0);
    EXPECT_EQ(s.send_buff.len, 0);
    for (int i = 0; i < 2; i++) {
        int length = i ? sizeof(second) : sizeof(first);
        ASSERT_EQ(recv(relay.value, bytes, sizeof(bytes), 0), length + 10);
        EXPECT_EQ(bytes[0], 0); EXPECT_EQ(bytes[1], 0); EXPECT_EQ(bytes[2], 0); EXPECT_EQ(bytes[3], 1);
        EXPECT_EQ(memcmp(bytes + 4, &s.in.sin_addr, 4), 0);
        EXPECT_EQ(memcmp(bytes + 8, &s.in.sin_port, 2), 0);
        EXPECT_EQ(memcmp(bytes + 10, i ? second : first, length), 0);
    }
    // Exercise production nonblocking recv with no response, retaining the
    // connected proxy and leaving the drained queue empty.
    event.events = EPOLLIN;
    EXPECT_EQ(_dns_client_process_udp(&s, &event, get_tick_count()), 0);
    EXPECT_EQ(s.status, DNS_SERVER_STATUS_CONNECTED); EXPECT_EQ(s.send_buff.len, 0);
}
