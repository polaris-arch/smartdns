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

#include "client.h"
#include "include/utils.h"
#include "server.h"
#include "gtest/gtest.h"
#include <atomic>
#include <chrono>
#include <fstream>
#include <signal.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>

namespace {
std::atomic<bool> mock_signal_seen{false};
void mock_interrupt(int) { mock_signal_seen.store(true, std::memory_order_relaxed); }
void interrupted_mock_case() {
    static_assert(std::atomic<bool>::is_always_lock_free);
    struct sigaction action{}; action.sa_handler = mock_interrupt; sigemptyset(&action.sa_mask);
    ASSERT_EQ(sigaction(SIGUSR2, &action, nullptr), 0);
    sigset_t mask; sigemptyset(&mask); sigaddset(&mask, SIGUSR2);
    ASSERT_EQ(pthread_sigmask(SIG_UNBLOCK, &mask, nullptr), 0);
    std::atomic<pthread_t> worker{}; std::atomic<pid_t> tid{0};
    smartdns::MockServer server;
    ASSERT_TRUE(server.Start("udp://127.0.0.1:62997", [&](auto *r) {
        worker.store(pthread_self()); tid.store(syscall(SYS_gettid));
        dns_add_domain(r->response_packet, r->domain.c_str(), r->qtype, r->qclass);
        smartdns::MockServer::AddIP(r, r->domain, "192.0.2.91", 60);
        return smartdns::SERVER_REQUEST_OK;
    }));
    int fd = socket(AF_INET, SOCK_DGRAM, 0); ASSERT_GE(fd, 0);
    timeval timeout{0,500000}; ASSERT_EQ(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)),0);
    sockaddr_in target{}; target.sin_family=AF_INET;target.sin_port=htons(62997);
    inet_pton(AF_INET,"127.0.0.1",&target.sin_addr);
    unsigned char wire[]={0x73,0x31,1,0,0,1,0,0,0,0,0,0,1,'x',0,0,1,0,1};
    unsigned char reply[512];
    ASSERT_EQ(sendto(fd,wire,sizeof(wire),0,reinterpret_cast<sockaddr *>(&target),sizeof(target)),sizeof(wire));
    ASSERT_GT(recv(fd,reply,sizeof(reply),0),12);
    bool blocked=false;auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    do {
        std::ifstream state("/proc/self/task/"+std::to_string(tid.load())+"/syscall");std::string call;state>>call;
#ifdef SYS_poll
        blocked=call==std::to_string(SYS_poll);
#endif
#ifdef SYS_ppoll
        blocked=blocked || call==std::to_string(SYS_ppoll);
#endif
        if(blocked)break;
        poll(nullptr,0,1);
    }while(std::chrono::steady_clock::now()<deadline);
    ASSERT_TRUE(blocked) << "mock must be waiting in poll before signal injection";
    ASSERT_EQ(pthread_kill(worker.load(),SIGUSR2),0);
    deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(250);
    while(!mock_signal_seen.load() && std::chrono::steady_clock::now()<deadline)poll(nullptr,0,1);
    ASSERT_TRUE(mock_signal_seen.load());
    ASSERT_EQ(sendto(fd,wire,sizeof(wire),0,reinterpret_cast<sockaddr *>(&target),sizeof(target)),sizeof(wire));
    int received=recv(fd,reply,sizeof(reply),0);close(fd);
    std::cout << "Interrupted mock poll: reply_bytes=" << received << std::endl;
    EXPECT_GT(received,12) << "an interrupted poll must not insert a one-second mock outage";
}
}
TEST(MockServer, InterruptedPollDoesNotDelayReply) {
    ::testing::FLAGS_gtest_death_test_style="threadsafe";
    ASSERT_EXIT({interrupted_mock_case();_exit(::testing::Test::HasFailure()?1:0);},::testing::ExitedWithCode(0),"");
}

TEST(MockServer, query_fail)
{
	smartdns::MockServer server;
	smartdns::Client client;
	server.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		request->response_data_len = 0;
		return smartdns::SERVER_REQUEST_ERROR;
	});

	ASSERT_TRUE(client.Query("example.com", 61053));
	std::cout << client.GetResult() << std::endl;
	EXPECT_EQ(client.GetStatus(), "SERVFAIL");
}

TEST(MockServer, soa)
{
	smartdns::MockServer server;
	smartdns::Client client;
	server.Start("udp://0.0.0.0:61053",
				 [](struct smartdns::ServerRequestContext *request) { return smartdns::SERVER_REQUEST_SOA; });

	ASSERT_TRUE(client.Query("example.com", 61053));
	std::cout << client.GetResult() << std::endl;
	EXPECT_EQ(client.GetStatus(), "NXDOMAIN");
}

TEST(MockServer, noerror)
{
	smartdns::MockServer server;
	smartdns::Client client;
	server.Start("udp://0.0.0.0:61053",
				 [](struct smartdns::ServerRequestContext *request) { return smartdns::SERVER_REQUEST_OK; });

	ASSERT_TRUE(client.Query("example.com", 61053));
	std::cout << client.GetResult() << std::endl;
	EXPECT_EQ(client.GetStatus(), "NOERROR");
}
