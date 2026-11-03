#include "gtest/gtest.h"
extern "C" {
#include "dns_client/client_socket.h"
#include "dns_client/upstream_service.h"
#include "dns_client/upstream_discovery.h"
#include "smartdns/http2.h"
#include "smartdns/util.h"
}
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <thread>

namespace {
class ClientH2Maintenance : public ::testing::Test {
protected:
    dns_server_info endpoint{};
    dns_upstream_service service{};
    dns_discovery_snapshot desired{};
    bool armed = false, close_on_write = false, unlocked = true;
    unsigned writes = 0;
    size_t input_offset = 0;
    static int Read(void *arg, uint8_t *data, int size) {
        auto *self = static_cast<ClientH2Maintenance *>(arg);
        // Server SETTINGS and its ACK of the client's SETTINGS.
        static const uint8_t input[] = {0,0,0,4,0,0,0,0,0, 0,0,0,4,1,0,0,0,0};
        if (self->input_offset == sizeof(input)) { errno = EAGAIN; return -1; }
        size_t count = std::min(static_cast<size_t>(size), sizeof(input) - self->input_offset);
        memcpy(data, input + self->input_offset, count); self->input_offset += count;
        return count;
    }
    static int Write(void *arg, const uint8_t *, int size) {
        auto *self = static_cast<ClientH2Maintenance *>(arg);
        if (self->armed) {
            int result = EBUSY;
            // Probe from another thread: a recursive lock on this thread would hide inversion.
            std::thread probe([&] {
                result = pthread_mutex_trylock(&self->endpoint.lock);
                if (!result) pthread_mutex_unlock(&self->endpoint.lock);
            });
            probe.join();
            self->unlocked = self->unlocked && result == 0; ++self->writes;
            if (self->close_on_write) {
                self->close_on_write = false;
                _dns_client_close_socket(&self->endpoint);
            }
        }
        return size;
    }
    void SetUp() override {
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr); pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&endpoint.lock, &attr); pthread_mutexattr_destroy(&attr);
        pthread_mutex_init(&service.lock, nullptr);
        INIT_LIST_HEAD(&endpoint.conn_stream_list); atomic_set(&endpoint.refcnt, 1);
        endpoint.fd = -1; endpoint.type = DNS_SERVER_HTTPS;
        endpoint.status = DNS_SERVER_STATUS_CONNECTED; endpoint.service_protocol_ready = 1;
        service.desired = &desired; service.member_count = 1; service.members[0] = &endpoint;
        service.config.keepalive_ms = 10;
        endpoint.http2_ctx = http2_ctx_client_new("fixture", Read, Write, this, nullptr);
        ASSERT_NE(endpoint.http2_ctx, nullptr);
        for (unsigned i = 0; i < 8 && !http2_ctx_handshake_ready(endpoint.http2_ctx); ++i)
            ASSERT_GE(http2_ctx_handshake(endpoint.http2_ctx), 0);
        ASSERT_TRUE(http2_ctx_handshake_ready(endpoint.http2_ctx));
        armed = true;
    }
    void TearDown() override {
        armed = false;
        _dns_client_close_socket(&endpoint);
        pthread_mutex_destroy(&endpoint.lock); pthread_mutex_destroy(&service.lock);
    }
};
}

TEST_F(ClientH2Maintenance, KeepaliveIoDoesNotHoldEndpointLock) {
    _dns_service_connection_tick(&service, get_tick_count());
    EXPECT_GT(writes, 0u); EXPECT_TRUE(unlocked);
    EXPECT_EQ(endpoint.process_depth, 0u);
    EXPECT_NE(endpoint.http2_ctx, nullptr);
}

TEST_F(ClientH2Maintenance, ReentrantCloseWaitsForMaintenanceToReleaseTransport) {
    close_on_write = true;
    _dns_service_connection_tick(&service, get_tick_count());
    EXPECT_GT(writes, 0u); EXPECT_TRUE(unlocked);
    EXPECT_EQ(endpoint.process_depth, 0u);
    EXPECT_EQ(endpoint.close_deferred, 0);
    EXPECT_EQ(endpoint.http2_ctx, nullptr);
    EXPECT_EQ(endpoint.status, DNS_SERVER_STATUS_DISCONNECTED);
}
