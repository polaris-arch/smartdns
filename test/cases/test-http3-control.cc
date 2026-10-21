#include "gtest/gtest.h"
extern "C" {
#include "dns_client/client_http3_control.h"
#include "smartdns/http_parse.h"
}
#include <vector>
#include <cstring>
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
namespace {
struct Control {
    dns_server_info server{};
    ~Control() { _dns_http3_control_free(&server); }
    int Feed(unsigned slot, const std::vector<unsigned char> &v) {
        return _dns_http3_control_test_feed(&server, slot, v.data(), v.size());
    }
};
}
TEST(Http3Control, SettingsAtEverySplitAndLegalNonminimalVarints) {
    const std::vector<unsigned char> bytes = {0x40,0,0x80,0,0,4,0xc0,0,0,0,0,0,0,0};
    for (size_t split = 0; split <= bytes.size(); split++) {
        Control c;
        EXPECT_EQ(c.Feed(0, {bytes.begin(), bytes.begin()+split}), 0);
        EXPECT_EQ(c.Feed(0, {bytes.begin()+split, bytes.end()}), 0);
    }
}
TEST(Http3Control, MissingRepeatedAndDuplicateUnknownSettingsFail) {
    { Control c; EXPECT_LT(c.Feed(0, {0,7,1,0}), 0); }
    { Control c; EXPECT_LT(c.Feed(0, {0,4,0,4,0}), 0); }
    { Control c; EXPECT_LT(c.Feed(0, {0,4,4,0x21,0,0x21,1}), 0); }
    { Control c; EXPECT_LT(c.Feed(0, {0,4,2,2,0}), 0); }
}
TEST(Http3Control, UnknownFramesSkipIncrementally) {
    Control c;
    EXPECT_EQ(c.Feed(0, {0,4,0,0x21,4,1}), 0);
    EXPECT_EQ(c.Feed(0, {2,3,4,7,1,0}), 0);
    EXPECT_FALSE(_dns_http3_request_allowed(&c.server, 0, 0));
}
TEST(Http3Control, DuplicateCriticalStreamsAndPushRejected) {
    Control c;
    EXPECT_EQ(c.Feed(0, {2}), 0);
    EXPECT_LT(c.Feed(1, {2}), 0);
    Control push;
    EXPECT_LT(push.Feed(0, {1}), 0);
}
TEST(Http3Control, ZeroCapacityEncoderAndLegalDecoderCancellation) {
    { Control c; EXPECT_EQ(c.Feed(0, {2}), 0); EXPECT_EQ(c.Feed(0, {0x20}), 0); }
    { Control c; EXPECT_EQ(c.Feed(0, {3,0x40}), 0); }
    { Control c; EXPECT_EQ(c.Feed(0, {3,0x7f}), 0); EXPECT_EQ(c.Feed(0, {1}), 0); }
    { Control c; EXPECT_LT(c.Feed(0, {3,0x80}), 0); }
    { Control c; EXPECT_LT(c.Feed(0, {3,1}), 0); }
}
TEST(Http3Control, GoogleZeroCapacityIsIdempotentAndDoesNotAllowDynamicInstructions) {
    const std::vector<unsigned char> bytes = {2,0x20,0x20};
    for (size_t split = 0; split <= bytes.size(); split++) {
        Control c;
        EXPECT_EQ(c.Feed(0, {bytes.begin(), bytes.begin()+split}), 0);
        EXPECT_EQ(c.Feed(0, {bytes.begin()+split, bytes.end()}), 0);
        EXPECT_EQ(_dns_http3_error(&c.server), 0U);
        EXPECT_TRUE(_dns_http3_request_allowed(&c.server, 0, 0));
    }
    for (unsigned char instruction : {0x00,0x1f,0x21,0x3f,0x40,0x80,0xc0}) {
        Control c;
        EXPECT_LT(c.Feed(0, {2,0x20,instruction}), 0);
        EXPECT_EQ(_dns_http3_error(&c.server), 0x201U);
    }
}
TEST(Http3Control, GoawayStopsNewAndClassifiesAlreadyStarted) {
    Control c;
    EXPECT_EQ(c.Feed(0, {0,4,0,7,1,8}), 0);
    EXPECT_FALSE(_dns_http3_request_allowed(&c.server, 0, 0));
    EXPECT_TRUE(_dns_http3_request_allowed(&c.server, 4, 1));
    EXPECT_FALSE(_dns_http3_request_allowed(&c.server, 8, 1));
    EXPECT_EQ(c.Feed(0, {7,1,4}), 0);
    EXPECT_LT(c.Feed(0, {7,1,8}), 0);
}
#endif
TEST(Http3RequestFraming, RejectSettingsOnRequestStream) {
    const unsigned char bytes[] = {4,0};
    http_head *head = http_head_init(4096, HTTP_VERSION_3_0);
    ASSERT_NE(head, nullptr);
    EXPECT_LT(http_head_parse(head, bytes, sizeof(bytes)), 0);
    http_head_destroy(head);
}
TEST(Http3RequestFraming, StaticOnlyQpackAllowsPositiveMultibyteBase) {
    const unsigned char bytes[] = {1,4,0,0x7f,1,0xd9}; // RIC=0, Base=128, static :status 200
    http_head *head = http_head_init(4096, HTTP_VERSION_3_0);
    ASSERT_NE(head, nullptr);
    EXPECT_GE(http_head_parse(head, bytes, sizeof(bytes)), 0);
    EXPECT_EQ(http_head_get_httpcode(head), 200);
    http_head_destroy(head);
}
TEST(Http3RequestFraming, IncompleteVarintIsNotReadPastInput) {
    const unsigned char bytes[] = {1};
    http_head *head = http_head_init(4096, HTTP_VERSION_3_0);
    ASSERT_NE(head, nullptr);
    EXPECT_LT(http_head_parse(head, bytes, sizeof(bytes)), 0);
    http_head_destroy(head);
}
