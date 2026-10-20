#include "gtest/gtest.h"
#include "include/fixture_startup.h"
#include <thread>
#include <vector>

TEST(FixtureStartup, InterruptedPollRetainsSingleDeadline)
{
	int64_t now = 0;
	std::vector<int> budgets;
	auto ready = smartdns::WaitForFixtureReady(10, [&] { return now; },
		[&](int remaining) {
			budgets.push_back(remaining);
			if (budgets.size() <= 2) { now += 3; errno = EINTR; return -1; }
			return 1;
		},
		[](uint64_t &value) -> ssize_t { value = 1; return sizeof(value); });
	EXPECT_TRUE(ready.IsReady());
	EXPECT_EQ(budgets, (std::vector<int>{10, 7, 4}));
}

TEST(FixtureStartup, RepeatedInterruptionsCannotExtendDeadline)
{
	int64_t now = 0;
	std::vector<int> budgets;
	int reads = 0;
	auto ready = smartdns::WaitForFixtureReady(10, [&] { return now; },
		[&](int remaining) {
			budgets.push_back(remaining);
			now += remaining < 4 ? remaining : 4;
			errno = EINTR;
			return -1;
		},
		[&](uint64_t &) -> ssize_t { ++reads; return 0; });
	EXPECT_FALSE(ready.IsReady());
	EXPECT_EQ(ready.poll_result, 0);
	EXPECT_EQ(now, 10);
	EXPECT_EQ(reads, 0);
	EXPECT_EQ(budgets, (std::vector<int>{10, 6, 2}));
}

TEST(FixtureStartup, InterruptedOrWouldBlockReadRetriesWithinDeadline)
{
	int64_t now = 0;
	std::vector<int> budgets;
	int reads = 0;
	auto ready = smartdns::WaitForFixtureReady(10, [&] { return now; },
		[&](int remaining) { budgets.push_back(remaining); return 1; },
		[&](uint64_t &value) -> ssize_t {
			++reads;
			if (reads < 3) { now += 2; errno = reads == 1 ? EINTR : EAGAIN; return -1; }
			value = 1;
			return sizeof(value);
		});
	EXPECT_TRUE(ready.IsReady());
	EXPECT_EQ(budgets, (std::vector<int>{10, 8, 6}));
}

TEST(FixtureStartup, EofPartialAndFailureNotificationsAreNotReady)
{
	for (ssize_t size : {ssize_t{0}, ssize_t{3}, ssize_t{-1}, ssize_t{8}}) {
		auto ready = smartdns::WaitForFixtureReady(10, [] { return int64_t{0}; },
			[](int) { return 1; },
			[&](uint64_t &value) -> ssize_t { value = 2; errno = EIO; return size; });
		EXPECT_FALSE(ready.IsReady()) << "size=" << size;
		EXPECT_EQ(ready.bytes, size);
	}
	for (int result : {0, -1}) {
		int reads = 0;
		auto ready = smartdns::WaitForFixtureReady(10, [] { return int64_t{0}; },
			[&](int) { errno = EBADF; return result; },
			[&](uint64_t &) -> ssize_t { ++reads; return 0; });
		EXPECT_FALSE(ready.IsReady());
		EXPECT_EQ(reads, 0);
		EXPECT_EQ(ready.error, result < 0 ? EBADF : 0);
	}
}

TEST(FixtureStartup, CancellationCannotBeLostAcrossInitialization)
{
	smartdns::FixtureStartupCancellation startup;
	EXPECT_FALSE(startup.Cancel());       // Must not stop before init resets run.
	EXPECT_TRUE(startup.MarkInitialized()); // Worker performs the deferred stop.
	startup.Reset();                       // No worker exists at reset.
	EXPECT_FALSE(startup.MarkInitialized());
	EXPECT_TRUE(startup.Cancel());         // Parent stops an initialized worker.
	for (int i = 0; i < 64; ++i) {
		startup.Reset();
		bool worker_stops = false;
		std::thread worker([&] { worker_stops = startup.MarkInitialized(); });
		bool parent_stops = startup.Cancel();
		worker.join();
		EXPECT_TRUE(worker_stops || parent_stops);
	}
}
