#ifndef SMARTDNS_TEST_FIXTURE_STARTUP_H
#define SMARTDNS_TEST_FIXTURE_STARTUP_H

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <sys/types.h>

namespace smartdns {

struct FixtureReadyResult {
	int poll_result = 0;
	ssize_t bytes = -1;
	uint64_t notification = 0;
	int error = 0;
	bool IsReady() const { return poll_result > 0 && bytes == sizeof(notification) && notification == 1; }
};

/* Callbacks keep interruption/deadline tests deterministic, without signals or
 * sleeps. The live fixture supplies monotonic milliseconds, poll and read. */
template <typename Now, typename Poll, typename Read>
FixtureReadyResult WaitForFixtureReady(int timeout_ms, Now now, Poll poll_ready, Read read_ready)
{
	FixtureReadyResult result;
	const int64_t deadline = now() + timeout_ms;
	for (;;) {
		const int64_t remaining = deadline - now();
		if (remaining <= 0) { result.poll_result = 0; return result; }
		result.poll_result = poll_ready(static_cast<int>(remaining));
		if (result.poll_result < 0 && errno == EINTR) continue;
		if (result.poll_result <= 0) {
			result.error = result.poll_result < 0 ? errno : 0;
			return result;
		}
		result.bytes = read_ready(result.notification);
		if (result.bytes < 0 && (errno == EINTR || errno == EAGAIN)) continue;
		result.error = result.bytes < 0 ? errno : 0;
		return result;
	}
}

class FixtureStartupCancellation {
public:
	/* Reset only before starting a worker, never while a worker can access it. */
	void Reset() { initialized_.store(false); cancelled_.store(false); }
	bool MarkInitialized() { initialized_.store(true); return cancelled_.load(); }
	bool Cancel() { cancelled_.store(true); return initialized_.load(); }
private:
	/* Sequential consistency guarantees at least one side observes the other
	 * flag. Stop is issued only after init, which otherwise resets run=1. */
	std::atomic<bool> initialized_{false};
	std::atomic<bool> cancelled_{false};
};

} // namespace smartdns
#endif
