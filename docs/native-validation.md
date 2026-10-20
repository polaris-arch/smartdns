# Native and release validation

The existing C/C++ workflow covers pushes and pull requests targeting both
`master` and the fork's `polaris-main`. The isolated candidate branch retains its
push trigger. Ordinary CI runs the complete unfiltered existing suite once in
Ubuntu 24.04 system OpenSSL and once in Debian trixie QUIC-capable OpenSSL.

## Explicit release mode

Dispatch the same workflow at the exact candidate commit/ref with boolean input
`release_validation: true`. This runs the two complete suites under AddressSanitizer
and UndefinedBehaviorSanitizer instead of duplicating the ordinary jobs. It also
runs the bounded comparative workload in the QUIC distribution container.
Normal push runs do not enable these additional costs. Record both the ordinary
run and release-mode run, including their exact source SHA, before declaring the
candidate release-validated.

The sanitizer lane uses the existing make extension points for C compilation,
C++ test compilation and linking. It cleans old objects, enables ASan and UBSan,
keeps frame pointers, and does not recover from sanitizer findings. Leak detection
is enabled; no suppressions are installed. Existing forked server children use
`_exit`, so normal exit-time leak scanning does not cover those child lifetimes;
this mode does not claim complete leak detection. The ordinary full suite has a
10-minute runtime cap; the sanitizer full suite has a 30-minute cap. Both use
TERM followed by KILL after 15 seconds and fail on timeout, inside the existing
45-minute job cap. Five seconds before either suite deadline, a bounded best-effort
process/thread, kernel wait-channel/stack and open-FD snapshot is saved alongside
the last reported test. Kernel stack access may be denied; this is recorded rather
than treated as proof that no hang exists. No retry or test filter is applied. A child-process sanitizer report fails
the lane even if its parent test process exits successfully. Missing/skipped
critical tests continue to fail the existing XML gate. A sanitizer failure must
be diagnosed, including whether it is inherited from the pinned upstream base;
it is not permission to suppress a category of findings or expand product scope.

## Offline comparative measurement

Source preparation retrieves the exact upstream baseline
`dfc9ef4bd947891178924c06070fbccc3ea370ba` and archives it together with the exact
candidate HEAD. Compilation and workloads run with Docker `--network none` and
check that loopback is the only network interface. No public DNS or provider
traffic is possible in the measurement container.

Both binaries are rebuilt in fresh directories with the same compiler, linked
libraries and `-O2 -g -fno-omit-frame-pointer` flags, without sanitizers. Version
metadata generation is disabled equally. Artifacts retain source and archive
identities, compiler and library details, binary hashes, raw samples and workload
results. An ephemeral loopback certificate is shared by the local HTTPS fixtures
and is not included in artifacts.

The measurement program uses deterministic names and bounded operation counts.
Common-config comparisons and candidate-only aggregate-mode observations must
remain separate. Successful answers, error responses and timeouts are accounted
separately: a fast rejection is not a latency improvement. Upstream send counts
are observed at the local fixture and reported per logical measured lookup.
No artificial performance pass threshold is imposed. Functional preconditions
and accounting errors still fail validation.

The comparison has a 10-minute wall-clock cap. Existing normal Perf/Stress tests
remain unchanged and unfiltered. Results describe these local workloads, not
public-provider quota dimensions or interoperability, arbitrary Internet traffic,
or a guarantee of zero overhead. Process RSS/CPU measurements are not allocation
counts, and instrumented sanitizer timing is not compared with normal timing.
