#!/usr/bin/env bash
# Run only inside the distribution container with --network none.
set -euo pipefail
: "${CI_NATIVE_PROFILE:?system or quic required}"
case "$CI_NATIVE_PROFILE" in system|quic) ;; *) exit 2 ;; esac
case "${CI_NATIVE_SANITIZERS:-0}" in 0|1) ;; *) exit 2 ;; esac
mkdir -p ci-results
{
    cat /etc/os-release
    cc --version
    c++ --version
    openssl version -a
    dpkg-query -W libssl-dev libgtest-dev dnsperf dnsutils curl openssl zlib1g-dev
    curl --version
    cat /proc/net/route
    cat /proc/net/ipv6_route
} > ci-results/environment.txt
# Refuse an accidentally network-enabled runtime. Loopback is the only interface.
python3 - <<'PY'
import socket
names = {name for _, name in socket.if_nameindex()}
assert names == {'lo'}, f'Expected isolated loopback only, got {names}'
for family, address in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.bind((address, 0))
PY
# Legacy discovery fixtures use documentation-only addresses. Give those
# synthetic destinations loopback routes; no default route or external interface
# is introduced. NET_ADMIN is confined to this --network none container.
ip route add 192.0.2.0/24 dev lo
ip route add 198.51.100.0/24 dev lo
ip route add 203.0.113.0/24 dev lo
ip -6 route add 2001:db8::/32 dev lo
ip -j route show > ci-results/fixture-routes-v4.json
ip -j -6 route show > ci-results/fixture-routes-v6.json
command -v dig
command -v dnsperf
curl --version | grep -q HTTP2
# Both compile-time headers and linked runtime must match the intended capability.
cat > /tmp/native-ssl-capability.c <<'C'
#include <openssl/ssl.h>
#include <stdio.h>
#ifdef REQUIRE_QUIC
#if OPENSSL_VERSION_NUMBER < 0x30500000L || !defined(OSSL_QUIC1_VERSION) || defined(OPENSSL_NO_QUIC)
#error OpenSSL 3.5 QUIC headers required
#endif
#else
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
#error Ordinary system job must retain non-QUIC compile coverage
#endif
#endif
int main(void) {
    printf("headers=%lx runtime=%lx %s\n", (unsigned long)OPENSSL_VERSION_NUMBER,
           OpenSSL_version_num(), OpenSSL_version(OPENSSL_VERSION));
#ifdef REQUIRE_QUIC
    if (OpenSSL_version_num() < 0x30500000L) return 1;
    /* Resolve actual server API; a header-only check cannot establish availability. */
    if (OSSL_QUIC_server_method() == NULL) return 1;
#endif
    return 0;
}
C
flags=()
if [[ "$CI_NATIVE_PROFILE" == quic ]]; then flags+=(-DREQUIRE_QUIC); fi
cc "${flags[@]}" /tmp/native-ssl-capability.c -o /tmp/native-ssl-capability -lssl -lcrypto
/tmp/native-ssl-capability | tee ci-results/ssl-capability.txt
# Existing make extension points instrument both C production code and C++ tests.
# Never reuse objects from an uninstrumented build.
if [[ "${CI_NATIVE_SANITIZERS:-0}" == 1 ]]; then
    make -C test clean
    export EXTRA_CFLAGS="-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all"
    export CXXFLAGS="-O1 -fsanitize=address,undefined -fno-sanitize-recover=all"
    export EXTRA_LDFLAGS="-fsanitize=address,undefined"
    export ASAN_OPTIONS="detect_leaks=1:halt_on_error=1:abort_on_error=1"
    export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
    printf '%s\n' "EXTRA_CFLAGS=$EXTRA_CFLAGS" "CXXFLAGS=$CXXFLAGS" \
        "EXTRA_LDFLAGS=$EXTRA_LDFLAGS" "ASAN_OPTIONS=$ASAN_OPTIONS" \
        "UBSAN_OPTIONS=$UBSAN_OPTIONS" > ci-results/sanitizer-options.txt
fi
# Preserve the upstream build-clean-test sequence. No test filter or stress override.
make all -j4
make clean
make -C test -j8
ldd test/test.bin > ci-results/test-linked-libraries.txt
suite_seconds=600
suite_log=ci-results/native-test.log
if [[ "${CI_NATIVE_SANITIZERS:-0}" == 1 ]]; then
    grep -q 'libasan\.' ci-results/test-linked-libraries.txt
    grep -q 'libubsan\.' ci-results/test-linked-libraries.txt
    suite_seconds=1800
    suite_log=ci-results/sanitizer-test.log
fi
# Capture live state before timeout terminates the process group. This is a
# diagnostic, not a retry or a pass condition; unavailable kernel stacks are noted.
(
    sleeper=
    trap '[[ -z "$sleeper" ]] || kill "$sleeper" 2>/dev/null || :; exit 0' TERM INT
    sleep "$((suite_seconds - 5))" &
    sleeper=$!
    wait "$sleeper" || exit 0
    sleeper=
    # Bound the snapshot itself, including cat/ls children. A blocked diagnostic
    # must not strand the wrapper's cleanup wait after the suite terminates.
    timeout --signal=TERM --kill-after=1s 3s bash -c '
        suite_seconds=$1
        suite_log=$2
        echo "Suite deadline approaching: ${suite_seconds}s; $(date -u +%FT%TZ)"
        grep "^\[ RUN " "$suite_log" | tail -1 || :
        # /proc only: avoid dependencies, credentials, environments and core dumps.
        processes=0
        for proc in /proc/[0-9]*; do
            [[ -r "$proc/comm" ]] || continue
            IFS= read -r comm < "$proc/comm" || continue
            case "$comm" in test.bin|smartdns|dig|dnsperf) ;; *) continue ;; esac
            echo "PROCESS ${proc##*/} $comm"
            cat "$proc/status" 2>/dev/null || :
            ls -l "$proc/fd" 2>/dev/null | head -65 || :
            threads=0
            for task in "$proc"/task/[0-9]*; do
                echo "THREAD ${task##*/}"
                cat "$task/wchan" 2>/dev/null || :
                echo
                cat "$task/stack" 2>&1 || :
                threads=$((threads + 1))
                if (( threads >= 64 )); then echo "Thread snapshot capped at 64"; break; fi
            done
            processes=$((processes + 1))
            if (( processes >= 128 )); then echo "Process snapshot capped at 128"; break; fi
        done
    ' diagnostic "$suite_seconds" "$suite_log" > ci-results/pre-timeout-diagnostics.txt 2>&1 || :
) &
diagnostic_pid=$!
set +e
# Include tee in the timeout process group: a stuck descendant retaining stdout
# must not leave an unbounded outer tee waiting for EOF after test.bin exits.
timeout --signal=TERM --kill-after=15s "${suite_seconds}s" \
    bash -o pipefail -c './test/test.bin --gtest_output=xml:ci-results/results.xml 2>&1 | tee "$1"' \
    suite "$suite_log"
result=$?
kill "$diagnostic_pid" 2>/dev/null || :
wait "$diagnostic_pid" 2>/dev/null || :
set -e
if [[ "$result" == 124 || "$result" == 137 ]]; then
    echo "Complete suite exceeded ${suite_seconds}s; this run fails. See pre-timeout-diagnostics.txt." >&2
fi
# Child-process sanitizer findings fail even if GoogleTest reports success.
if [[ "${CI_NATIVE_SANITIZERS:-0}" == 1 ]] &&
    grep -Eq 'ERROR: (AddressSanitizer|LeakSanitizer)|AddressSanitizer:DEADLYSIGNAL|LeakSanitizer has encountered a fatal error|runtime error:' "$suite_log"; then
    echo 'Sanitizer report found; no suppressions are applied.' >&2
    exit 1
fi
exit "$result"
