#!/usr/bin/env bash
set -euo pipefail
repo=$PWD
driver=$repo/.github/verification/closure.py
manifest=$repo/.github/verification/closure.json
proof=${PROOF:?}
mkdir -p "$proof"
trap 'find "$proof" -name "*.log" -type f -exec gzip -f {} \;' EXIT
git config --global --add safe.directory "$repo"
if [[ ${PUBLIC_REPRO:-0} == 1 ]]; then
    python3 .github/verification/public-reproduce.py
    exit
fi
openssl version -a > "$proof/openssl.txt"
dpkg-query -W gcc g++ libssl-dev libc6 libgtest-dev zlib1g-dev > "$proof/packages.txt"
if [[ ${PROFILE:-} == integration || ${PROFILE:-} == sanitizers || ${PROFILE:-} == compat32 ]]; then
    root=/tmp/closure-combined
    git worktree add --detach "$root" HEAD
    cd "$root"
    git rev-parse HEAD HEAD^{tree} > "$proof/source.txt"
    if [[ $PROFILE == sanitizers ]]; then
        make -C test -j4 CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' CXXFLAGS='-O1 -g -DTEST -I./ -I../src -I../src/include -fsanitize=address,undefined -fno-omit-frame-pointer' EXTRA_LDFLAGS='-fsanitize=address,undefined' > "$proof/build.log" 2>&1
        export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
    else
        make -C test -j4 > "$proof/build.log" 2>&1
    fi
    filter='*'
    if [[ $PROFILE != integration ]]; then filter='LibConf.*:CacheCheckpoint.*:Ping.*:ThreadStartup.*:HeaderCompression.*:LIBHTTP2.*:Http2Cancellation.*:Http2Scheduling.*:HTTP2.CancelledZeroWindow*:HTTP2.ConnectedDohRequests*:Http3Control.*:Http3RequestFraming.*:QuicLifecycle.*:QuicEndToEnd.*:Cache.InvalidPersisted*:Cache.BrokenRecordFraming*:Cache.ValidLargeTtl*:Cache.FuturePersisted*:Cache.ValidPersistedCounterBounds*:Cache.PersistedExpiry*:Cache.TtlConsumers*'; fi
    executor=()
    if [[ $PROFILE == compat32 && $EUID != 0 ]]; then executor=(sudo); fi
    ./test/test.bin --gtest_list_tests > "$proof/compiled-tests.txt"
    "${executor[@]}" timeout 900 ./test/test.bin --gtest_filter="$filter" --gtest_output="xml:$proof/candidate.xml" > "$proof/candidate.log" 2>&1
    python3 - "$proof/candidate.xml" "$manifest" "$PROFILE" <<'PY'
import json,sys,xml.etree.ElementTree as E
r=E.parse(sys.argv[1]).getroot();assert int(r.attrib['failures'])==0 and int(r.attrib.get('errors',0))==0
cases={c.attrib['classname']+'.'+c.attrib['name']:c for c in r.iter('testcase')}
for item in json.load(open(sys.argv[2])):
 if item['pr']==2486 or (sys.argv[3]=='compat32' and item['pr']==2494):continue
 for name in item['required_tests']:
  assert name in cases and cases[name].find('skipped') is None,name
print(r.attrib)
PY
    sha256sum test/test.bin src/libsmartdns-test.a > "$proof/binaries.sha256"
    readelf -h test/test.bin > "$proof/elf.txt"
    ldd test/test.bin > "$proof/libraries.txt"
    exit
fi
eval "$(python3 - "$manifest" "$PR" <<'PY'
import json,shlex,sys
t=next(t for t in json.load(open(sys.argv[1])) if t['pr']==int(sys.argv[2]))
for key,value in [('CANDIDATE',t['sha']),('BASE',t['base']),('FILTER',t['test_filter']),('NEGATIVE_FILTER',t.get('negative_filter',t['test_filter']))]:print(key+'='+shlex.quote(str(value)))
PY
)"
if [[ $PR == 2486 && ( -n ${CARGO_BUILD_TARGET:-} || ${UI_COMBINED:-0} == 1 ) ]]; then
    CANDIDATE=$(git rev-parse HEAD)
    printf '%s\n' 'combined-UI: statistics plus cache native-time ABI compatibility; isolated statistics proof is separately bound to its manifest topic SHA' > "$proof/source-scope.txt"
    cp "$manifest" "$proof/component-candidates.json"
fi
root=/tmp/closure-candidate
git worktree add --detach "$root" "$CANDIDATE"
git rev-parse "$CANDIDATE" "$CANDIDATE^{tree}" "$BASE" > "$proof/source.txt"
git diff --check "$BASE" "$CANDIDATE"
if [[ $PR == 2486 ]]; then
    cd "$root"
    make -C src -j4 WITH_ZLIB=0 EXTRA_CFLAGS=-fPIC libsmartdns-test.a > "$proof/native-build.log" 2>&1
    # Match the compiler/flags used for the native library; compare with bindgen's
    # actual Rust type below rather than inferring time_t from CPU bitness.
    cat > "$proof/time-abi.c" <<'C'
#include <stdint.h>
#include <stdio.h>
#include <time.h>
int main(void) {
    printf("cache callback ABI: pointer_bytes=%zu time_t_bytes=%zu time_t_max=%jd\n",
        sizeof(void *), sizeof(time_t), (intmax_t)(sizeof(time_t) == 4 ? INT32_MAX : INT64_MAX));
    return 0;
}
C
    read -r -a abi_cc <<< "${CC:-cc}"
    read -r -a abi_flags <<< "${CFLAGS:-}"
    "${abi_cc[@]}" "${abi_flags[@]}" "$proof/time-abi.c" -o "$proof/time-abi"
    "$proof/time-abi" > "$proof/time-abi.txt"
    "${abi_cc[@]}" "${abi_flags[@]}" -dM -E -include time.h -x c /dev/null > "$proof/time-abi-macros.txt"
    "${abi_cc[@]}" -print-sysroot > "$proof/sysroot.txt"
    printf 'CC=%s\nCFLAGS=%s\nBINDGEN_EXTRA_CLANG_ARGS=%s\nCARGO_BUILD_TARGET=%s\n' \
        "${CC:-cc}" "${CFLAGS:-}" "${BINDGEN_EXTRA_CLANG_ARGS:-}" "${CARGO_BUILD_TARGET:-}" > "$proof/abi-flags.txt"
    cp "$repo/.github/verification/closure.Cargo.lock" plugin/smartdns-ui/Cargo.lock
    rustc --version > "$proof/rust.txt"
    cargo --version >> "$proof/rust.txt"
    if [[ -n ${CARGO_BUILD_TARGET:-} ]]; then rustc --print cfg --target "$CARGO_BUILD_TARGET" > "$proof/rust-cfg.txt"; else rustc --print cfg > "$proof/rust-cfg.txt"; fi
    cp plugin/smartdns-ui/src/data_stats.rs "$proof/data_stats.rs"
    (cd plugin/smartdns-ui && cargo test --locked --lib "$FILTER" -- --test-threads=1) > "$proof/candidate.log" 2>&1
    (cd plugin/smartdns-ui && cargo test --locked --lib -- --test-threads=1 --nocapture) > "$proof/full-library.log" 2>&1
    if [[ ${UI_COMBINED:-0} == 1 || -n ${CARGO_BUILD_TARGET:-} ]]; then
        python3 - "$proof/full-library.log" "$proof/time-abi.txt" <<'PY'
import sys
text=open(sys.argv[1]).read()
assert 'smartdns::tests::cache_callback_preserves_native_timestamp_width' in text
assert open(sys.argv[2]).read().strip() in text, 'C and bindgen time_t ABI differ'
assert 'test result: ok. 5 passed; 0 failed; 0 ignored' in text
PY
    fi
    python3 "$driver" inverse-ui plugin/smartdns-ui/src/data_stats.rs
    set +e
    (cd plugin/smartdns-ui && cargo test --locked --lib "$FILTER" -- --test-threads=1) > "$proof/baseline.log" 2>&1
    result=$?
    set -e
    test "$result" -eq 101
    python3 - "$proof" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);assert 'test result: ok. 3 passed; 0 failed; 0 ignored' in (p/'candidate.log').read_text()
text=(p/'baseline.log').read_text()
assert 'test result: FAILED' in text
failures=text.rsplit('\nfailures:\n',1)[1].split('\n\ntest result:',1)[0].splitlines()
failures={line.strip() for line in failures}
assert failures == {'data_stats::regression_tests::'+name for name in [
    'request_drop_accumulates',
    'request_drop_parallel_updates_are_not_lost',
    'request_drop_persistent_initialization_accumulates_without_reset',
]}
PY
    cp "$proof/data_stats.rs" plugin/smartdns-ui/src/data_stats.rs
    sha256sum plugin/smartdns-ui/Cargo.lock > "$proof/lock.sha256"
    cp plugin/smartdns-ui/Cargo.lock "$proof/Cargo.lock"
    git diff --exit-code -- src plugin test
    exit
fi
baseline=/tmp/closure-baseline
git worktree add --detach "$baseline" "$BASE"
python3 "$driver" baseline "$baseline" --manifest "$manifest" --pr "$PR"
git -C "$baseline" diff --binary > "$proof/baseline-instrumentation.patch"
make -C "$baseline/test" -j4 > "$proof/baseline-build.log" 2>&1
set +e
timeout 600 "$baseline/test/test.bin" --gtest_filter="$NEGATIVE_FILTER" --gtest_output="xml:$proof/baseline.xml" > "$proof/baseline.log" 2>&1
result=$?
set -e
test "$result" -eq 1
python3 "$driver" xml "$proof/baseline.xml" --manifest "$manifest" --pr "$PR" --negative
make -C "$root/test" -j4 > "$proof/candidate-build.log" 2>&1
timeout 600 "$root/test/test.bin" --gtest_filter="$FILTER" --gtest_output="xml:$proof/candidate.xml" > "$proof/candidate.log" 2>&1
python3 "$driver" xml "$proof/candidate.xml" --manifest "$manifest" --pr "$PR"
sha256sum "$root/test/test.bin" "$root/src/libsmartdns-test.a" > "$proof/binaries.sha256"
if [[ $PR == 2493 ]]; then
    file="$root/src/dns_client/client_http2.c"
    cp "$file" "$proof/client_http2.c"
    python3 "$driver" inverse-h2-wakeup "$file"
    git -C "$root" diff --binary > "$proof/inverse-wakeup.patch"
    make -C "$root/test" -j4 > "$proof/inverse-wakeup-build.log" 2>&1
    set +e
    timeout 30 "$root/test/test.bin" --gtest_filter=Http2Scheduling.ConcurrentEnqueueCannotLoseWriteInterest --gtest_output="xml:$proof/inverse-wakeup.xml" > "$proof/inverse-wakeup.log" 2>&1
    result=$?
    set -e
    test "$result" -eq 1
    python3 - "$proof/inverse-wakeup.xml" <<'PY'
import sys,xml.etree.ElementTree as E
r=E.parse(sys.argv[1]).getroot();assert int(r.attrib['tests'])==1 and int(r.attrib['failures'])==1
c=next(r.iter('testcase'));assert c.attrib['name']=='ConcurrentEnqueueCannotLoseWriteInterest' and c.find('failure') is not None
PY
    cp "$proof/client_http2.c" "$file"
    make -C "$root/test" -j4 > "$proof/restored-build.log" 2>&1
    timeout 60 "$root/test/test.bin" --gtest_filter='Http2Scheduling.*' --gtest_output="xml:$proof/restored.xml" > "$proof/restored.log" 2>&1
fi
if [[ $PR == 2487 || $PR == 2489 ]]; then
    previous=/tmp/closure-previous
    old=$(python3 - "$manifest" "$PR" <<'PY'
import json,sys
print(next(t for t in json.load(open(sys.argv[1])) if t['pr']==int(sys.argv[2]))['previous_head'])
PY
)
    git worktree add --detach "$previous" "$old"
    if [[ $PR == 2487 ]]; then file=test-lib-conf.cc; filter=LibConf.DefaultTlsCertificatesStayBesideTheTopConfiguration; else file=test-ping.cc; filter=Ping.Ipv6ReadinessCallerRetainsItsStopReferenceAfterEarlyEnd; fi
    cp "$root/test/cases/$file" "$previous/test/cases/$file"
    make -C "$previous/test" -j4 > "$proof/previous-build.log" 2>&1
    set +e
    timeout 60 "$previous/test/test.bin" --gtest_filter="$filter" --gtest_output="xml:$proof/previous.xml" > "$proof/previous.log" 2>&1
    result=$?
    set -e
    test "$result" -eq 1
    python3 - "$proof/previous.xml" <<'PY'
import sys,xml.etree.ElementTree as E
r=E.parse(sys.argv[1]).getroot();assert int(r.attrib['tests'])==1 and int(r.attrib['failures'])==1
assert next(r.iter('testcase')).find('failure') is not None
PY
fi
git -C "$root" diff --exit-code -- src test
