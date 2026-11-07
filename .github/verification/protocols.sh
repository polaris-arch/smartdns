#!/usr/bin/env bash
set -euo pipefail
repo=$PWD
root=/tmp/protocol-$PROFILE
proof=${PROOF:-/tmp/evidence}
mkdir -p "$proof"
trap 'find "$proof" -name "*.log" -type f -exec gzip -f {} \;' EXIT
git config --global --add safe.directory "$repo"
git worktree add --detach "$root" "$CANDIDATE"
cd "$root"
git rev-parse HEAD HEAD^ > "$proof/source.txt"
openssl version -a > "$proof/openssl.txt"
git diff --check HEAD^
if [ "$PROFILE" = http2 ] || [ "$PROFILE" = quic-http3 ]; then
  baseline=/tmp/baseline-$PROFILE
  git worktree add --detach "$baseline" 65832a19c248f8a0f8714304d819e1da408b3835
  export root baseline PROFILE
  python3 - <<'PY'
import os,re
from pathlib import Path
r=Path(os.environ['root']);b=Path(os.environ['baseline']);profile=os.environ['PROFILE']
if profile=='http2':
    s=(r/'test/cases/test-http2-cancellation.cc').read_text()
    keep={'AbortDiscardsUnscheduledBodyAndReleasesCapacity','NormalCloseStillFlushesAfterWindowUpdate'}
    s=s.replace('#include "dns_client/conn_stream.h"','#include "dns_client/conn_stream.h"\nstatic void http2_stream_abort(struct http2_stream *s) { http2_stream_close(s); }')
    filename='test-http2-cancellation.cc'
else:
    s=(r/'test/cases/test-quic-lifecycle.cc').read_text()
    keep={'LocalControlStartsWithSettingsAndRemainsOpen','ResetIsProcessedWithoutKernelReadability','HardReadErrorRetiresTheStream','CompleteDoqPayloadWaitsForNormalFin','StopSendingAloneRetiresTheWriteSide'}
    (b/'src/dns_client/client_http3_control.h').write_text((r/'src/dns_client/client_http3_control.h').read_text())
    s='#define UPSTREAM_BASELINE\n'+s
    with (b/'test/Makefile').open('a') as f:f.write('\nLDFLAGS += -Wl,--wrap=_dns_client_socket_ssl_recv_ext,--wrap=_dns_client_recv\n')
    filename='test-quic-lifecycle.cc'
# Preserve fixture and existing APIs; remove tests requiring new production APIs.
for m in reversed(list(re.finditer(r'TEST_F\([^,]+,\s*(\w+)\)\s*\{',s))):
    if m.group(1) in keep:continue
    depth=1;i=m.end()
    while depth:
        depth+=(s[i]=='{')-(s[i]=='}');i+=1
    s=s[:m.start()]+s[i:]
(b/'test/cases'/filename).write_text(s)
PY
  make -C "$baseline/test" -j4 > "$proof/baseline-build.log" 2>&1
  set +e
  timeout 180 "$baseline/test/test.bin" --gtest_filter='Http2Cancellation.*:QuicLifecycle.*' --gtest_output="xml:$proof/baseline.xml" > "$proof/baseline.log" 2>&1
  baseline_result=$?
  set -e
  test "$baseline_result" -eq 1
  python3 - "$proof/baseline.xml" <<'PY'
import sys,xml.etree.ElementTree as E
r=E.parse(sys.argv[1]).getroot()
assert int(r.attrib['failures'])>0 and int(r.attrib['tests'])>0
print('Baseline functional failures:',r.attrib['failures'])
PY
fi
if [ "$PROFILE" = http2 ]; then
  previous=/tmp/previous-http2
  git worktree add --detach "$previous" 80ebc59562f0749b3cfa3092c524337b9a053fa9
  cp "$root/test/cases/test-http2-cancellation.cc" "$previous/test/cases/test-http2-cancellation.cc"
  make -C "$previous/test" -j4 > "$proof/previous-build.log" 2>&1
  set +e
  timeout 60 "$previous/test/test.bin" --gtest_filter=Http2Cancellation.CompletedServerRequestStillHonorsPeerCancellation --gtest_output="xml:$proof/previous.xml" > "$proof/previous.log" 2>&1
  previous_result=$?
  set -e
  test "$previous_result" -eq 1
  python3 - "$proof/previous.xml" <<'PYPREVIOUS'
import sys,xml.etree.ElementTree as E
r=E.parse(sys.argv[1]).getroot()
assert int(r.attrib['tests'])==1 and int(r.attrib['failures'])==1
print('Previous complete-request cancellation regression reproduced.')
PYPREVIOUS
fi
if [ "$PROFILE" = sanitizers ]; then
  make -C test -j4 CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' CXXFLAGS='-O1 -g -DTEST -I./ -I../src -I../src/include -fsanitize=address,undefined -fno-omit-frame-pointer' EXTRA_LDFLAGS='-fsanitize=address,undefined' > "$proof/candidate-build.log" 2>&1
  export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
  filter='Http2Cancellation.*:Http3Control.*:Http3RequestFraming.*:QuicLifecycle.*:HeaderCompression.*:Cache.PersistedLifetimeAndCountersAreValidatedBeforeUse'
else
  make -C test -j4 > "$proof/candidate-build.log" 2>&1
  filter='*'
  if [ "$PROFILE" = quic-http3 ]; then filter='Http3Control.*:Http3RequestFraming.*:QuicLifecycle.*:*HTTP3*.*'; fi
fi
timeout 600 ./test/test.bin --gtest_filter="$filter" --gtest_output="xml:$proof/candidate.xml" > "$proof/candidate.log" 2>&1
python3 - "$proof/candidate.xml" "$PROFILE" <<'PY'
import sys,xml.etree.ElementTree as E
r=E.parse(sys.argv[1]).getroot()
assert int(r.attrib['failures'])==0
if sys.argv[2] in ('sanitizers','integration','quic-http3'):
    suite=r.find("testsuite[@name='QuicLifecycle']")
    assert suite is not None and int(suite.attrib['tests'])==10 and int(suite.attrib['skipped'])==0
print('Candidate:',r.attrib)
PY
git diff --exit-code -- src test
