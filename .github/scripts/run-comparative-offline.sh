#!/usr/bin/env bash
# Called only by explicit release_validation, inside the same --network none image.
set -euo pipefail
python3 - <<'PY'
import socket
assert {name for _, name in socket.if_nameindex()} == {'lo'}, 'Loopback-only runtime required'
PY
: "${PWD:?}"
source_dir=$PWD
out="$source_dir/ci-results/comparison"
mkdir -p "$out"
work=$(mktemp -d /tmp/smartdns-comparison.XXXXXX)
trap 'rm -rf "$work"' EXIT
# Do not benchmark ASan overhead or accidentally inherit sanitizer flags.
unset ASAN_OPTIONS UBSAN_OPTIONS EXTRA_CFLAGS EXTRA_LDFLAGS CXXFLAGS LDFLAGS
export CFLAGS='-O2 -g -fno-omit-frame-pointer'
export NO_GIT_VER=1
{
    printf 'CFLAGS=%s\nNO_GIT_VER=%s\n' "$CFLAGS" "$NO_GIT_VER"
    cc --version
    openssl version -a
    sha256sum .ci-baseline.tar .ci-candidate.tar
    cat ci-results/benchmark-baseline-sha.txt ci-results/source-sha.txt
} > "$out/build-identity.txt"
for variant in baseline candidate; do
    mkdir "$work/$variant"
    tar -xf ".ci-$variant.tar" -C "$work/$variant"
    make -C "$work/$variant" -j4 all
    sha256sum "$work/$variant/src/smartdns" > "$out/$variant-binary.sha256"
    ldd "$work/$variant/src/smartdns" > "$out/$variant-linked-libraries.txt"
done
# Loopback fixture credentials are temporary and are never uploaded as artifacts.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -keyout "$work/loopback.key" -out "$work/loopback.pem" >/dev/null 2>&1
timeout --signal=TERM --kill-after=15s 600s python3 .github/scripts/benchmark-native-offline.py \
    --baseline "$work/baseline/src/smartdns" --candidate "$work/candidate/src/smartdns" \
    --output-dir "$out/measurements" --tls-cert "$work/loopback.pem" --tls-key "$work/loopback.key"
