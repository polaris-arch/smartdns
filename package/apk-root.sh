#!/bin/sh
# Normalize only a helper-owned snapshot; apk.static bypasses LD_PRELOAD fakeroot.
set -eu
reject() { echo "Unsafe APK build path: $1" >&2; exit 2; }
[ "$#" -ge 3 ] || reject "missing arguments"
raw=$1
while [ "${raw%/}" != "$raw" ]; do raw=${raw%/}; done
if [ ! -d "$raw" ] || [ -L "$raw" ]; then reject "staging is not a real directory"; fi
stage=$(realpath "$raw")
[ "$raw" = "$stage" ] || reject "staging has a path alias"
parent=$(dirname "$stage")
[ "$(basename "$stage")" = root ] && [ "$(dirname "$parent")" = /tmp ] || reject "staging is outside a package build"
case "$(basename "$parent")" in smartdns-openwrt.*|luci-app-smartdns.*) ;; *) reject "unknown staging prefix" ;; esac
[ "$(stat -c %a "$parent")" = 700 ] || reject "build directory is not private"
owner=$(stat -c '%u:%g' "$parent")
uid=${owner%:*}
caller=$(id -u)
if [ "$uid" != "$caller" ] && { [ "$caller" != 0 ] || [ "$uid" != "${SUDO_UID:-0}" ]; }; then reject "foreign staging owner"; fi
[ "$(stat -c %u "$stage")" = "$uid" ] || reject "foreign stage owner"
case "${2##*/}" in smartdns.*.apk|luci-app-smartdns.*.apk|luci-app-smartdns-lite.*.apk) ;; *) reject "unexpected output name" ;; esac
if [ -L "$2" ] || { [ -e "$2" ] && [ ! -f "$2" ]; }; then reject "output is not a regular file"; fi
outdir=$(realpath "$(dirname "$2")")
[ "$(stat -c %u "$outdir")" = "$uid" ] || reject "foreign output directory"
output="$outdir/$(basename "$2")"
if [ -e "$output" ] && [ "$(stat -c %u "$output")" != "$uid" ]; then reject "foreign output owner"; fi
apk=$(realpath "$3")
shift 3
if [ "$caller" != 0 ]; then
    exec sudo -n /bin/sh "$(realpath "$0")" "$stage" "$output" "$apk" "$@"
fi
work=$(mktemp -d /tmp/smartdns-apk-build.XXXXXXXX)
cleanup() {
    result=$?
    trap - EXIT
    rm -rf -- "$work" || result=1
    if [ -f "$output" ] && [ ! -L "$output" ]; then chown -h -- "$owner" "$output" || result=1; fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
mkdir "$work/root" "$work/verify"
cp -a -- "$stage/." "$work/root/"
chown -hR -- 0:0 "$work/root"
"$apk" mkpkg --files "$work/root" "$@"
"$apk" --allow-untrusted extract --destination "$work/verify" "$output"
bad=$(find "$work/verify" \( ! -uid 0 -o ! -gid 0 \) -print -quit)
if [ -n "$bad" ]; then echo "APK contains a non-root file or directory: $bad" >&2; exit 1; fi
