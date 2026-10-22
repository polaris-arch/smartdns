#!/bin/sh
# Offline preparation regression. Supply the pinned tarball, never a URL.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ "$#" -eq 1 ] || { echo "usage: $0 PINNED_ARCHIVE" >&2; exit 1; }
ARCHIVE=$(CDPATH= cd -- "$(dirname -- "$1")" && pwd)/$(basename -- "$1")
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
"$HERE/prepare-source.sh" "$ARCHIVE" "$TMP/good"
[ ! -e "$TMP/good/out" ] && [ ! -e "$TMP/good/node_modules" ]
printf 'keep\n' > "$TMP/good/sentinel"
if "$HERE/prepare-source.sh" "$ARCHIVE" "$TMP/good"; then exit 1; fi
[ "$(cat "$TMP/good/sentinel")" = keep ]
cp "$ARCHIVE" "$TMP/bad.tar.gz"
printf 'bad archive\n' >> "$TMP/bad.tar.gz"
if "$HERE/prepare-source.sh" "$TMP/bad.tar.gz" "$TMP/bad"; then exit 1; fi
[ ! -e "$TMP/bad" ]
mkdir "$TMP/hooks"
cp "$HERE"/prepare-source.sh "$HERE"/source.conf "$HERE"/*.sha256 "$HERE"/service-pool.patch "$TMP/hooks/"
# Reject wrong preimages before attempting patch application.
printf '%064d  src/lib/backend/server.ts\n' 0 > "$TMP/hooks/preimage.sha256"
if "$TMP/hooks/prepare-source.sh" "$ARCHIVE" "$TMP/wrong-preimage"; then exit 1; fi
[ ! -e "$TMP/wrong-preimage" ]
cp "$HERE/preimage.sha256" "$TMP/hooks/preimage.sha256"
sed 's/export interface UpStreamServers {/export interface DoesNotExist {/' "$HERE/service-pool.patch" > "$TMP/hooks/service-pool.patch"
if "$TMP/hooks/prepare-source.sh" "$ARCHIVE" "$TMP/wrong-patch"; then exit 1; fi
[ ! -e "$TMP/wrong-patch" ]
cp "$HERE/service-pool.patch" "$TMP/hooks/service-pool.patch"
printf '%064d  src/lib/backend/server.ts\n' 0 > "$TMP/hooks/postimage.sha256"
if "$TMP/hooks/prepare-source.sh" "$ARCHIVE" "$TMP/wrong-postimage"; then exit 1; fi
[ ! -e "$TMP/wrong-postimage" ]
. "$HERE/source.conf"
grep -Fx "SMARTDNS_WEBUI_SOURCE_VERSION:=$SMARTDNS_WEBUI_COMMIT" "$HERE/../openwrt/Makefile"
grep -Fx "SMARTDNS_WEBUI_HASH:=$SMARTDNS_WEBUI_SHA256" "$HERE/../openwrt/Makefile"
grep -Fx "SMARTDNS_WEBUI_SOURCE_URL:=${SMARTDNS_WEBUI_URL%/*}" "$HERE/../openwrt/Makefile"
echo 'PASS: pinned preparation, cache rejection, preimage/patch/postimage failure, OpenWrt pin parity'
