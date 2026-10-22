#!/bin/sh
# Prepare only from the verified archive; never trust an old extracted/build cache.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$HERE/source.conf"
[ "$#" -eq 2 ] || { echo "usage: $0 ARCHIVE NEW_DESTINATION" >&2; exit 1; }
ARCHIVE=$(CDPATH= cd -- "$(dirname -- "$1")" && pwd)/$(basename -- "$1")
DEST=$2
[ ! -e "$DEST" ] && [ ! -L "$DEST" ] || { echo "destination already exists: $DEST" >&2; exit 1; }
printf '%s  %s\n' "$SMARTDNS_WEBUI_SHA256" "$ARCHIVE" | sha256sum -c -
PARENT=$(CDPATH= cd -- "$(dirname -- "$DEST")" && pwd)
DEST=$PARENT/$(basename -- "$DEST")
TMP=$(mktemp -d "$PARENT/.smartdns-webui.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
tar -xzf "$ARCHIVE" -C "$TMP"
SRC=$TMP/smartdns-webui-$SMARTDNS_WEBUI_COMMIT
(cd "$SRC" && sha256sum -c "$HERE/preimage.sha256")
(cd "$SRC" && patch --batch --forward --fuzz=0 -p1 < "$HERE/service-pool.patch")
(cd "$SRC" && sha256sum -c "$HERE/postimage.sha256")
# An upstream archive must not smuggle a prebuilt output past the build step.
rm -rf "$SRC/out" "$SRC/.next" "$SRC/node_modules"
mv "$SRC" "$DEST"
