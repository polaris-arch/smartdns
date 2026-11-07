#!/bin/sh
# Build the pinned, architecture-independent pages once into WORKDIR.
set -eu
CURR_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$CURR_DIR/webui/source.conf"
[ "$#" -eq 1 ] || { echo "usage: $0 WORKDIR" >&2; exit 1; }
WORKDIR=$1
SMARTDNS_WEBUI_SOURCE="$WORKDIR/smartdns-webui"

mkdir -p "$WORKDIR" || exit 1
WEBUI_ARCHIVE="$WORKDIR/smartdns-webui-$SMARTDNS_WEBUI_COMMIT.tar.gz"
if [ ! -f "$WEBUI_ARCHIVE" ]; then
	WEBUI_DOWNLOAD=$(mktemp "$WORKDIR/.webui-download.XXXXXX") || exit 1
	if ! wget -O "$WEBUI_DOWNLOAD" "$SMARTDNS_WEBUI_URL" ||
	   ! printf '%s  %s\n' "$SMARTDNS_WEBUI_SHA256" "$WEBUI_DOWNLOAD" | sha256sum -c -; then
		rm -f "$WEBUI_DOWNLOAD"
		exit 1
	fi
	mv "$WEBUI_DOWNLOAD" "$WEBUI_ARCHIVE" || exit 1
fi
# Always validate cached archive and rebuild a clean source. An existing
# out/index.html is not evidence of the pinned source or the local patch.
WEBUI_BUILD=$(mktemp -d "$WORKDIR/webui-build.XXXXXX") || exit 1
if ! "$CURR_DIR/webui/prepare-source.sh" "$WEBUI_ARCHIVE" "$WEBUI_BUILD/source" ||
   ! npm ci --prefix "$WEBUI_BUILD/source" ||
   ! npm run build --prefix "$WEBUI_BUILD/source"; then
	rm -rf "$WEBUI_BUILD"
	exit 1
fi
rm -rf "$SMARTDNS_WEBUI_SOURCE"
mv "$WEBUI_BUILD/source" "$SMARTDNS_WEBUI_SOURCE" || exit 1
rmdir "$WEBUI_BUILD"
echo "smartdns-webui build completed."
