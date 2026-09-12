#!/usr/bin/env sh
# Downloads the official Wintun release and drops bin/amd64/wintun.dll where the Tauri bundler expects it.
# The DLL is not in git: run this once before `cargo tauri build`.
set -eu
VERSION=0.14.1
SHA256=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
DEST="$(cd "$(dirname "$0")/.." && pwd)/src-tauri/resources"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/wintun.zip" "https://www.wintun.net/builds/wintun-$VERSION.zip"
if command -v sha256sum >/dev/null 2>&1; then
	echo "$SHA256  $TMP/wintun.zip" | sha256sum -c -
else
	echo "$SHA256  $TMP/wintun.zip" | shasum -a 256 -c -
fi
unzip -q -o "$TMP/wintun.zip" -d "$TMP/x"
DLL="$(find "$TMP/x" -path "*bin/amd64/wintun.dll" -print -quit)"
test -n "$DLL" || { echo "bin/amd64/wintun.dll missing from the archive" >&2; exit 1; }
mkdir -p "$DEST"
cp "$DLL" "$DEST/wintun.dll"
echo "wintun $VERSION placed at $DEST/wintun.dll"
