#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${NODEKIT_BUILD_ROOT:-$(dirname "$ROOT")}
VERSION=${1:-v0.2.0}
[[ $VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
mkdir -p "$BUILD/dist"
stage=$(mktemp -d "$BUILD/package-XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch bash "$ROOT/scripts/build.sh" build -trimpath -ldflags '-s -w' -o "$stage/nodekit" ./cmd/nodekit
  case "$arch" in
    amd64) asset=mihomo-linux-amd64-v1-v1.19.33.gz; sha=8ec92e7b2fdc6b853ba00156bab7e4e965c8b0d843b8c4ac8ab98795f02ad524 ;;
    arm64) asset=mihomo-linux-arm64-v1.19.33.gz; sha=ba408b317080ee265c46cb923a50018c1b82cbd708551cdd46a1e3e307396187 ;;
  esac
  curl -fLsS --retry 2 "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/$asset" -o "$stage/core.gz"
  printf '%s  %s\n' "$sha" "$stage/core.gz" | sha256sum -c -
  gzip -dc "$stage/core.gz" > "$stage/mihomo"
  chmod 755 "$stage/mihomo" "$stage/nodekit"
  printf '{"version":"%s","arch":"%s","core_version":"v1.19.33","schema":1}\n' "$VERSION" "$arch" > "$stage/release.json"
  tar -czf "$BUILD/dist/nodekit-$VERSION-linux-$arch.tar.gz" -C "$stage" nodekit mihomo release.json
done
cd "$BUILD/dist"
sha256sum nodekit-"$VERSION"-linux-*.tar.gz > SHA256SUMS
cat SHA256SUMS
