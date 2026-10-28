#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${NODEKIT_BUILD_ROOT:-$(dirname "$ROOT")}
tmp=$(mktemp -d "$BUILD/unit-root-XXXXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/etc/systemd/system" "$tmp/opt/nodekit/current" "$tmp/opt/nodekit/previous" "$tmp/run/nodekit" "$tmp/var/lib/nodekit"
cp "$ROOT/packaging/nodekit-core.service" "$ROOT/packaging/nodekit-manager.service" "$tmp/etc/systemd/system/"
cp /bin/true "$tmp/opt/nodekit/current/nodekit"
cp /bin/true "$tmp/opt/nodekit/current/mihomo"
cp /bin/true "$tmp/opt/nodekit/previous/nodekit"
for target in sysinit basic shutdown multi-user network-online; do
  printf '[Unit]\nDescription=Isolated verification fixture\nDefaultDependencies=no\n' > "$tmp/etc/systemd/system/$target.target"
done
systemd-analyze --root="$tmp" verify nodekit-core.service nodekit-manager.service
