#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${NODEKIT_BUILD_ROOT:-$(dirname "$ROOT")}
export GOCACHE="$BUILD/cache" GOMODCACHE="$BUILD/modules" GOTMPDIR="$BUILD/tmp" GOTOOLCHAIN=local GOMAXPROCS=2
mkdir -p "$GOCACHE" "$GOMODCACHE" "$GOTMPDIR"
cd "$ROOT"
exec nice -n 10 go "$@"
