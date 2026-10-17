#!/bin/sh
# Build the CLI with its nearest release tag and separate build identity.
# Usage: scripts/build.sh [-o /path/to/netinspect] [other go build flags]
set -eu
cd "$(dirname "$0")/.."
release_tag=$(git describe --tags --abbrev=0 2>/dev/null || printf dev)
build_id=$(git rev-parse --short=12 HEAD 2>/dev/null || printf local)
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then build_id="$build_id-dirty"; fi
exec go build -ldflags "-X=netinspect/internal/version.Tag=$release_tag -X=netinspect/internal/version.Build=$build_id" "$@" ./cmd/netinspect
