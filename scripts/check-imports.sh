#!/usr/bin/env bash
# Fail if the scanner module imports net, net/http, or os/exec.
set -euo pipefail
cd "$(dirname "$0")/.."
forbidden='^(net|net/http|net/http/.*|os/exec)$'
fail=0
for goos in linux darwin windows; do
  for goarch in amd64 arm64; do
    deps="$(GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go list -deps -f '{{.ImportPath}}' ./cmd/... ./internal/...)"
    if printf '%s\n' "$deps" | grep -E "$forbidden"; then
      echo "forbidden import for ${goos}/${goarch}" >&2
      fail=1
    fi
  done
done
if ! printf '%s\n' "$(GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go list -deps -f '{{.ImportPath}}' ./internal/scan)" | grep -qx 'github.com/ucsurf/aftermath/internal/scan'; then
  echo "scanner package missing from go list" >&2
  fail=1
fi
exit "$fail"
