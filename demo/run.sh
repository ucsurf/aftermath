#!/bin/sh
cd "$(dirname "$0")/.." || exit 2
# Git stores this fixture as a normal file. A private mode is the usual case.
chmod 600 demo/fixtures/home/.npmrc 2>/dev/null || true
exec ./aftermath scan \
  --home demo/fixtures/home \
  --system-root demo/fixtures/system \
  --temp-dir demo/fixtures/temp \
  --platform linux \
  --username dev
