#!/bin/bash
# Build and test every transport combination (DoH x DoT x DoQ, minus all-off).
#
# Each combination gets its own object and bin dir under $BUILD_ROOT so a
# rerun never links or runs a binary built for a different transport set.
set -euo pipefail

if [ -z "${C_LOG_PATH:-}" ]; then
  for candidate in /tmp/c-log /opt/c-log ../c-log; do
    if [ -f "$candidate/log.h" ]; then
      C_LOG_PATH=$candidate
      break
    fi
  done
fi
if [ -z "${C_LOG_PATH:-}" ]; then
  echo "C_LOG_PATH is not set and no default c-log checkout exists" >&2
  exit 1
fi

BUILD_ROOT="${BUILD_ROOT:-build/matrix}"
BUILD="${BUILD:-debug}"
JOBS="${JOBS:-$(nproc)}"

for doh in 0 1; do
  for dot in 0 1; do
    for doq in 0 1; do
      [ "$doh$dot$doq" = "000" ] && continue
      combo="doh-${doh}_dot-${dot}_doq-${doq}"
      bdir="$BUILD_ROOT/$combo"
      echo "==> $combo"
      make --no-print-directory -j"$JOBS" test \
        BUILD="$BUILD" DOH="$doh" DOT="$dot" DOQ="$doq" \
        C_LOG_PATH="$C_LOG_PATH" OBJ_DIR="$bdir" BIN_DIR="$bdir/bin"
    done
  done
done
