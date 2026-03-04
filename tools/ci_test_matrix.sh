#!/bin/sh
set -eu

if [ "${BASH_VERSION-}" ]; then
  set -o pipefail
fi

if [ -z "${C_LOG_PATH:-}" ]; then
  if [ -d /tmp/c-log ]; then
    C_LOG_PATH=/tmp/c-log
  elif [ -d /opt/c-log ]; then
    C_LOG_PATH=/opt/c-log
  else
    echo "C_LOG_PATH is not set and no default c-log path exists" >&2
    exit 1
  fi
fi

BUILD_ROOT="${BUILD_ROOT:-build-matrix-ci}"
BUILD_TESTS="${BUILD_TESTS:-ON}"
BUILD_BENCHMARKS="${BUILD_BENCHMARKS:-OFF}"

mkdir -p "$BUILD_ROOT"

for doh in OFF ON; do
  for dot in OFF ON; do
    for doq in OFF ON; do
      if [ "$doh" = "OFF" ] && [ "$dot" = "OFF" ] && [ "$doq" = "OFF" ]; then
        continue
      fi

      combo="doh-${doh}_dot-${dot}_doq-${doq}"
      bdir="$BUILD_ROOT/$combo"

      echo "==> Configure $combo"
      cmake -S . -B "$bdir" \
        -DC_LOG_PATH="$C_LOG_PATH" \
        -DBUILD_TESTS="$BUILD_TESTS" \
        -DBUILD_BENCHMARKS="$BUILD_BENCHMARKS" \
        -DENABLE_UPSTREAM_DOH="$doh" \
        -DENABLE_UPSTREAM_DOT="$dot" \
        -DENABLE_UPSTREAM_DOQ="$doq"

      echo "==> Build $combo"
      cmake --build "$bdir" -j

      echo "==> Test $combo"
      ctest --test-dir "$bdir" --output-on-failure --timeout 30
    done
  done
done
