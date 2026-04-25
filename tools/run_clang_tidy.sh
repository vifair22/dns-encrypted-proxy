#!/bin/sh
# Wrapper around clang-tidy used by the CMake 'lint' / 'lint-strict' targets.
#
# Usage: run_clang_tidy.sh <strict|advisory> <build-dir> <source-files...>
#
# The 'advisory' mode swallows clang-tidy's non-zero exit so the lint target
# surfaces findings without blocking the build. The 'strict' mode propagates
# the exit code as-is.

set -eu

mode="$1"
build_dir="$2"
shift 2

case "$mode" in
    strict|advisory) ;;
    *) echo "run_clang_tidy.sh: mode must be strict or advisory, got '$mode'" >&2; exit 2 ;;
esac

set +e
clang-tidy \
    -p "$build_dir" \
    --quiet \
    --extra-arg=-Wno-unknown-warning-option \
    --extra-arg=-Qunused-arguments \
    "$@"
rc=$?
set -e

if [ "$mode" = "advisory" ] && [ "$rc" -ne 0 ]; then
    echo "lint: clang-tidy reported findings (advisory mode — not failing the build)"
    exit 0
fi
exit "$rc"
