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

# Strip GCC-only flags from compile_commands.json before clang-tidy reads it.
# When the build is configured with -DENABLE_ANALYZER=ON, every TU's compile
# args contain -fanalyzer (a GCC flag clang doesn't recognize). clang-tidy
# uses clang as its frontend and emits clang-diagnostic-error per TU, which
# drowns the actual lint output. -Qunused-arguments / -Wno-unknown-warning-option
# don't help — -fanalyzer is rejected at the driver level, not as a warning.
filtered_dir=$(mktemp -d)
trap 'rm -rf "$filtered_dir"' EXIT
sed 's/ -fanalyzer//g' "$build_dir/compile_commands.json" > "$filtered_dir/compile_commands.json"

set +e
clang-tidy \
    -p "$filtered_dir" \
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
