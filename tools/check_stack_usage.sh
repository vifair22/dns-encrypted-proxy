#!/bin/bash
# Check that no per-function stack frame exceeds the configured limit.
#
# Reads .su files emitted by gcc -fstack-usage. Each row is:
#   <source-and-line>:<func>\t<bytes>\t<qualifier>
# where qualifier is one of: static, dynamic, dynamic,bounded.
#
# Usage: check_stack_usage.sh <build-dir> <limit-bytes>

set -euo pipefail

BUILD_DIR="${1:?usage: $0 <build-dir> <limit-bytes>}"
LIMIT="${2:?usage: $0 <build-dir> <limit-bytes>}"

if [ ! -d "$BUILD_DIR" ]; then
    echo "stack-usage: build dir not found: $BUILD_DIR" >&2
    exit 2
fi

su_files=$(find "$BUILD_DIR" -name '*.su' 2>/dev/null || true)
if [ -z "$su_files" ]; then
    echo "stack-usage: no .su files found under $BUILD_DIR — was -DENABLE_STACK_USAGE_CHECK=ON used?" >&2
    exit 2
fi

violations=0
max_seen=0
max_func=""
while IFS=$'\t' read -r where bytes _qual; do
    [ -z "$bytes" ] && continue
    # 'dynamic' rows have no useful number; skip them
    case "$bytes" in
        ''|*[!0-9]*) continue ;;
    esac
    if [ "$bytes" -gt "$max_seen" ]; then
        max_seen="$bytes"
        max_func="$where"
    fi
    if [ "$bytes" -gt "$LIMIT" ]; then
        printf 'stack-usage: %s uses %s bytes (limit %s)\n' "$where" "$bytes" "$LIMIT" >&2
        violations=$((violations + 1))
    fi
done < <(cat $su_files)

if [ "$violations" -gt 0 ]; then
    echo "stack-usage: $violations function(s) over the ${LIMIT}-byte limit" >&2
    exit 1
fi

printf 'stack-usage: OK — largest frame %s bytes (%s) under %s-byte limit\n' "$max_seen" "$max_func" "$LIMIT"
