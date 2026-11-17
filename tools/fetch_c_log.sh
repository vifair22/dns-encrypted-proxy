#!/bin/bash
# Fetch c-log at the commit pinned in tools/c-log.ref into DEST.
#
# Every build path (CI jobs, the release and CI-test images, the .deb job)
# goes through here so the c-log a binary was built against is a property of
# this repo's history, not of whatever c-log master was on the day. c-log
# has no tags, so the pin is a full SHA; GitLab serves a shallow fetch of an
# arbitrary reachable commit, which `git clone --branch` cannot do.
#
# Usage: fetch_c_log.sh DEST
#   C_LOG_REF=<sha>  override the pin (for testing a c-log change)
#   C_LOG_URL=<url>  override the remote
set -euo pipefail

dest="${1:?usage: $0 DEST}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ref="${C_LOG_REF:-$(tr -d '[:space:]' < "$here/c-log.ref")}"
url="${C_LOG_URL:-https://git.airies.net/vifair22/c-log.git}"

if [[ ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
    echo "fetch_c_log: pin must be a full 40-char SHA, got '$ref'" >&2
    exit 1
fi

rm -rf "$dest"
mkdir -p "$dest"
git -C "$dest" init -q
git -C "$dest" fetch -q --depth 1 "$url" "$ref"
git -C "$dest" checkout -q FETCH_HEAD

got="$(git -C "$dest" rev-parse HEAD)"
if [ "$got" != "$ref" ]; then
    echo "fetch_c_log: wanted $ref, got $got" >&2
    exit 1
fi
echo "fetch_c_log: c-log $ref -> $dest"
