#!/bin/sh
set -eu

IMAGE_TAG="${IMAGE_TAG:-dns-encrypted-proxy-ci-test:local}"

docker build -f Dockerfile.ci-test -t "$IMAGE_TAG" .

docker run --rm \
  -v "$(pwd):/work" \
  -w /work \
  "$IMAGE_TAG" \
  sh -lc "tools/ci_test_matrix.sh"
