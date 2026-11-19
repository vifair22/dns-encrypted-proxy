#!/bin/bash
# Run the CI transport matrix locally inside the Alpine CI image.
set -euo pipefail

IMAGE_TAG="${IMAGE_TAG:-dns-encrypted-proxy-ci-test:local}"

docker build -f Dockerfile.ci-test -t "$IMAGE_TAG" .

# The container builds against musl, the host against glibc. They get
# separate trees (build/matrix-ci vs build/matrix) because .flags only tracks
# compiler flags, not the libc behind them: a shared tree would let make
# consider glibc objects up to date and link them into a musl binary.
#
# Run as the host user so files written into the bind-mounted tree stay
# owned by the host user, not root. HOME=/tmp covers a UID with no passwd
# entry in the container.
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e BUILD_ROOT=build/matrix-ci \
  -v "$(pwd):/work" \
  -w /work \
  "$IMAGE_TAG" \
  bash tools/ci_test_matrix.sh
