#!/bin/sh
set -eu

IMAGE_TAG="${IMAGE_TAG:-dns-encrypted-proxy-ci-test:local}"

docker build -f Dockerfile.ci-test -t "$IMAGE_TAG" .

# Wipe build/bin before launching the matrix. CMAKE_RUNTIME_OUTPUT_DIRECTORY
# points all targets at $repo/build/bin, which is shared between local Gentoo
# glibc builds and Alpine musl builds run inside the container. Make's
# incremental build only re-links targets whose direct deps changed; stale
# glibc binaries left over from a local `cmake --build build/release` run can
# survive a matrix invocation when they happen to not need relinking, and
# Alpine's sh chokes on them with a misleading "not found" because the glibc
# dynamic linker isn't in the container. Wiping build/bin forces every target
# to relink against musl in this run.
rm -rf build/bin

# Run as the host user so build artifacts written into the bind-mounted
# /work tree are owned by the host user, not root. Without --user the
# container runs as root and every cmake/ninja/ctest output ends up
# root-owned on the host, requiring sudo to clean.
#
# HOME=/tmp covers the case where the chosen UID has no entry in the
# container's /etc/passwd; tools that probe $HOME (cmake user package
# registry, etc.) get a writable directory rather than failing on '/'.
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -v "$(pwd):/work" \
  -w /work \
  "$IMAGE_TAG" \
  sh -lc "tools/ci_test_matrix.sh"
