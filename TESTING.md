# Testing Guide

This project uses CMocka-based unit and integration tests plus optional coverage reporting.

## Prerequisites

- `cmocka`
- `python3` (required for DoH integration tests that use local HTTPS mock upstream)
- `python3` + `aioquic` (optional; used by DoQ integration transport test peer)

## Build and Run All Tests

```bash
cmake -S . -B build/debug -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON
cmake --build build/debug
ctest --test-dir build/debug --output-on-failure
```

All test binaries land in `build/bin/` alongside `dns-encrypted-proxy`.

## Test Binaries

- `./build/bin/test_config`
- `./build/bin/test_cache`
- `./build/bin/test_cache_internal`
- `./build/bin/test_dns_message`
- `./build/bin/test_dns_message_internal`
- `./build/bin/test_upstream`
- `./build/bin/test_upstream_internal`
- `./build/bin/test_upstream_doh_internal`
- `./build/bin/test_upstream_dot_internal`
- `./build/bin/test_metrics_internal`
- `./build/bin/test_dns_server_internal`
- `./build/bin/test_integration_core`
- `./build/bin/test_integration_transport`
- `./build/bin/test_integration_runtime`

Run a specific suite via CTest:

```bash
ctest --test-dir build/debug --output-on-failure -R test_dns_server_internal
```

## Coverage

```bash
cmake -S . -B build/coverage -DBUILD_TESTS=ON -DENABLE_COVERAGE=ON
cmake --build build/coverage -j
ctest --test-dir build/coverage --output-on-failure
```

If `gcovr` is installed:

```bash
gcovr -r . build/coverage --exclude "tests/|tools/" --print-summary
gcovr -r . build/coverage --exclude "tests/|tools/" --html-details -o build/coverage/coverage.html
```

Convenience target (when CMake finds `gcovr`):

```bash
cmake --build build/coverage --target coverage
```

## CI-Equivalent Strict Build

```bash
cmake -S . -B build/release -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON -DWARNINGS_AS_ERRORS=ON
cmake --build build/release -j
ctest --test-dir build/release --output-on-failure
```

## Docker CI Mirror (Recommended)

Use the dedicated CI test image and run the same matrix script used by GitLab:

```bash
sh tools/run_ci_tests_docker.sh
```

This builds `Dockerfile.ci-test`, installs ngtcp2 v1.12.0 and c-log, and runs `tools/ci_test_matrix.sh` across all upstream feature combinations.
