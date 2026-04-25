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

The `coverage` target runs the full ctest suite, prints the per-file table, gates on the line-coverage threshold (default 80%, configurable via `-DCOVERAGE_LINE_THRESHOLD=<percent>`), and writes `build/coverage/coverage.html` for browsing. Below threshold the build fails before the HTML is regenerated, so the previous report stays available for triage.

## CI-Equivalent Strict Build

```bash
cmake -S . -B build/release -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON -DWARNINGS_AS_ERRORS=ON
cmake --build build/release -j
ctest --test-dir build/release --output-on-failure
```

## Static Analysis

The build defines four analysis targets; each is independent.

### `cppcheck`

Runs cppcheck with `--enable=warning,performance,portability` over `src/`. Gates the build (non-zero exit on any finding).

```bash
cmake --build build/release --target cppcheck
```

### `lint` and `lint-strict`

Both run `clang-tidy` against the project's `compile_commands.json` using rules in `.clang-tidy`.

- `lint` is advisory — surfaces findings, exits 0 regardless. Use during development.
- `lint-strict` propagates clang-tidy's exit code. Use to gate.

```bash
cmake --build build/release --target lint
cmake --build build/release --target lint-strict
```

### `stack-usage`

Per-function frame-size check against a 64KB limit (configurable via `-DSTACK_USAGE_LIMIT_BYTES=...`). Requires `-DENABLE_STACK_USAGE_CHECK=ON` at configure time so the compiler emits `.su` files.

```bash
cmake -S . -B build/analyze -DCMAKE_BUILD_TYPE=Debug -DENABLE_STACK_USAGE_CHECK=ON
cmake --build build/analyze
cmake --build build/analyze --target stack-usage
```

### GCC `-fanalyzer`

`-DENABLE_ANALYZER=ON` adds `-fanalyzer` to production-source compilation (skipped on test targets, where it false-positives heavily). Findings surface as warnings during the build itself; with `-Werror` they fail compilation.

```bash
cmake -S . -B build/analyze -DCMAKE_BUILD_TYPE=Debug -DENABLE_ANALYZER=ON
cmake --build build/analyze
```

### `analyze`

Umbrella target that runs `lint`, `cppcheck`, and (when stack-usage is enabled) `stack-usage`.

```bash
cmake -S . -B build/analyze -DCMAKE_BUILD_TYPE=Debug -DENABLE_ANALYZER=ON -DENABLE_STACK_USAGE_CHECK=ON
cmake --build build/analyze --target analyze
```

## Docker CI Mirror (Recommended)

Use the dedicated CI test image and run the same matrix script used by GitLab:

```bash
sh tools/run_ci_tests_docker.sh
```

This builds `Dockerfile.ci-test`, installs ngtcp2 v1.12.0 and c-log, and runs `tools/ci_test_matrix.sh` across all upstream feature combinations.
