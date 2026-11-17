# Testing Guide

This project uses CMocka-based unit and integration tests plus optional coverage reporting.

## Prerequisites

- `cmocka`
- `python3` (required for DoH integration tests that use local HTTPS mock upstream)
- `python3` + `aioquic` (optional; used by DoQ integration transport test peer)

## Build and Run All Tests

```bash
make -j test BUILD=debug
```

`make test` builds the proxy and every test binary for the selected variant and
transport set, then runs each one from the repo root with a 30 s timeout
(`TEST_TIMEOUT=`). A failing test prints its captured output; full logs stay in
`build/<variant>/<test>.log`. All test binaries land in `build/bin/` alongside
`dns-encrypted-proxy`.

On a toolchain newer than CI's (for example OpenSSL 4 or cmocka 2, which
deprecate APIs the code still uses), add `WERROR=0` to build locally; CI keeps
`-Werror`.

## Test Binaries

- `./build/bin/test_errors`
- `./build/bin/test_config`
- `./build/bin/test_cache`
- `./build/bin/test_cache_internal`
- `./build/bin/test_dns_message`
- `./build/bin/test_dns_message_internal`
- `./build/bin/test_upstream`
- `./build/bin/test_upstream_internal`
- `./build/bin/test_upstream_bootstrap_internal`
- `./build/bin/test_upstream_dispatch_internal`
- `./build/bin/test_upstream_doh_internal` (DOH=1)
- `./build/bin/test_upstream_dot_internal` (DOT=1)
- `./build/bin/test_upstream_doq_internal`, `test_upstream_doq_ngtcp2_internal` (DOQ=1)
- `./build/bin/test_iterative_resolver_internal`
- `./build/bin/test_metrics_internal`
- `./build/bin/test_dns_server_internal`
- `./build/bin/test_integration_core`
- `./build/bin/test_integration_transport`
- `./build/bin/test_integration_runtime`

Run one suite directly from the repo root:

```bash
./build/bin/test_dns_server_internal
```

## Coverage

```bash
make -j coverage
```

Builds the `coverage` variant, clears stale `.gcda` data, runs the full suite,
then runs gcovr twice: the first pass prints the per-file table and gates on
line coverage (default 80%, `COVERAGE_LINE_THRESHOLD=<percent>`), the second
writes `build/coverage/coverage.html`. Below threshold the run fails before the
HTML is regenerated, so the previous report stays available for triage.

## Static Analysis

### `analyze`

```bash
make -j analyze
```

Builds the proxy and the tests in the `analyze` variant with `-fstack-usage`,
and production sources with `-fanalyzer` as well (analyzer findings fail the
build through `-Werror`; tests are excluded from the analyzer because they
deliberately walk paths it flags), then runs `cppcheck`, `stack-usage` and
`lint` in turn. This is what CI's analyze job runs.

### `cppcheck`

Runs cppcheck with `--enable=warning,performance,portability` over `src/`.
Gates (non-zero exit on any finding).

```bash
make cppcheck
```

### `lint` and `lint-strict`

Both run `clang-tidy` with the rules in `.clang-tidy` against a
`compile_commands.json` the Makefile writes into the variant's object
directory (`make compdb` writes it on its own, for editors).

- `lint` is advisory: surfaces findings, exits 0 regardless.
- `lint-strict` propagates clang-tidy's exit code. Use to gate.

```bash
make lint
make lint-strict
```

### `stack-usage`

Per-function frame-size check against a 64 KB limit (`STACK_USAGE_LIMIT=`),
read from the `.su` files the `analyze` variant emits for production and
test code alike.

```bash
make stack-usage
```

## Docker CI Mirror (Recommended)

Use the dedicated CI test image and run the same matrix script used by GitLab:

```bash
tools/run_ci_tests_docker.sh
```

This builds `Dockerfile.ci-test`, installs ngtcp2 v1.12.0 and c-log, and runs `tools/ci_test_matrix.sh` across all upstream feature combinations. Container builds go to `build/matrix-ci/` so they never share objects with a host build in `build/matrix/`.
