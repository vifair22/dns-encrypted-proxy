# Benchmarking Guide

This repository includes two benchmark tools:

- `cache_bench`: cache micro/macro performance
- `e2e_proxy_bench`: end-to-end proxy latency/throughput with local mock upstream

## Build Benchmarks

```bash
cmake -S . -B build/release -DCMAKE_BUILD_TYPE=Release -DBUILD_BENCHMARKS=ON
cmake --build build/release
```

Benchmark binaries land in `build/bin/` alongside the proxy.

## Cache Benchmark

Runs mixed lookup/store workloads across capacities and reports latency-at-depth and threaded scaling.

```bash
./build/bin/cache_bench
./build/bin/cache_bench 500000
./build/bin/cache_bench 500000 8
```

- arg1: operations per capacity
- arg2: max thread count for threaded sweep (`1,2,4,...,max`)

Performance step log is tracked in:

- `CACHE_PERF_STEPS.md`

## End-to-End Proxy Benchmark

`e2e_proxy_bench` launches:

1. local HTTPS mock DoH upstream (`tools/mock_doh_server.py`)
2. compiled `dns-encrypted-proxy`
3. concurrent benchmark clients

and reports end-to-end throughput and p50/p95/p99/max latency.

### Protocol Modes

- `udp`: UDP query/response timing
- `tcp`: TCP query/response timing (new TCP connection per request)
- `udp-upgrade`: UDP request must return `TC=1`, then benchmark retries same query over TCP and reports combined latency

### Examples

```bash
./build/bin/e2e_proxy_bench --protocol udp --requests 20000 --concurrency 32 --warmup 1000 --timeout-ms 2000
./build/bin/e2e_proxy_bench --protocol tcp --requests 5000 --concurrency 16 --warmup 500 --timeout-ms 2500
./build/bin/e2e_proxy_bench --protocol udp-upgrade --requests 5000 --concurrency 16 --warmup 300 --timeout-ms 3000
```

### Useful Flags

- `--protocol udp|tcp|udp-upgrade`
- `--requests N`
- `--concurrency N`
- `--warmup N`
- `--timeout-ms N`
- `--upstream-delay-us N` (inject mock upstream latency)
- `--upstream-answer-count N` (larger responses; auto-min 40 for `udp-upgrade`)
- `--proxy-bin PATH` (default `./build/bin/dns-encrypted-proxy`)

## Notes

- Benchmarks are local-loopback synthetic measurements; compare runs using the same host/load profile.
- For robust comparisons, run multiple times and compare medians, not single samples.
