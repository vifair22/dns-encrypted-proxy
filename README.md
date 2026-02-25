# DOH-Proxy

A DNS proxy in C that listens on UDP/TCP and resolves queries via upstream DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) servers.

## Features

- DNS listener on UDP and TCP.
- Multiple upstream DoH/DoT servers with round-robin start + failover.
- TTL-respecting in-memory cache keyed by DNS question.
- Config from file with environment variable overrides.

## Build

```bash
cmake -S . -B build
cmake --build build
```

## Testing

The project includes a test suite using [CMocka](https://cmocka.org/).

**Dependencies:** `cmocka`

Note: the DoH success integration test uses a local Python HTTPS mock server, so `python3` is required when running the full integration suite.

```bash
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build
cd build && ctest --output-on-failure
```

Individual test suites can be run directly:

```bash
./build/test_config       # Configuration tests
./build/test_cache        # Cache operations tests
./build/test_dns_message  # DNS message parsing tests
./build/test_upstream     # Upstream parsing and health policy tests
./build/test_integration  # Integration tests
```

### Coverage (gcov/gcovr)

Use a dedicated build directory for coverage instrumentation.

```bash
cmake -S . -B build-coverage -DBUILD_TESTS=ON -DENABLE_COVERAGE=ON
cmake --build build-coverage -j
ctest --test-dir build-coverage --output-on-failure
```

If `gcovr` is installed, generate reports:

```bash
gcovr -r . build-coverage --exclude "tests/|tools/" --print-summary
gcovr -r . build-coverage --exclude "tests/|tools/" --html-details -o build-coverage/coverage.html
```

If CMake finds `gcovr`, a convenience target is also available:

```bash
cmake --build build-coverage --target coverage
```

| Suite | Tests | Description |
|-------|-------|-------------|
| test_config | 10 | Config file parsing, env overrides, defaults |
| test_cache | 11 | Store/lookup, TTL expiry, LRU eviction, thread safety |
| test_dns_message | 23 | Key extraction, EDNS, TTL handling, validation |
| test_upstream | 10 | Upstream URL parsing and failover health policy helpers |
| test_integration | 14 | Full cache flows plus DoH/DoT transport success/failure and failover coverage |

## Docker (buildx)

Build a local image:

```bash
docker buildx build --load -t doh-proxy-c:dev .
```

Run on default DNS port:

```bash
docker run --rm \
  -p 53:53/udp \
  -p 53:53/tcp \
  doh-proxy-c:dev
```

Run on a non-privileged port for local development:

```bash
docker run --rm \
  -p 5353:53/udp \
  -p 5353:53/tcp \
  doh-proxy-c:dev
```

Build and push multi-arch image:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t your-registry/doh-proxy-c:latest \
  --push .
```

## Run

```bash
./build/DOH-Proxy
```

Use a non-privileged port for local development:

```bash
LISTEN_PORT=5353 ./build/DOH-Proxy
```

## Configuration

By default the proxy reads `doh-proxy.conf` if present.

You can pass an explicit file path:

```bash
./build/DOH-Proxy /path/to/doh-proxy.conf
```

Supported config keys:

- `listen_addr`
- `listen_port`
- `upstream_timeout_ms`
- `upstream_pool_size`
- `cache_capacity`
- `tcp_idle_timeout_ms`
- `tcp_max_clients`
- `tcp_max_queries_per_conn`
- `metrics_enabled` (`1` enable, `0` disable)
- `metrics_port`
- `upstreams` (comma-separated `https://...` and/or `tls://host:port`)

Environment variable overrides:

- `DOH_PROXY_CONFIG`
- `LISTEN_ADDR`
- `LISTEN_PORT`
- `UPSTREAM_TIMEOUT_MS`
- `UPSTREAM_POOL_SIZE`
- `CACHE_CAPACITY`
- `TCP_IDLE_TIMEOUT_MS`
- `TCP_MAX_CLIENTS`
- `TCP_MAX_QUERIES_PER_CONN`
- `METRICS_ENABLED`
- `METRICS_PORT`
- `UPSTREAMS`

Prometheus metrics endpoint:

- Route: `GET /metrics`
- Bind: `0.0.0.0:<metrics_port>`
- Content type: `text/plain; version=0.0.4`

## Cache Architecture

The cache uses a hash-indexed in-memory store with LRU eviction and TTL expiration.

- **Sharded design:** keys are partitioned across fixed shards; each shard has its own mutex, hash buckets, and LRU list.
- **Lookup path:** 64-bit hash + bucket chain for O(1)-average key lookup within a shard.
- **Recency policy:** successful lookups move entries to the shard-local LRU head.
- **Capacity bound:** each shard enforces a bounded entry budget and evicts least-recently-used entries when full.
- **Admission control:** a lightweight shard-local doorkeeper filters one-off inserts under pressure to reduce churn.
- **TTL behavior:** entries store absolute expiry timestamps; stale entries are removed lazily on access and via bounded periodic shard sweeps.
- **Memory accounting:** tracks live key/value payload bytes across all shards.

Cache observability metrics include:

- `doh_proxy_cache_entries`
- `doh_proxy_cache_capacity`
- `doh_proxy_cache_evictions_total`
- `doh_proxy_cache_expirations_total`
- `doh_proxy_cache_bytes_in_use`

Sizing guidance:

- Start with `cache_capacity` in the low thousands for local/small deployments.
- Increase capacity when `doh_proxy_cache_evictions_total` grows quickly and hit rate remains low.
- Use `doh_proxy_cache_bytes_in_use` to verify memory footprint before increasing capacity significantly.

## Cache Benchmark

The repository includes a cache benchmark utility that runs mixed lookup/store workloads across capacities `1024`, `4096`, and `16384`.

For each capacity, it also reports average lookup latency at multiple cache depths (10%, 25%, 50%, 75%, 100%) with separate hit and miss timings.

Build:

```bash
cmake -S . -B build -DBUILD_BENCHMARKS=ON
cmake --build build
```

Run with default workload (`200000` operations per capacity):

```bash
./build/cache_bench
```

Run with a custom operation count:

```bash
./build/cache_bench 500000
```

Run with custom operation count and threaded scaling limit:

```bash
./build/cache_bench 500000 8
```

The second argument is the maximum thread count for the threaded throughput sweep (runs at 1,2,4,...,max).

## Notes

- Binding to port `53` usually needs elevated privileges or `cap_net_bind_service`.
- Cache TTL uses the minimum TTL in the DNS response record sections.
- Upstream request pools are configured via `upstream_pool_size`.
