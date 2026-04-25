# dns-encrypted-proxy

dns-encrypted-proxy is a small, high-performance DNS forward proxy written in C.

It listens on classic DNS (`UDP`/`TCP`) and forwards to encrypted upstreams. The goal is simple: keep the data path fast, predictable, and easy to reason about.

## Protocol Support

- **DoH (HTTP/1.1 + HTTP/2 + HTTP/3):** supported. The proxy automatically prefers the highest HTTP version available in the linked `libcurl` build.
- **DoT:** supported and production-ready.
- **DoQ:** supported behind build flag and currently experimental.

Notes on DoH HTTP version selection:

- If `libcurl` is built with HTTP/3 support, DoH requests prefer HTTP/3.
- Otherwise, DoH falls back to HTTP/2 (and HTTP/1.1 where needed).
- The test hook `DNS_ENCRYPTED_PROXY_TEST_FORCE_HTTP1` can force HTTP/1.1 for integration tests.

## What This Proxy Is For

- Running a lightweight encrypted-DNS edge for local networks, labs, and small production deployments.
- Bridging traditional DNS clients to modern encrypted upstream resolvers.
- Keeping latency low with an in-memory TTL-aware cache and efficient request handling.

## How It Works (At a High Level)

- Accepts DNS queries over UDP/TCP.
- Extracts a canonical question key and checks an in-memory cache.
- On miss, enqueues upstream work into the dispatch facilitator (priority-ordered provider/member selection, per-job deadlines, completion queue).
- Allocator loop manages member lifecycle (`UNINIT -> CONNECTING -> READY/FAILED -> COOLDOWN`) and refresh scheduling.
- Rewrites response ID to match the incoming client query.
- Applies cache policy from DNS TTLs and response semantics.
- Exposes runtime metrics for traffic, cache behavior, upstream health, and transport usage.

## Design Priorities

### Speed First

- Tight C implementation with explicit control over network and memory behavior.
- Low-overhead cache path (hash-indexed storage, LRU, admission filtering, bounded sweeps).
- Focus on practical latency and throughput, not just microbenchmarks.

### Test Coverage and Reliability

- Extensive unit + integration + internal branch tests.
- Coverage-driven hardening (including edge/failure paths).
- Fault-injection tests for parser, transport, cache, and server lifecycle behaviors.

### Real Benchmarking

- Micro benchmark for cache internals.
- End-to-end benchmark that runs the compiled proxy against a mock encrypted upstream.
- Modes for UDP, TCP, and UDP-truncate-then-TCP-upgrade flows.

## Quick Start

Build (release):

```bash
cmake -S . -B build/release -DCMAKE_BUILD_TYPE=Release
cmake --build build/release
```

Build artifacts land under `build/`:

- `build/release/`, `build/debug/`, `build/asan/`, `build/coverage/` — per-variant CMake trees (intermediates, `Makefile`, `CMakeFiles/`)
- `build/bin/` — ready-to-run binaries (`dns-encrypted-proxy`, all `test_*`, benchmark tools). Shared across variants; last build wins.
- `build/matrix/<combo>/` — protocol feature-matrix builds produced by `tools/ci_test_matrix.sh`

Optional upstream provider build flags (DoH/DoT ON by default, DoQ OFF by default):

```bash
cmake -S . -B build/release -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_UPSTREAM_DOH=ON \
  -DENABLE_UPSTREAM_DOT=ON \
  -DENABLE_UPSTREAM_DOQ=ON
```

Tip: verify HTTP/3 availability in your runtime image/host with:

```bash
curl -V
```

Look for `HTTP3` in the `Features` list.

DoQ uses ngtcp2 and requires ngtcp2 + OpenSSL-family crypto modules when enabled.

Current DoQ status: experimental and disabled by default; implementation exists behind `-DENABLE_UPSTREAM_DOQ=ON`, but interoperability is still provider/environment dependent.

Run:

```bash
./build/bin/dns-encrypted-proxy
```

Local non-privileged port:

```bash
LISTEN_PORT=5353 ./build/bin/dns-encrypted-proxy
```

Version and help:

```bash
./build/bin/dns-encrypted-proxy --version    # prints SEMVER_YYYYMMDD.HHMM.TYPE
./build/bin/dns-encrypted-proxy --help
```

The version string embeds the semver from `release_version`, the configure-time UTC timestamp, and the build variant (`release`, `debug`, `asan`, `coverage`, …). It also prints on the first INFO line at startup so crash logs self-identify.

## Configuration

By default the proxy reads `dns-encrypted-proxy.conf` if present. You can also pass an explicit config path:

```bash
./build/bin/dns-encrypted-proxy /path/to/dns-encrypted-proxy.conf
```

Main config keys:

- `listen_addr`, `listen_port`
- `upstreams` (comma-separated `https://...`, `tls://host[:port]`, and/or `quic://host[:port]`)
- `upstream_timeout_ms`, `upstream_pool_size`
- `max_inflight_doh`, `max_inflight_dot`, `max_inflight_doq`
- `bootstrap_resolvers` (comma-separated IPv4 recursive resolvers used for stage2 bootstrap)
- `cache_capacity`
- `hosts_a` (comma-separated `name=IPv4` or `name:IPv4` overrides for local A answers)
- `tcp_idle_timeout_ms`, `tcp_max_clients`, `tcp_max_queries_per_conn`
- `metrics_enabled`, `metrics_port`
- `log_level` (`DEBUG`, `INFO`, `WARN`, `ERROR`)

Environment override support includes:

- `DNS_ENCRYPTED_PROXY_CONFIG`, `LISTEN_ADDR`, `LISTEN_PORT`
- `UPSTREAMS`, `UPSTREAM_TIMEOUT_MS`, `UPSTREAM_POOL_SIZE`
- `MAX_INFLIGHT_DOH`, `MAX_INFLIGHT_DOT`, `MAX_INFLIGHT_DOQ`
- `BOOTSTRAP_RESOLVERS`
- `CACHE_CAPACITY`
- `HOSTS_A`
- `TCP_IDLE_TIMEOUT_MS`, `TCP_MAX_CLIENTS`, `TCP_MAX_QUERIES_PER_CONN`
- `METRICS_ENABLED`, `METRICS_PORT`
- `LOG_LEVEL`

`hosts_a` behavior:

- Applied before cache/upstream resolution for single-question `A IN` queries.
- Returns a local synthesized DNS answer with fixed TTL `60`.
- Intended as a fast hosts-style override path for internal names.

`bootstrap_resolvers` behavior:

- Stage1 uses local resolver first.
- If stage1 cannot establish a working upstream path, stage2 queries these recursive resolvers for upstream host A records (with TTL).
- Stage3 iterative bootstrap resolver is used only if stage2 fails.

## Metrics

Prometheus endpoint:

- route: `GET /metrics`
- health probes: `GET /healthz` and `GET /readyz`
- bind: `0.0.0.0:<metrics_port>`
- format: `text/plain; version=0.0.4`

Includes counters/gauges for query volume, upstream success/failure, cache entries/evictions/expirations/bytes, TCP connection state, response codes, and upstream-dispatch internals (queue depth, member states, queue-wait histogram, requeue/drop/budget-exhausted events).

## Docker

Build local image:

```bash
docker buildx build --load -t dns-encrypted-proxy:dev .
```

Run:

```bash
docker run --rm -p 53:53/udp -p 53:53/tcp dns-encrypted-proxy:dev
```

Docker image config path:

- The container reads config from `/app/config/dns-encrypted-proxy.conf` via `DNS_ENCRYPTED_PROXY_CONFIG`.
- Mount your own file there to override defaults.

```bash
docker run --rm -p 53:53/udp -p 53:53/tcp \
  -v "$(pwd)/dns-encrypted-proxy.conf:/app/config/dns-encrypted-proxy.conf:ro" \
  dns-encrypted-proxy:dev
```

## Project Guides

- Operations manual: `Manual.md` — config keys, state machines, metrics taxonomy, troubleshooting
- Testing guide: `TESTING.md`
- Benchmarking guide: `BENCHMARKING.md`
- Performance step notes: `CACHE_PERF_STEPS.md`

## Notes

- Binding to port `53` usually needs elevated privileges or `cap_net_bind_service`.
- This project currently targets IPv4-oriented deployment patterns.
