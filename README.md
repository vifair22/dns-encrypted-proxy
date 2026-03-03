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
- On miss, resolves upstream via DoH/DoT with health-aware failover.
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

Build:

```bash
cmake -S . -B build
cmake --build build
```

Optional upstream provider build flags (DoH/DoT ON by default, DoQ OFF by default):

```bash
cmake -S . -B build \
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
./build/dns-encrypted-proxy
```

Local non-privileged port:

```bash
LISTEN_PORT=5353 ./build/dns-encrypted-proxy
```

## Configuration

By default the proxy reads `dns-encrypted-proxy.conf` if present. You can also pass an explicit config path:

```bash
./build/dns-encrypted-proxy /path/to/dns-encrypted-proxy.conf
```

Main config keys:

- `listen_addr`, `listen_port`
- `upstreams` (comma-separated `https://...`, `tls://host[:port]`, and/or `quic://host[:port]`)
- `upstream_timeout_ms`, `upstream_pool_size`
- `upstream_bootstrap_enabled`, `upstream_bootstrap_a` (optional hostname->IPv4 bootstrap map for upstream dialing fallback)
- `cache_capacity`
- `hosts_a` (comma-separated `name=IPv4` or `name:IPv4` overrides for local A answers)
- `tcp_idle_timeout_ms`, `tcp_max_clients`, `tcp_max_queries_per_conn`
- `metrics_enabled`, `metrics_port`

Environment override support includes:

- `DNS_ENCRYPTED_PROXY_CONFIG`, `LISTEN_ADDR`, `LISTEN_PORT`
- `UPSTREAMS`, `UPSTREAM_TIMEOUT_MS`, `UPSTREAM_POOL_SIZE`
- `UPSTREAM_BOOTSTRAP_ENABLED`, `UPSTREAM_BOOTSTRAP_A`
- `CACHE_CAPACITY`
- `HOSTS_A`
- `TCP_IDLE_TIMEOUT_MS`, `TCP_MAX_CLIENTS`, `TCP_MAX_QUERIES_PER_CONN`
- `METRICS_ENABLED`, `METRICS_PORT`

`hosts_a` behavior:

- Applied before cache/upstream resolution for single-question `A IN` queries.
- Returns a local synthesized DNS answer with fixed TTL `60`.
- Intended as a fast hosts-style override path for internal names.

`upstream_bootstrap_a` behavior:

- Upstream dial flow is local resolver first; if that fails, configured bootstrap IPv4 is attempted.
- Set `upstream_bootstrap_enabled=0` to disable step 2 (iterative bootstrap fallback is currently stubbed for future work).

## Metrics

Prometheus endpoint:

- route: `GET /metrics`
- bind: `0.0.0.0:<metrics_port>`
- format: `text/plain; version=0.0.4`

Includes counters/gauges for query volume, upstream success/failure, cache entries/evictions/expirations/bytes, TCP connection state, and response codes.

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

- Testing guide: `TESTING.md`
- Benchmarking guide: `BENCHMARKING.md`
- Performance step notes: `CACHE_PERF_STEPS.md`

## Notes

- Binding to port `53` usually needs elevated privileges or `cap_net_bind_service`.
- This project currently targets IPv4-oriented deployment patterns.
