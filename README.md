# DOH-Proxy

DOH-Proxy is a small, high-performance DNS forward proxy written in C.

It listens on classic DNS (`UDP`/`TCP`) and forwards to encrypted upstreams (`DoH` and `DoT`). The goal is simple: keep the data path fast, predictable, and easy to reason about.

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

Run:

```bash
./build/DOH-Proxy
```

Local non-privileged port:

```bash
LISTEN_PORT=5353 ./build/DOH-Proxy
```

## Configuration

By default the proxy reads `doh-proxy.conf` if present. You can also pass an explicit config path:

```bash
./build/DOH-Proxy /path/to/doh-proxy.conf
```

Main config keys:

- `listen_addr`, `listen_port`
- `upstreams` (comma-separated `https://...` and/or `tls://host:port`)
- `upstream_timeout_ms`, `upstream_pool_size`
- `cache_capacity`
- `tcp_idle_timeout_ms`, `tcp_max_clients`, `tcp_max_queries_per_conn`
- `metrics_enabled`, `metrics_port`

Environment override support includes:

- `DOH_PROXY_CONFIG`, `LISTEN_ADDR`, `LISTEN_PORT`
- `UPSTREAMS`, `UPSTREAM_TIMEOUT_MS`, `UPSTREAM_POOL_SIZE`
- `CACHE_CAPACITY`
- `TCP_IDLE_TIMEOUT_MS`, `TCP_MAX_CLIENTS`, `TCP_MAX_QUERIES_PER_CONN`
- `METRICS_ENABLED`, `METRICS_PORT`

## Metrics

Prometheus endpoint:

- route: `GET /metrics`
- bind: `0.0.0.0:<metrics_port>`
- format: `text/plain; version=0.0.4`

Includes counters/gauges for query volume, upstream success/failure, cache entries/evictions/expirations/bytes, TCP connection state, and response codes.

## Docker

Build local image:

```bash
docker buildx build --load -t doh-proxy-c:dev .
```

Run:

```bash
docker run --rm -p 53:53/udp -p 53:53/tcp doh-proxy-c:dev
```

## Project Guides

- Testing guide: `TESTING.md`
- Benchmarking guide: `BENCHMARKING.md`
- Performance step notes: `CACHE_PERF_STEPS.md`

## Notes

- Binding to port `53` usually needs elevated privileges or `cap_net_bind_service`.
- This project currently targets IPv4-oriented deployment patterns.
