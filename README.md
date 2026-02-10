# DOH-Proxy

A DNS proxy in C that listens on UDP/TCP and resolves queries via upstream DNS-over-HTTPS servers.

## Features

- DNS listener on UDP and TCP.
- Multiple upstream DoH servers with round-robin start + failover.
- TTL-respecting in-memory cache keyed by DNS question.
- Config from file with environment variable overrides.

## Build

```bash
cmake -S . -B build
cmake --build build
```

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
  -e LISTEN_PORT=5353 \
  -p 5353:5353/udp \
  -p 5353:5353/tcp \
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
- `doh_pool_size`
- `cache_capacity`
- `upstream_doh_urls` (comma-separated)

Environment variable overrides:

- `DOH_PROXY_CONFIG`
- `LISTEN_ADDR`
- `LISTEN_PORT`
- `UPSTREAM_TIMEOUT_MS`
- `DOH_POOL_SIZE`
- `CACHE_CAPACITY`
- `UPSTREAM_DOH_URLS`

## Notes

- Binding to port `53` usually needs elevated privileges or `cap_net_bind_service`.
- Cache TTL uses the minimum TTL in the DNS response record sections.
- DoH uses a reusable request handle pool (`doh_pool_size`) for connection reuse.
