# Standards Compliance TODO

Remaining items to make `DOH-Proxy` standards-compliant for production use.

## P0 (High Priority)

- [ ] Preserve DNS header/flag fidelity in locally generated errors.
- [ ] For synthetic `SERVFAIL`, preserve query `OPCODE` and relevant flags (`RD`, `CD`) and avoid setting flags that are not justified.
- [ ] Add EDNS-aware synthetic error responses: include OPT in local responses when query included OPT and keep EDNS version/DO semantics correct.
- [ ] Tighten cache eligibility rules: do not cache truncated responses (`TC=1`), malformed responses, and non-cacheable response classes.
- [ ] Implement RFC 2308 negative caching correctly (derive TTL from SOA negative caching rules, not generic minimum TTL across all RRs).

## P1 (Important)

- [ ] Preserve OPT record in truncated UDP responses when it fits; if omitted, ensure behavior remains RFC-consistent.
- [ ] Improve DoH response validation: verify DNS response ID handling and stricter checks for inconsistent section/header combinations.
- [ ] Add per-connection TCP limits/timeouts aligned with RFC 7766 operational guidance (idle timeout, max concurrent clients, max outstanding per connection).
- [ ] Add IPv6 listener support (`AF_INET6`) with dual-stack behavior controls.

## P2 (Hardening)

- [ ] Add optional DNS-over-TLS upstream mode (separate from DoH) for interoperability testing and operational flexibility.
- [ ] Add upstream policy controls for standards-friendly failover (retry budget, server penalty windows, jitter/backoff).
- [ ] Add structured counters for protocol behavior (`cache_hit/miss`, `truncated_sent`, `local_servfail`, `invalid_upstream_response`).

## Validation and Test Matrix

- [ ] Add automated integration tests for UDP/TCP parity, EDNS sizes, truncation behavior, and TCP retry after `TC=1`.
- [ ] Add DNSSEC-focused tests (`+dnssec`, `+cdflag`, large RRsets, negative answers with SOA).
- [ ] Add malformed packet tests (bad compression pointers, short RDLENGTH, inconsistent section counts).
- [ ] Add cache correctness tests for positive and negative caching TTL behavior.
- [ ] Test with a bunch of concurrent clients
