---
tags: [adr, performance, security]
status: accepted
date: 2026-07-30
---

# ADR-0003 — Bound Argon2 concurrency instead of adding a worker pool

**Status:** Accepted · **Related:** [[Performance and scaling#1. Argon2 is memory-hard, so login concurrency must be bounded]]

## Context

Argon2id is deliberately memory-hard: ~19 MiB per hash at the configured cost. The
reflex in Node is "native crypto blocks the event loop, add piscina". That reflex is
wrong here, and it hides the actual risk.

`@node-rs/argon2`'s async API already runs the native work on the **libuv
threadpool** — the event loop is never blocked. A JS worker pool would add
processes, IPC and complexity for a problem that does not exist.

The real risk is memory. 200 concurrent logins is ~3.8 GiB of transient RSS. The
process OOMs long before the CPU saturates, so an unauthenticated login flood is a
trivial memory-exhaustion DoS.

## Decision

No worker pool. Instead:

1. A **semaphore** caps simultaneous hashes at `HASH_MAX_CONCURRENCY` (8 →
   ~152 MiB worst case). Excess requests queue for `HASH_QUEUE_TIMEOUT_MS`, then
   shed with `503` + `Retry-After`.
2. **`UV_THREADPOOL_SIZE` must be ≥ that cap.** Its default is 4 and it is shared
   with DNS and filesystem work, so it — not our cap — becomes the real ceiling if
   left alone. The app warns at boot if it is lower.
3. `verifyDummy()` runs a real Argon2 verification on the unknown-user path so
   response timing does not leak account existence.

## Alternatives rejected

**piscina / worker_threads** — redundant (the work is already off-loop) and would
multiply the memory problem across processes rather than bound it.

**Unbounded hashing** — the status quo in most Node auth code, and a DoS primitive.

**Lower the Argon2 cost so more fit in memory** — trades an availability problem for
a cracking-resistance problem. The cost parameter should be set by how long a hash
takes (~500 ms ceiling), not by concurrency.

## Consequences

- Shedding is visible: `auth_hash_queue{state="shed"}`. Climbing under normal
  traffic means the cap is too low, not that the tuning is wrong.
- A load balancer can retry a shed request elsewhere; it cannot retry an OOM.
- Measured 123 ms per hash in-container. Re-measure per deployment target.
- Unit tests cover the cap (peak concurrency never exceeds it), the shedding path
  (typed `SERVICE_UNAVAILABLE` with `Retry-After`), and permit release on throw —
  a leaked permit would permanently reduce login capacity.

## Related

[[Performance and scaling]] · [[Observability]] · [[Testing#Unit]]
