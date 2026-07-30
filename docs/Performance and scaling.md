---
tags: [performance, operations]
updated: 2026-07-31
---

# Performance and scaling

Load-bearing decisions, and where to look when they stop being true.

## 1. Argon2 is memory-hard, so login concurrency must be bounded

The single most important number in this codebase. At 19 MiB per hash, 200
concurrent logins is ~3.8 GiB of transient RSS — the process OOMs long before the
CPU saturates, which makes an unauthenticated login flood a trivial
memory-exhaustion DoS.

Three things address it:

- **Bounded admission.** `HASH_MAX_CONCURRENCY` (default 8) caps simultaneous
  hashes at ~152 MiB. Excess requests queue for `HASH_QUEUE_TIMEOUT_MS`, then shed
  with `503` + `Retry-After` — which a load balancer can retry elsewhere, unlike a
  dead container.
- **No worker pool.** `@node-rs/argon2`'s async API already runs the native work on
  the libuv threadpool, so the event loop stays free and piscina would be
  redundant. But that makes **`UV_THREADPOOL_SIZE`** (default **4**) the real
  concurrency ceiling, and it is shared with DNS and filesystem work. It must be
  ≥ `HASH_MAX_CONCURRENCY`; the app warns at boot if it is not.
- **Timing parity.** The unknown-user path runs `verifyDummy()` against a real
  Argon2 hash, so response time does not reveal whether an account exists.

**Measured:** 123 ms per hash at `m=19456, t=2, p=1` inside the container.
Re-measure on your target hardware and tune to under ~500 ms:

```bash
docker compose exec api node -e "const{hash}=require('@node-rs/argon2');(async()=>{const t=Date.now();await hash('pw',{memoryCost:19456,timeCost:2,parallelism:1,algorithm:2});console.log(Date.now()-t+'ms')})()"
```

Watch `auth_hash_queue{state="depth"}` and `{state="shed"}`. A rising queue with no
shedding means the cap is about right; shedding under normal traffic means it is
too low. See [[ADR-0003 Bound Argon2 concurrency instead of adding a worker pool]].

## 2. Small connection pool, deliberately

```
replicas × DB_POOL_MAX  ≪  postgres max_connections (200)
```

Postgres allocates ~5–10 MiB per backend and context-switches between them, so
pushing connections past roughly (2 × cores + spindles) makes throughput *worse*.
`DB_POOL_MAX` defaults to 10 per process. `db_pool_connections{state="waiting"}`
sustained above 0 means the **pool** is the bottleneck — raise the pool or add
pgBouncer, not more replicas.

Timeouts are set on the connection, not just in code, so a hung query can never
hold a slot forever: `statement_timeout` 15 s,
`idle_in_transaction_session_timeout` 30 s, `maxUses` 7500 to recycle connections.

**Past ~10 replicas:** pgBouncer in transaction mode, and drop `DB_POOL_MAX` to
2–3. Not in the compose stack because its SCRAM `userlist.txt` must be generated
from real credentials — half-working auth infrastructure is worse than none.

## 3. Load shedding before collapse

`@fastify/under-pressure` samples; **the shed decision is ours** and lives in an
`onRequest` hook. `/health`, `/metrics` and `/docs` are exempt: shedding those
would make the orchestrator kill a container that is merely busy.

> [!danger] A non-finite delay is not pressure
> under-pressure maps a NaN histogram mean to `Infinity`, which beats any
> threshold — so a freshly started process would shed **every** request until its
> first event-loop sample landed. The hook treats a non-finite reading as "no
> measurement yet". Full story: [[ADR-0004 Own the load-shedding decision]].

## 4. Liveness vs readiness

`/health/live` deliberately touches **nothing**. If it pinged Postgres, a
30-second database blip would make the orchestrator kill and restart every replica
at once — turning a recoverable wobble into a full outage.

`/health/ready` checks all dependencies and returns 503 with per-dependency detail.
SMTP is **soft**: mail must never gate authentication, so a broken relay reports
`degraded` and still serves traffic.

Readiness costs three network round-trips, one an SMTP handshake, so the result is
cached for 1 second and concurrent probes de-duplicate onto a single check
(`x-cache: hit|miss`). An orchestrator polls far slower than that, so the answer
stays honest — but a probe burst can no longer multiply load onto the dependencies
it is asking about.

## 5. Load testing

`pnpm load` runs `load/k6/login.js`. Scenarios use **arrival-rate** executors, not
`constant-vus`: VUs with no think time generate whatever throughput the box allows
(~1000 req/s here), which measures nothing actionable and trips every per-endpoint
rate limit — so the run "fails" on limits working correctly rather than on a
regression. A short warm-up phase runs first and is excluded from all thresholds,
because on a 30-second run the handful of cold-start outliers *are* the p99.

```
jwks_duration ... avg=4.07ms med=3.28ms p(95)=7.99ms p(99)=15.01ms
http_req_failed ... 0.00%      rate_limited_429 ... 0
```

> [!success] This test already earned its keep
> The first run failed with an 87% error rate: exactly 60 JWKS requests succeeded
> and the rest returned 429. `/.well-known/jwks.json` had a 60/minute limit — but
> it is the one endpoint every resource server must poll to verify tokens, and
> every pod re-fetches on cold start. That would have broken token verification
> cluster-wide. Now 1200/min with the 5-minute `Cache-Control` doing the real work,
> and the profile asserts `rate_limited_429 == 0` so it cannot regress.

## 6. No response compression

Deliberately absent. Compressing a response that mixes a secret (a token) with
attacker-influenced input is the BREACH side channel, and auth payloads are a few
hundred bytes — nothing to win, something real to lose.

## 7. Smaller choices

| Choice | Why |
|---|---|
| UUIDv7 keys, app-generated | Time-sortable: inserts land at the right edge of the index instead of scattering |
| Partial indexes (`WHERE revoked_at IS NULL`) | Hot indexes stay small as dead sessions accumulate |
| Redis `volatile-lru` | Every key we set has a TTL; evicting one without would break the limiter |
| `coerceTypes: false` in ajv | `"1"` must never become `1` in an auth payload |
| `bodyLimit` 64 KiB | Auth payloads are tiny; a small limit is free DoS reduction |
| `tsBuildInfoFile` inside `dist/` | Deleting `dist/` can never leave stale incremental state that makes `tsc` emit nothing |
| `pnpm fetch` in the Dockerfile | Dependency layer keyed on the lockfile alone |

## Horizontal scaling

The API holds no session state — sessions in Postgres, counters and revocation in
Redis — so replicas scale out directly. Two things must be true; one is not yet:

1. ✅ **Rate limits are per-cluster** (Redis-backed, `nameSpace: rl:`). Without a
   shared store, N replicas silently multiply every limit by N.
2. ❌ **Signing keys are in-memory.** Each replica generates its own Ed25519
   keypair, so a token minted by one will not verify on another. The
   `auth_signing_keys` table exists and [[AUTH-MODULE-PLAN#8.6 Key rotation]]
   specifies rotation; the DB-backed key store is a Phase 8 task and **is the
   blocker** for running more than one instance.

## Related

[[Observability]] · [[Docker stack]] · [[Testing]] · [[Decisions]]
