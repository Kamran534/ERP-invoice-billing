---
tags: [runbook, operations, infrastructure]
severity: high
updated: 2026-07-31
---

# Redis is down

Redis backs the **rate limiter**, OTP throttles and (when enabled) the revocation
cache. Losing it does not lose data — everything in it has a TTL and is
reconstructible — but it changes how the API behaves.

## What happens automatically

Rate limiting **fails closed** ([[AUTH-MODULE-PLAN#8.2 Rate limiting (token bucket, per rule; Redis-backed in prod)]]):
a limiter outage must not become an open brute-force window. Requests to
rate-limited routes get `503 SERVICE_UNAVAILABLE` with `Retry-After: 2` — a
retryable answer, not a leaked internal error.

`/health/ready` reports `redis: { ok: false }` and returns **503**, so an
orchestrator stops routing traffic to the pod. `/health/live` stays 200, so the
container is not killed for a dependency outage.

## Triage

```bash
docker compose ps redis
docker compose logs redis --tail 100
docker compose exec redis redis-cli ping
docker compose exec redis redis-cli info memory | grep -E 'used_memory_human|maxmemory'
```

**Out of memory?** `maxmemory` is 256 MiB with `volatile-lru`. Under the eviction
policy Redis evicts TTL-bearing keys rather than refusing writes, so OOM should
present as increased limiter churn rather than hard failure. If `maxmemory-policy`
has been changed to `noeviction`, writes fail — that is the likelier cause of a hard
outage.

> [!warning] Never set `allkeys-lru`
> Every key we write has a TTL. `allkeys-*` is free to evict keys that do not, and
> the two things stored here are the rate limiter and the revocation cache.
> Evicting either fails open silently. The smoke test asserts the policy for this
> reason.

## Restoring

```bash
docker compose restart redis
docker compose exec redis redis-cli ping      # expect PONG
curl -s localhost:3000/health/ready | jq .checks.redis
```

Counters restart from zero. That is acceptable: rate-limit windows are ≤ 1 hour,
and the alternative — persisting them — would make an outage worse rather than
better.

> [!note] The API waits for Redis at boot
> `enableOfflineQueue: false` means a command issued before the socket is up throws
> immediately. Combined with fail-closed limiting, the first requests after boot
> would surface as 500s — so startup waits (bounded, non-fatal) for the connection.
> A failure there is logged and readiness reports it.

## If it will be down a while

The honest options, in order:

1. Point `REDIS_URL` at a replacement instance. Nothing needs migrating.
2. Accept 503s on rate-limited routes. Authentication is unavailable, but no
   brute-force window opens.
3. **Do not** flip rate limiting to fail-open to restore service. That converts an
   availability incident into a security one, and the login endpoint is exactly
   where you least want an unlimited window.

## Related

[[Docker stack#Redis eviction policy]] · [[Observability]] · [[Performance and scaling]]
