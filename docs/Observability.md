---
tags: [operations, observability]
updated: 2026-07-31
---

# Observability

`pnpm up:obs` adds Prometheus (http://localhost:9090) and Grafana
(http://localhost:3001, datasource pre-provisioned).

## Metrics

Names follow [[AUTH-MODULE-PLAN#16. Observability & operations]] so the dashboards
and alerts described there work without renaming anything.

| Metric | Labels | Watch for |
|---|---|---|
| `http_request_duration_seconds` | method, route, status_code | p99 drift |
| `http_requests_total` | method, route, status_code | error-rate ratios |
| `http_requests_shed_total` | reason | anything above zero in steady state |
| `db_pool_connections` | state=total\|idle\|waiting | `waiting` > 0 sustained ⇒ the pool is the bottleneck |
| `auth_hash_queue` | state=depth\|peak\|shed | rising depth = login load; `shed` = cap too low |
| `auth_login_total` | result, method | failure ratio (credential stuffing) |
| `auth_refresh_total` | result | `reuse` at all; `concurrent` climbing |
| `auth_otp_total` | channel, purpose, result | verify-failure ratio, delivery time |
| `auth_mfa_total` | type, result | — |

The auth-domain counters are wired now and stay at zero until the handlers land, so
dashboards exist before there is anything to put on them.

> [!warning] Route **patterns**, never URLs
> `/auth/sessions/:id`, not `/auth/sessions/0191f0aa-…`. Labelling by concrete URL
> turns every id into a new time series and melts Prometheus. There is an e2e test
> asserting the concrete id never appears in the metrics output.

## Alerts that matter

Sketched in `docker/prometheus/prometheus.yml`; the reasoning is in
[[AUTH-MODULE-PLAN#16. Observability & operations]].

| Alert | Condition | Why |
|---|---|---|
| **Refresh token reuse** | `increase(auth_refresh_reuse_detected_total[5m]) > 0` | Presumed theft. Pages a human → [[Refresh token reuse detected]] |
| Refresh concurrency | `rate(auth_refresh_concurrent_total[5m])` climbing | A client's single-flight refresh has regressed; silently degrades every user's session |
| OTP verify-failure ratio | > 30% for 10 min | Guessing campaign — **or** delivery is broken and users are typing stale codes |
| OTP delivery p95 | > 30 s | Users abandon at ~30 s; a conversion incident as much as a security one → [[OTP delivery outage]] |
| Login-failure ratio | > 40% for 5 min | Credential stuffing |
| Lockouts | > 3σ above baseline | — |
| JWKS key age | > rotation SLO | Rotation job has stopped |
| Audit-write failures | any | ⚑ If audit writes fail, security-critical operations should fail too. That is a deliberate choice to record, not a silent degradation |

## Logs

pino, JSON in production. **Redaction is not optional** — without it a debug log of
a request body puts plaintext passwords and live tokens in your log aggregator,
which is then a credential store you did not mean to build. The redact list covers
`authorization`, `cookie`, `set-cookie`, `password`, `newPassword`,
`currentPassword`, `code`, `refreshToken`, `mfaToken`, `token`, and wildcard
`*.secret` / `*.accessToken` / `*.recoveryCodes`.

Every request carries an id, visible in three places: `reqId` in the log,
`x-request-id` on the response, and `error.traceId` in any error body. An inbound
`x-request-id` is honoured so a trace spans services.

Slow queries over `DB_QUERY_LOG_THRESHOLD_MS` (200 ms) are logged with the
statement — `pg_stat_statements` tells you *which* statements are slow across the
cluster, this tells you which request produced one.

## Reading the signals together

- **`auth_hash_queue{state="depth"}` up + `http_requests_shed_total` flat** →
  healthy back-pressure, cap is right.
- **`shed` climbing with normal traffic** → `HASH_MAX_CONCURRENCY` too low, or
  `UV_THREADPOOL_SIZE` below it.
- **`db_pool_connections{state="waiting"}` > 0 sustained** → pool, not Postgres.
  More replicas will make it worse.
- **`auth_refresh_total{result="concurrent"}` climbing** → a client is refreshing
  in parallel. Not dangerous yet, but it is one step from tripping theft detection.

## Related

[[Runbooks]] · [[Performance and scaling]] · [[Docker stack]]
