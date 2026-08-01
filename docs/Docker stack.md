---
tags: [operations, infrastructure]
updated: 2026-07-31
---

# Docker stack

Defined in `docker-compose.yml`. Every long-running service has a healthcheck, so
`--wait` and `depends_on` mean *ready*, not merely *started*.

| Service | Image | Purpose |
|---|---|---|
| `postgres` | `postgres:17-alpine` | Database |
| `redis` | `redis:7-alpine` | Rate limits, OTP throttles, revocation cache |
| `mailpit` | `axllent/mailpit` | SMTP sink + web UI + REST API |
| `adminer` | `adminer:5` | DB browser |
| `api` | built from `docker/api.Dockerfile` | The service |
| `prometheus` | `prom/prometheus` | Metrics — profile `obs` |
| `grafana` | `grafana/grafana` | Dashboards — profile `obs` |
| `k6` | `grafana/k6` | Load tests — profile `perf` |

## Postgres tuning, and why

Planner costs are set for SSD (`random_page_cost=1.1`) because the defaults assume
spinning rust and will refuse to use an index it should. WAL settings smooth
checkpoints so a burst of writes does not stall. `pg_stat_statements` is preloaded —
the only honest way to find slow queries:

```sql
SELECT calls, mean_exec_time, query FROM pg_stat_statements
ORDER BY mean_exec_time DESC LIMIT 20;
```

`docker/postgres/init/01-extensions.sql` runs once on first init and creates
`citext` (case-insensitive email identity), `pgcrypto` and `pg_stat_statements`,
then sets per-database `statement_timeout`, `lock_timeout` and
`idle_in_transaction_session_timeout`.

> [!warning] Init SQL runs **only** on an empty data directory
> Editing it does nothing to an existing volume. `pnpm down:volumes` to re-init —
> which drops the database.

## Redis eviction policy

Every key we set carries a TTL. `allkeys-lru` would be free to evict a key that
did not — and the two things stored here are the rate limiter and the revocation
cache. Evicting either fails open silently. The smoke test asserts the policy.

## Mailpit

Accepts everything, delivers nothing outside the machine. Its REST API is what
makes mail assertable: [[Testing#Integration]] sends a real message and reads it
back to confirm the code never reached the subject line.

## MinIO, and the two URLs it needs

Object storage for organization logos (§10.11.1). MinIO speaks the S3 API, so the
application code cannot tell the difference — in production only the endpoint and
the credentials change.

`minio-init` is a one-shot `mc` container that creates the bucket and runs
`anonymous set download` on **`public/` only**. ⚑ Not on the bucket: logos have to
be fetchable without a signature because they appear in emails and on invoices,
but a wholly public bucket is one careless `putObject` away from serving whatever
else lands in it.

⚑ Two URLs, and they are not the same string. `S3_ENDPOINT` is where the API
*writes* — inside the compose network that is `minio:9000`. `S3_PUBLIC_URL` is what
a **browser** fetches, which from the host is `localhost:59000` and in production is
likely a CDN. Storing the private one puts an unreachable address on every invoice.

| | |
|---|---|
| API | `${MINIO_PORT:-59000}` |
| Console | `${MINIO_CONSOLE_PORT:-59001}` — sign in with `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` |

## The API image

Multi-stage, in `docker/api.Dockerfile`:

1. **fetch** — `pnpm fetch` populates the store from the **lockfile alone**, so the
   dependency layer is cached until `pnpm-lock.yaml` changes. Editing source never
   re-downloads anything.
2. **build** — full install, `pnpm run build`.
3. **prod-deps** — a separate `--prod` install from the same warm store.
4. **runtime** — copies the prod tree, overlays the compiled `dist/`, runs as
   `node`.

> [!note] Why not `pnpm prune --prod` on the built tree
> With pnpm's isolated `node_modules`, pruning leaves dangling symlinks into
> `.pnpm/` and the app dies at runtime with `ERR_MODULE_NOT_FOUND` on packages that
> are genuinely production dependencies. A clean `--prod` install is correct by
> construction. `CI=true` is set because pnpm refuses to replace `node_modules`
> without a TTY.

`dumb-init` is PID 1 so SIGTERM actually reaches Node and the graceful-shutdown
path runs. Verified: `SIGTERM → shutting down → closing infrastructure → shutdown
complete`.

## What the smoke test proves

```
ok  postgres: connect / extensions / schema migrated / write-read-rollback
ok  redis: ping / set-get-ttl / eviction policy
ok  smtp: handshake / send templated mail
ok  mailpit: message received      ← read back through the API
ok  api: health / JWKS / OpenAPI
```

It also asserts two invariants rather than mere connectivity: that Redis is **not**
on an `allkeys-*` policy, and that the OTP template never puts the code in the
subject line.

## Scaling out

```bash
docker compose up -d --scale api=3     # remove the fixed host port first
```

Rate limits are already shared through Redis, so a limit is per-cluster. Signing
keys are **not** — see [[Performance and scaling#Horizontal scaling]].

## Related

[[Running locally]] · [[Observability]] · [[Performance and scaling]] · [[Redis is down]]
