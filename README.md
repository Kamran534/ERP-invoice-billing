# Invoice & Billing — platform

TypeScript monorepo. The auth module is the first subsystem.

📚 **Documentation lives in [`docs/`](docs/) — an [Obsidian](https://obsidian.md) vault.**
Open that folder as a vault, or read it on GitHub; it is plain markdown either way.
Start at [docs/Home.md](docs/Home.md).

## Quick start

```bash
cp .env.example .env
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"   # paste into AUTH_KEK

pnpm install
pnpm up                     # postgres + redis + mailpit + adminer + api, waits for healthy
pnpm db:migrate             # apply the auth schema
pnpm smoke                  # verify every dependency end to end
```

| What | Where |
|---|---|
| **API** | http://localhost:3000 — `GET /` lists everything below |
| **API docs (Swagger UI)** | http://localhost:3000/docs |
| OpenAPI document | http://localhost:3000/docs/json · `/docs/yaml` |
| Health | `/health/live` (liveness) · `/health/ready` (dependencies) |
| Metrics | http://localhost:3000/metrics |
| Mail catcher | http://localhost:8025 |
| DB browser | http://localhost:8080 (server `postgres`, user `app`, pass `app_dev_password`) |
| Grafana / Prometheus | http://localhost:3001 · http://localhost:9090 (`pnpm up:obs`) |

> **Port conflicts.** If `pnpm up` fails with *port is already allocated*, override the host ports in
> `.env` — `POSTGRES_PORT`, `REDIS_PORT`, `MAILPIT_SMTP_PORT`, `MAILPIT_HTTP_PORT`, `ADMINER_PORT`,
> `API_PORT`. Container-to-container traffic always uses the default ports, so only your host-side
> URLs (`DATABASE_URL`, `REDIS_URL`, `SMTP_PORT`, `MAILPIT_API_URL`) need to match.

> **`pnpm up` already runs the API in a container on port 3000.** Running it on the host too will
> fail to bind — `docker compose stop api` first, or give the host instance its own `PORT`. See
> [docs/Running locally.md](docs/Running%20locally.md).

## Layout

```
apps/api            Fastify HTTP surface: routes, OpenAPI, plugins, load shedding
packages/core       Ports, error model, config schema. No framework, no driver, no I/O.
packages/crypto     Argon2id (bounded), EdDSA tokens, UUIDv7, OTP codes, hashing
packages/db         Drizzle schema (19 tables), migrations, tuned pg pool
packages/mail       SMTP transport + templates
packages/testing    DB helpers, fixtures, infra preflight
docs/               Obsidian vault — architecture, decisions, runbooks, the auth spec
docker/             Dockerfile, Postgres init SQL, Prometheus/Grafana config
load/k6/            Load profiles with the plan's latency thresholds as gates
```

The dependency rule is one-directional: `core` imports nothing, adapters import `core`, `api`
imports everything. That is what makes the auth module portable — swap the adapters, keep `core`.
See [docs/Architecture.md](docs/Architecture.md).

## Commands

```bash
pnpm dev                   # watch mode: tsc --watch on packages + tsx watch on the api
pnpm start                 # build (turbo-cached), then run the compiled api
pnpm build                 # compile everything (turbo-cached)
pnpm typecheck             # packages + test files
pnpm verify                # build + typecheck + unit tests + docs:check

pnpm test                  # unit only — no Docker needed, ~3s
pnpm test:watch            # unit, watch mode
pnpm test:int              # integration (needs Docker)
pnpm test:e2e              # end-to-end (needs Docker)
pnpm test:all              # all three projects
pnpm test:coverage         # all three + coverage report + thresholds

pnpm up / down             # docker stack up (waits for healthy) / down
pnpm up:obs                # + prometheus + grafana
pnpm down:volumes          # also drops the database
pnpm logs / ps

pnpm db:generate           # author a migration from the drizzle schema diff
pnpm db:migrate            # apply pending migrations
pnpm db:studio             # drizzle studio

pnpm smoke                 # full dependency check
pnpm docs:check            # resolve every wikilink in docs/ (part of pnpm verify)
pnpm load                  # k6 against the containerized api
pnpm openapi               # write openapi/openapi.json for codegen / CI diff
```

## Status

**233 tests** across three layers — unit (122, no Docker), integration (51), e2e (60).
Coverage 95.96% statements / 88.13% branches.

The auth **contracts** are final and published as OpenAPI; the **handlers** are phased. Only health,
metrics, JWKS and the service index are implemented — every `/auth/*` route answers
`501 NOT_IMPLEMENTED` with a pointer to the spec section defining it. Nothing half-authenticates
anyone. Phase 1 is password login plus the full refresh flow.

⚠️ **Multi-replica is blocked**: signing keys are generated in memory per process, so a token minted
by one replica will not verify on another. See
[docs/Performance and scaling.md](docs/Performance%20and%20scaling.md#horizontal-scaling).

## Where to read next

| Topic | Note |
|---|---|
| How the code is shaped | [Architecture](docs/Architecture.md) |
| Getting it running, day to day | [Running locally](docs/Running%20locally.md) |
| The auth subsystem | [Auth module](docs/Auth%20module.md) → [the spec](docs/AUTH-MODULE-PLAN.md) |
| The API and its docs | [API and Swagger](docs/API%20and%20Swagger.md) |
| Tests | [Testing](docs/Testing.md) |
| Speed, capacity, scaling | [Performance and scaling](docs/Performance%20and%20scaling.md) |
| Metrics and alerts | [Observability](docs/Observability.md) |
| Containers | [Docker stack](docs/Docker%20stack.md) |
| Why things are the way they are | [Decisions](docs/Decisions.md) |
| Response headers | [Security headers](docs/Security%20headers.md) |
| When something breaks | [Runbooks](docs/Runbooks.md) |
