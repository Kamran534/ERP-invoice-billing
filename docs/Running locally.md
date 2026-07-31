---
tags: [operations, onboarding]
updated: 2026-07-31
---

# Running locally

## First run

```bash
cp .env.example .env
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"   # paste into AUTH_KEK

pnpm install
pnpm up                     # starts the stack, waits for healthy
pnpm db:migrate             # applies the auth schema
pnpm smoke                  # proves every dependency is actually wired
```

`pnpm smoke` is the one to trust. It does not check that containers are running —
it connects, writes and rolls back a transaction, round-trips a Redis key with a
TTL, sends a real templated email and **reads it back out of Mailpit's API**. See
[[Docker stack#What the smoke test proves]].

## Where things live

| What | URL |
|---|---|
| API | http://localhost:3000 — `GET /` lists everything below |
| Swagger UI | http://localhost:3000/docs |
| OpenAPI document | http://localhost:3000/docs/json |
| Mail catcher | http://localhost:8025 |
| DB browser | http://localhost:8080 — server `postgres`, user `app`, pass `app_dev_password` |
| Grafana / Prometheus | http://localhost:3001 · http://localhost:9090 (`pnpm up:obs`) |

## Three ways to run the API, one port

`pnpm up` already runs the API **in a container** on port 3000. Running it on the
host as well will fail to bind. Pick one:

| | Command | When |
|---|---|---|
| Container | `pnpm up` | You just want the stack up; closest to production |
| Host, watch | `docker compose stop api` then `pnpm dev` | Editing code — reloads on save |
| Host, compiled | `docker compose stop api` then `pnpm start` | Checking the built output |

Both host modes read `.env`, so they use your remapped host ports and talk to the
containerised Postgres, Redis and Mailpit. To run a host instance *alongside* the
container, give it its own port: `$env:PORT=3010; pnpm start`.

> [!bug] Port already allocated
> Something on your machine already owns 5432 / 6379 / 1025 / 8025 — a second
> Postgres, another dev stack, WSL. Override the host ports in `.env`:
> `POSTGRES_PORT`, `REDIS_PORT`, `MAILPIT_SMTP_PORT`, `MAILPIT_HTTP_PORT`,
> `ADMINER_PORT`, `API_PORT`. Container-to-container traffic always uses the
> defaults, so only your host-side URLs (`DATABASE_URL`, `REDIS_URL`, `SMTP_PORT`,
> `MAILPIT_API_URL`) need to match.

## Commands

```bash
pnpm dev                   # watch mode across packages + api
pnpm start                 # build (turbo-cached), then run the compiled api
pnpm build                 # compile everything
pnpm typecheck             # packages + test files
pnpm verify                # build + typecheck + unit tests

pnpm test                  # unit only — no Docker, ~3s
pnpm test:int              # integration (needs Docker)
pnpm test:e2e              # end-to-end (needs Docker)
pnpm test:coverage         # everything + coverage thresholds

pnpm up / up:obs / down    # docker stack
pnpm down:volumes          # also drops the database
pnpm logs / ps
pnpm db:generate / db:migrate / db:studio
pnpm db:test:setup         # create billing_test + set TEST_DATABASE_URL (once)
pnpm db:migrate:test       # apply migrations to it
pnpm smoke                 # dependency check
pnpm docs:check            # resolve every wikilink in docs/ (part of pnpm verify)
pnpm load                  # k6 against the containerised api
pnpm openapi               # write openapi/openapi.json for codegen or a CI diff
```

## Things that will confuse you once

- **`pnpm start` needs no separate build step** — it builds first, turbo-cached.
- **The compose stack runs the production image with `NODE_ENV=development`** on
  purpose. The boot-time production audit rejects an `http://` `APP_ORIGIN`, so a
  local stack with `NODE_ENV=production` correctly refuses to start. To exercise
  those checks: `docker compose run --rm -e NODE_ENV=production api`.
- **Unit tests need nothing.** If `pnpm test:int` complains, it will tell you
  exactly what to start — see [[Testing#Running without Docker]].
- **⚑ Integration tests need their own database.** Run `pnpm db:test:setup` and
  `pnpm db:migrate:test` once. The suite truncates every `auth_*` table between
  tests, and until it was made to refuse, it did that to whatever `DATABASE_URL`
  pointed at — deleting real accounts from the database being developed against.
  See [[Testing#The test database is not your database]].
- **Signing up needs outbound internet**, or it takes an extra 1.5 s. Every
  password goes to the HIBP range API before it is accepted; without a route out,
  the call times out, the check fails open with a warning, and signup proceeds.
  Set `PASSWORD_BREACH_CHECK=false` to skip it deliberately rather than paying the
  timeout — and read the ⚑ in `.env.example` before you do.
- **Registration is capped at 5 per hour per IP.** Clicking through the signup form
  half a dozen times while testing will earn you a `429` that looks like a bug. Use
  a different address *and* a different client, or wait out the window.
- **`POSTGRES_PORT` and `DATABASE_URL` must move together.** If you remap the
  published port because 5432 is already taken by another project, the URL has to
  follow. They are separate lines in `.env` and nothing cross-checks them.

  ⚑ Getting this wrong does not produce "connection refused" — it produces a
  connection to *somebody else's* Postgres, because 5432 on a machine running
  several stacks is rarely free. The symptom is
  `password authentication failed for user "app"`, which reads like a credentials
  problem in this project and is really a wrong-server problem.

  `drizzle.config.ts` now loads `.env` itself and throws when `DATABASE_URL` is
  absent rather than defaulting to `localhost:5432` — a tool that connects
  somewhere plausible-but-wrong is worse than one that refuses to start.

## Related

[[Docker stack]] · [[Testing]] · [[Architecture]] · [[API and Swagger]]
