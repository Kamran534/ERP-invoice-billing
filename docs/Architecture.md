---
tags: [architecture]
updated: 2026-07-31
---

# Architecture

A pnpm workspace with one app and five packages. The shape exists to make the auth
module portable: swap the adapters, keep the core.

## The dependency rule

```
apps/api          ──┐
                    ├──▶ packages/db ──┐
packages/testing  ──┤    packages/mail ├──▶ packages/core
                    └──▶ packages/crypto ┘
```

`core` imports **nothing** — no framework, no driver, no logger, no `process.env`.
Adapters import `core`. The app imports everything. Nothing imports the app.

That single rule is what makes the module reusable — see
[[ADR-0006 Ports and adapters for portability]]. The coupling surface is the set of
port interfaces in [[AUTH-MODULE-PLAN#6. Ports (the genericity contract)]], and
every external concern arrives through one of them.

## Packages

| Package | Holds | Depends on |
|---|---|---|
| `@auth/core` | Ports, typed error model, config schema. Pure. | zod |
| `@auth/crypto` | Argon2id with bounded concurrency, EdDSA tokens, UUIDv7, OTP codes, hashing | core |
| `@auth/db` | Drizzle schema (19 tables), migrations, tuned pg pool | core |
| `@auth/mail` | SMTP transport, templates | core |
| `@auth/testing` | DB helpers, fixtures, infra preflight | core, crypto, db |
| `@app/api` | Fastify surface: routes, plugins, OpenAPI, load shedding | all of the above |

`@auth/db` re-exports the drizzle operators it needs (`sql`, `eq`, `getTableName`…)
so nothing else takes a direct ORM dependency. That boundary already earned its
keep — pnpm's strict isolation caught `@auth/testing` reaching for `drizzle-orm`
directly.

## Request lifecycle

Plugin registration order matters; later plugins decorate off earlier ones.

```
errors      setErrorHandler + setNotFoundHandler      (first: catches everything after)
infra       db, redis, mailer, hasher, tokens          (waits for the Redis connection)
security    helmet, CORS, cookies, rate limiting       (needs app.redis)
observability  metrics, load shedding                  (needs app.dbHandle, app.hasher)
swagger     OpenAPI document + UI
routes      root, health, well-known, auth
```

Per request:

```
onRequest   ├─ x-request-id echoed back
            ├─ rate limit (Redis, per cluster, fail-closed)
            └─ load shedding (503 if over threshold; health/metrics/docs exempt)
validation  ajv, compiled from the same zod schema that produced the docs
handler
onSend      cache-control: no-store on /auth
onResponse  http_request_duration_seconds, labelled by route pattern
```

## Where the boundaries actually are

- **`buildApp(env)` returns an un-listened instance**, so tests drive it through
  `app.inject()` with no sockets and no ports. It takes an `extend` hook purely so
  a test can register a deliberately-throwing route — Fastify refuses new routes
  after `ready()`.
- **Config is validated once at boot** and the process refuses to start on a bad
  value. Anything security-relevant has no permissive default.
- **The error model is public API.** Clients branch on `code`; the 401/403 split
  decides whether they retry. See [[API and Swagger#Error contract]].

## Related

- [[Auth module]] — the subsystem this was all built for
- [[Testing]] — how the layering makes each layer testable
- [[Performance and scaling]] — what the shape costs and where it bends
- [[Decisions]] — why, rather than what
