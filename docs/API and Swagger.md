---
tags: [api, architecture]
updated: 2026-07-31
---

# API and Swagger

Swagger UI at `/docs`, the document at `/docs/json` and `/docs/yaml`, a service
index at `/`. **26 documented paths**, OpenAPI 3.1.

## One schema, three jobs

A zod schema per payload produces all of:

1. **runtime validation** — Fastify compiles it with ajv,
2. **response serialization** — undeclared fields are stripped, a quiet defence
   against leaking internal columns,
3. **the OpenAPI document**.

They cannot drift because there is only one definition. Zod 4 emits JSON Schema
natively, so there is no third-party transform layer to fall out of sync with
either zod or Fastify — see
[[ADR-0005 Zod as the single source for validation, serialization and docs]].

`route()` in `apps/api/src/lib/schema.ts` adds the shared 400/429/500/503 responses
to every operation, so callers learn those are possible everywhere rather than
discovering them.

## Where the prose lives

`info.description` is **deliberately empty**. A narrative there renders as a wall of
text above the operation list and pushes the endpoints below the fold — the one
thing a reader opened the page for. Guidance is placed where it is acted on:

| Kind of guidance | Where it lives |
|---|---|
| "You must implement single-flight refresh" | the `/auth/token/refresh` operation description |
| "This endpoint is enumeration-safe" | the operation that behaves that way |
| What each auth scheme is and how to use it | the `securitySchemes` entries |
| Per-endpoint rate limits | appended to each operation by `route()` |
| Transport modes, error contract, 401 vs 403, the login sequence | this note and [[Auth module]] |
| Design and rationale | [[AUTH-MODULE-PLAN]], reachable from the page via `externalDocs` |

A client developer sees the guidance next to the call they are about to make,
rather than needing to have read a preamble ten operations earlier.

## Documentation as contract

E2E tests treat the document as a contract, not a by-product:

- every operation has a summary, a tag and a **unique** `operationId` — client
  generators name functions from it and duplicates collide silently;
- every referenced security scheme is **declared** — a missing one renders as a
  broken auth button and breaks generated clients;
- every operation documents the error envelope;
- `/auth/token/refresh` explains the single-flight requirement, because a client
  that misses it logs users out on every multi-tab race.

The prose is written to describe **behaviour a client must handle** — that refresh
rotation needs single-flight, that login and OTP-request are enumeration-safe by
design, which 403 the client should act on — not just field names.

## Security schemes

| Scheme | What |
|---|---|
| `cookieAuth` | `__Host-at` access-token cookie. Default mode. Pair with `csrfToken` on writes |
| `csrfToken` | Double-submit `X-CSRF-Token` header; must equal the readable `csrf` cookie |
| `bearerAuth` | `Authorization: Bearer` — mobile, desktop, cross-origin |
| `mfaChallenge` | Short-lived challenge token. Authorizes **only** `/auth/mfa/verify` and `/auth/mfa/otp/send`; carries no session and no permissions |

No global `security` requirement: most auth endpoints are deliberately public and a
blanket rule would document them wrongly. Each operation declares what it needs.

## Error contract

Every error, on every endpoint:

```json
{ "error": { "code": "INVALID_CREDENTIALS", "message": "…", "details": {}, "traceId": "…" } }
```

Branch on `code`, never on `message` or on the status alone. `traceId` equals the
`x-request-id` response header and the `reqId` in the logs.

**401 vs 403** — `401` means "no valid credential; refresh, then re-login". `403`
means "authenticated but not permitted; do not retry". The single exception is
`403 REAUTH_REQUIRED`, which the client *should* act on by prompting for step-up.

Genuine 5xx never forward their message. `NOT_IMPLEMENTED` and
`SERVICE_UNAVAILABLE` are the two deliberate exceptions: a 501 status with an
"Internal server error" body is a confusing lie, and a 503 needs to reach the
client for `Retry-After` to mean anything.

## Service index

`GET /` returns name, version and links to docs, health, readiness and JWKS.
`links.docs` is `null` when `SWAGGER_ENABLED=false`, so the index never advertises
an endpoint that is not there. It exposes no configuration and no dependency
state — that belongs on `/health/ready`, which is the endpoint you would gate.

404s carry `details: { index: "/", docs: "/docs" }` rather than leaving a developer
guessing whether the path, the method, or the service was wrong.

## Client codegen and CI

```bash
pnpm openapi          # writes apps/api/openapi/openapi.json
```

Commit it and `git diff --exit-code` in CI, so a breaking change to a request or
response shape fails the build instead of surprising a client at runtime.

> [!warning] Turn the docs off in production
> `SWAGGER_ENABLED=false`, or gate it. A public docs page hands an attacker a
> complete map of the auth surface, including which fields are optional and which
> codes each endpoint returns. The boot-time audit warns if you leave it on.

## Related

[[Auth module]] · [[Architecture]] · [[Testing]]
