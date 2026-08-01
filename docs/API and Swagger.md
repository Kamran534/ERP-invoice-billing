---
tags: [api, architecture]
updated: 2026-07-31
---

# API and Swagger

Swagger UI at `/docs`, the document at `/docs/json` and `/docs/yaml`, a service
index at `/`. **38 documented paths**, OpenAPI 3.1.

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

## The server URL is relative, on purpose

`servers` is a single entry, `/`. Swagger UI resolves it against the origin the
page was loaded from, so **"Try it out" always calls the server that served the
docs** — localhost, a LAN address, staging, anywhere.

> [!bug] An absolute server URL breaks Try-it-out for everyone but you
> With `http://localhost:3000` hardcoded, opening the docs at
> `http://192.168.x.x:3000/docs` sends every Try-it-out request to
> `http://localhost:3000` — a different origin. CORS blocks it and Swagger UI
> reports a bare **"Failed to fetch"** with no indication that the server list is
> the cause. It works perfectly on localhost, so the breakage only appears when
> someone opens the docs from another machine. Same shape as the
> [[Security headers#The localhost trap|upgrade-insecure-requests trap]].

There are deliberately **no staging or production entries**. Placeholder hostnames
are worse than none: they are selectable in the UI, so a stray Execute fires a real
request at a domain we do not own. Add real environments when they exist.

An e2e test asserts the first server is `/` and that no entry is absolute.

> [!note] This is not a reason to widen CORS
> The relative URL removes the cross-origin call entirely. `CORS_ORIGINS` stays the
> allowlist of front-end origins that legitimately call this API — adding a LAN
> address there to make a docs button work would be trading a real control for
> convenience.

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

### How CSRF is actually enforced

An `onRequest` hook, before anything reads a session, on every unsafe method in
cookie mode. The `csrf` cookie is set alongside the session cookies and is
deliberately **not** `httpOnly` — the client has to be able to read it to echo it,
and a cross-origin attacker can cause it to be *sent* but not *read*.

Three carve-outs, all narrow:

- **Routes that run before a session exists** — login, register, verify-email,
  password reset, OTP and MFA verify. None of them acts on an existing session
  using ambient credentials, which is the property that makes a route forgeable.
- **⚑ Requests authenticated by `Authorization: Bearer`.** CSRF exists because a
  browser attaches cookies to cross-site requests whether or not the page meant
  it. It does not attach an `Authorization` header — setting one cross-origin
  needs a preflight the target has to permit, and the attacker would need the
  token anyway. This is what makes Swagger UI's Authorize button work in `both`
  mode, where session cookies from an earlier login are still in the jar and were
  triggering `CSRF_FAILED` on every write.
- **⚑ Requests carrying no session cookie at all** are skipped rather than refused.
  This is not the bypass it resembles: a cross-site attacker cannot *remove* the
  victim's cookies, so a request with none provably cannot act on an ambient
  credential. Refusing them instead breaks the two calls a client must always be
  able to make with nothing in hand — logging out, and finding out that it is
  logged out. The access and refresh cookies count too, so a request that carries
  one of those without the CSRF cookie is still refused.

### Where the tokens end up

Set `COOKIE_MODE` to `cookie` (default), `bearer`, or `both`.

| | Cookie mode (default) | Bearer mode |
|---|---|---|
| Access token | `__Host-at`, `httpOnly`, `Path=/` | response body |
| Refresh token | `__Secure-rt`, `httpOnly`, **`Path=/auth/token`** | response body |
| CSRF token | `csrf`, readable | not used |

The prefixes shown are the HTTPS ones and are derived, not configured — see
[[Security headers]].

⚑ **Swagger UI's Authorize button needs a token**, and cookie mode returns none.
For poking at the API by hand, set `COOKIE_MODE=both` — the cookies are still set
*and* the tokens come back in the body, so you can paste one into `bearerAuth`.
It is a convenience, not a production setting: it puts the refresh token
everywhere a response body goes.

⚑ The refresh cookie's `Path` is load-bearing. Scoped to `/` it would ride along
on every ordinary API call, so any request log, proxy, or mis-set CORS header on
any route becomes an exposure of the one credential that mints new sessions.

⚑ In cookie mode the tokens are **omitted from the body**, not merely ignored.
Returning them as well would put the refresh token everywhere a response body goes.

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
