---
aliases: [Progress, Inventory, What exists]
tags: [moc]
updated: 2026-07-31
---

# Built so far

An inventory of what actually exists, as opposed to what is specified. The spec is
[[AUTH-MODULE-PLAN]] and is complete; this note is the part of it that runs.

> [!info] Where the line is
> Sign up, verify, log in, refresh, read yourself, list devices and sign out are
> **live over HTTP** — real cookies, real CSRF, real rotation. Password reset,
> password change, the OTP engine and the 2FA endpoints still answer `501` with a
> pointer to the section that specifies them.

## Where the code lives

| Package | Depends on | What it holds |
|---|---|---|
| `@auth/core` | zod only | Ports, config schema, error model, all use-cases. The decisions. |
| `@auth/crypto` | `@auth/core` | Argon2id, Ed25519 JWTs, AES-256-GCM AEAD, TOTP, UUIDv7, CSPRNG |
| `@auth/db` | `@auth/core` | Drizzle schema (19 tables) and the Postgres repositories |
| `@auth/mail` | `@auth/core` | Nodemailer transport and templates |
| `@auth/testing` | `@auth/core` | In-memory doubles for every port, `FakeClock`, DB harness |
| `@app/api` | everything | Fastify app, OpenAPI, cookies, CSRF, the auth guard, health, metrics, JWKS |

The one-directional rule is the whole point — see
[[ADR-0006 Ports and adapters for portability]]. `core` imports nothing, so every
use-case is testable with no database, no containers and no wall-clock.

## Platform

- **Monorepo** — pnpm 11 workspaces + Turborepo, Node 24, TypeScript strict with
  `verbatimModuleSyntax`.
- **HTTP** — Fastify 5, OpenAPI 3.1 generated from the same zod schemas that
  validate ([[ADR-0005 Zod as the single source for validation, serialization and docs]]),
  Swagger UI at `/docs`, 28 documented paths.
- **Auth transport** — `__Host-at` / `__Host-rt` / `csrf` cookies with the refresh
  cookie scoped to `/auth/token`, double-submit CSRF
  ([[ADR-0010 Skip CSRF when a request carries no session cookie]]), and a guard
  that enforces the 2FA enrollment quarantine.
- **Reliability** — load shedding we own rather than the plugin's
  ([[ADR-0004 Own the load-shedding decision]]), Redis-backed rate limiting,
  `/health/live` and `/health/ready` split, Prometheus metrics.
- **Security headers** — one `HTTPS_ENABLED` flag drives HSTS, the CSP upgrade,
  COOP and cookie `Secure` ([[ADR-0008 Gate HTTPS-only headers behind one flag]]).
  See [[Security headers]].
- **Containers** — Postgres 17, Redis, Mailpit, and an optional observability
  profile. See [[Docker stack]].
- **CI** — three jobs (static, integration+coverage, image), Dependabot, importable
  branch rulesets. See [[Git and CI]].

## Data

19 `auth_*` tables, migrated, with the invariants enforced in SQL rather than in
application code: partial unique indexes on the live subset, atomic one-time-token
consumption, atomic OTP attempt accounting, `citext` email identity, and cascades
that preserve the audit trail. Covered by [[Testing#Integration]].

## Crypto

| Primitive | Notes |
|---|---|
| Argon2id password hashing | Bounded concurrency semaphore — ⚑ `memoryCost × maxConcurrency` is worst-case RAM ([[ADR-0003 Bound Argon2 concurrency instead of adding a worker pool]]) |
| `verifyDummy` | A real Argon2 verify against a fixed hash, for the unknown-user path |
| Ed25519 (EdDSA) JWTs | Access tokens only; refresh tokens are opaque and never JWTs |
| AES-256-GCM AEAD | TOTP secrets at rest, with the *purpose* bound as AAD so a ciphertext cannot be moved between uses |
| TOTP (RFC 6238) | `verify()` returns the matched timestep — ⚑ without it, ±1 drift is a 90-second replay window |
| UUIDv7 | Time-sortable, so inserts land at the right edge of the index |
| CSPRNG digits | Rejection sampling, never modulo ([[Glossary]]) |
| HIBP breach check | k-anonymity — five hex characters of the SHA-1 leave the process, nothing else |

## Auth use-cases

All in `packages/core/src/use-cases/`, all unit-tested against in-memory ports.

| Use-case | Spec | The part that is easy to get wrong |
|---|---|---|
| `register` | §5.1 | ⚑ Hashes *before* the user lookup and on both branches, so "already registered" is not faster to detect. Mails the real owner instead of telling the caller. |
| `verifyEmail` | §5.2 | Atomic consume; promotes `pending`→`active` only, so verification can never undo a suspension |
| `resendVerification` | §5.2 | Always reports success; invalidates outstanding links so only the newest works |
| `login` | §5.3 | Dummy verify on the unknown-user, no-password and deleted paths; atomic lockout; lazy rehash that does **not** touch `passwordUpdatedAt` |
| `rotateRefreshToken` | §5.5.3 | Rotation with reuse detection, and the recency rule from [[ADR-0009 Decide refresh-token theft on recency, not on read ordering]] |
| `issueSession` | §5.5.2 | The single place a session is created, so the absolute cap is set identically whichever door the user came through |
| `logout` / `logoutAll` | §5.6 | Idempotent and silent; logout-all also kills trusted devices |
| `listSessions` / `revokeSession` | §5.6 | ⚑ Ownership checked before existence is admitted, so session ids cannot be enumerated |

Login also branches correctly into 2FA: it issues a client-bound challenge token
that carries no `sid` and no permissions (§5.4.2), honours a trusted-device cookie
without ever setting `mfaSatisfiedAt` (§5.4.5), and quarantines rather than refuses
when policy requires a factor the user has not enrolled (§5.4.6).

## HTTP

| Route | State |
|---|---|
| `POST /auth/register` | Live — 202 whether or not the address is taken |
| `POST /auth/verify-email`, `POST /auth/resend-verification` | Live |
| `POST /auth/login` | Live — returns `authenticated`, `mfa_required` or `mfa_enrollment_required` |
| `POST /auth/token/refresh` | Live — rotates, and 409s the multi-tab race |
| `POST /auth/logout`, `POST /auth/logout-all` | Live |
| `GET /auth/me`, `GET /auth/sessions`, `DELETE /auth/sessions/{id}` | Live |
| Password reset / change (§5.7, §5.8) | `501` |
| OTP engine (§5.11), 2FA endpoints (§5.4) | `501` |

⚑ `mfa_required` is reachable but not completable: login issues the challenge
token, and `/auth/mfa/verify` is still a `501`. A deployment with a confirmed TOTP
factor would be unable to finish signing in — which is fine today because nothing
can enroll one yet, and is the reason 2FA is the next slice rather than a later one.

## Tests

449 across three layers — see [[Testing]] for the split and the reasons for it.
Coverage floors live in `vitest.config.ts` rather than in prose.

## Not built yet

- Password reset and change (§5.7, §5.8), and with them `/auth/reauth` — which is
  why step-up is only partially enforced: a password-only session currently passes
  the check on `logout-all` because there is no way for it to re-authenticate.
- The OTP engine (§5.11) and the 2FA endpoints (§5.4) — the *challenge* is issued
  by `login`, but nothing verifies one yet.
- RBAC, orgs and permissions (§10). `mfa.enforce: 'admins'` currently falls back to
  a per-user marker for want of a role table.
- OAuth/SSO (§5.10), passkeys (§5.13), API keys (§4.6), impersonation.
- ⚑ **Multi-replica.** Signing keys are generated in memory per process, so a token
  minted by one replica will not verify on another. `auth_signing_keys` exists and
  §8.6 specifies rotation — see [[Performance and scaling#Horizontal scaling]].

## Related

[[Home]] · [[Auth module]] · [[Architecture]] · [[Decisions]] · [[Testing]]
