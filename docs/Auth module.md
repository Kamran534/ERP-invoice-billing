---
tags: [moc, auth]
updated: 2026-07-31
---

# Auth module

The full specification is [[AUTH-MODULE-PLAN]] — one document, ~1500 lines, with
stable `§` numbers that code comments and error messages cite. This note is the way
in: it links to the sections you actually need and tracks what is built.

> [!warning] Do not renumber the plan
> `§` references are scattered through source comments, the `501` response bodies,
> the Prometheus alert notes and the k6 thresholds. Add sections; never renumber.

## By question

| I want to know… | Read |
|---|---|
| Why build rather than buy | [[AUTH-MODULE-PLAN#0. Assumptions (veto any of these before Phase 0 starts)]] |
| What "auth" covers here | [[AUTH-MODULE-PLAN#2. Scope map — what "auth" means here]] |
| The tables and why each column exists | [[AUTH-MODULE-PLAN#4. Data model]] |
| How login works, end to end | [[AUTH-MODULE-PLAN#5.3 Login (password)]] |
| **How refresh rotation works** | [[AUTH-MODULE-PLAN#5.5 Refresh-token flow (rotation, reuse detection, revocation)]] |
| Two-factor, trusted devices, step-up | [[AUTH-MODULE-PLAN#5.4 Two-factor authentication (2FA) — full lifecycle]] |
| Passwordless login by code | [[AUTH-MODULE-PLAN#5.11 Login by one-time passcode (OTP)]] |
| What we are defending against | [[AUTH-MODULE-PLAN#8.7 Threat model → mitigation]] |
| The port interfaces to implement | [[AUTH-MODULE-PLAN#6. Ports (the genericity contract)]] |
| Every config knob | [[AUTH-MODULE-PLAN#7. Configuration surface]] |
| What ships when | [[AUTH-MODULE-PLAN#18. Delivery phases]] |
| What is still undecided | [[AUTH-MODULE-PLAN#19. Open decisions I need from you]] |

## The three flows worth understanding before touching anything

**Refresh rotation** (§5.5). Every refresh invalidates the token it was given. A
token presented twice means two parties hold it, so the entire session family is
revoked and the user is emailed. The consequence for clients is that
[[ADR-0002 Hybrid access and refresh tokens|single-flight is mandatory]] — parallel
refreshes from several tabs will trip your own theft detection.

**OTP** (§5.11). Six digits is ~20 bits. That is safe *only* because of three
things at once: a 5-attempt cap, exactly one live challenge per destination, and a
10-minute TTL. All three are load-bearing; none may be relaxed alone.

**Enumeration resistance** (§5.1, §5.3, §5.7, §5.11.1). Register, login, password
reset and OTP-request all return the same response whether or not the account
exists — same body, same status, same *timing*. The unknown-user path runs a dummy
Argon2 verification to keep the timing honest, and there is a test for it.

## Implementation status

| Surface | State |
|---|---|
| `/health/live`, `/health/ready`, `/metrics`, `/` | Built |
| `/.well-known/jwks.json` | Built |
| Everything under `/auth/*` | Contract published, handler returns `501` |

A 501 names the section that defines it:

```json
{"error":{"code":"NOT_IMPLEMENTED",
          "message":"Not implemented yet — see AUTH-MODULE-PLAN.md §5.3 (Phase 1)",
          "details":{"plannedIn":"§5.3 (Phase 1)"}}}
```

Nothing half-authenticates anyone: a stub never sets a cookie and never returns a
token shape, and there is an e2e test asserting exactly that.

**Blocking multi-replica:** signing keys are generated in memory per process, so a
token minted by one replica will not verify on another. The `auth_signing_keys`
table exists and §8.6 specifies rotation — see [[Performance and scaling#Horizontal scaling]].

## What already exists in code

The schema is real and migrated (19 tables), and the invariants it encodes are
covered by [[Testing#Integration]]: the partial unique index that enforces one live
refresh token per session, atomic one-time-token consumption, atomic OTP attempt
accounting, `citext` email identity, and cascade rules that preserve the audit trail.

## Related

- [[Architecture]] · [[API and Swagger]] · [[Testing]]
- [[Refresh token reuse detected]] — the runbook for the alert §5.5.4 describes
- [[User lost their 2FA device]] — the §5.4.4 fallback, written down
