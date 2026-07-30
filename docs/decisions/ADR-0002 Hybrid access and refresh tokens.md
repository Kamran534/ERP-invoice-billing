---
tags: [adr, auth, tokens]
status: accepted
date: 2026-07-30
---

# ADR-0002 — Hybrid access and refresh tokens

**Status:** Accepted · **Related:** [[AUTH-MODULE-PLAN#5.5 Refresh-token flow (rotation, reuse detection, revocation)]]

## Context

Two familiar extremes. **Stateless JWTs only**: fast, no lookup, but nothing can be
revoked before expiry — a stolen token is valid until it is not. **Opaque server
sessions only**: revocable instantly, but every resource server round-trips to the
auth service on every request.

A billing product needs both properties: authorization cheap enough to do on every
API call, and revocation that actually revokes.

## Decision

Split them by job.

| | Access token | Refresh token |
|---|---|---|
| Format | JWT, EdDSA | Opaque, 32 random bytes |
| Stored server-side | no | yes, **hash only** |
| Lifetime | 10 min | idle 30 d, absolute 90 d |
| Accepted by | any resource server | only `POST /auth/token/refresh` |
| Revocable | at expiry (or instantly, §5.9) | immediately |

⚑ **Refresh tokens are never JWTs.** A self-contained refresh token cannot be
revoked before expiry, which defeats the entire reason for having one.

Every refresh **rotates**: the presented token is marked used and a successor
issued. Presenting a used token means two parties hold it → the whole session
family is revoked, the user is emailed, an operator is paged.

## Consequences

- Permissions are re-read from the database on every rotation, so a role change or
  suspension takes effect within one access-token lifetime with no invalidation
  fan-out.
- **Clients must single-flight their refreshes.** Parallel refreshes from several
  tabs rotate the chain concurrently; the loser gets `409 REFRESH_IN_PROGRESS`, and
  a genuinely replayed token is treated as theft. This is a real client burden and
  it is documented on the endpoint itself.
- Theft becomes *detectable* rather than silent — the property that justifies the
  whole scheme, and it evaporates if you revoke only the single reused token.
- A partial unique index enforces "at most one live refresh token per session" in
  the database rather than by application discipline. [[Testing#Integration]]
  covers it.

## Related

[[Auth module]] · [[Refresh token reuse detected]] · [[API and Swagger]]
