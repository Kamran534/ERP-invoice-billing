---
tags: [adr]
status: accepted
date: 2026-07-31
deciders: [Muhammad Kamran]
---

# ADR-0010 — Skip CSRF when a request carries no session cookie

**Status:** Accepted · **Supersedes:** — · **Related:** [[ADR-0008 Gate HTTPS-only headers behind one flag]]

## Context

CSRF is enforced by an `onRequest` hook: on every unsafe method in cookie mode, the
`X-CSRF-Token` header must equal the readable `csrf` cookie. Routes that run before
a session exists — login, register, verify-email — are exempt by path.

The first draft refused any unsafe request that lacked the cookie, on the reasoning
that "no cookie" must not become the bypass. Two e2e tests immediately failed, and
both were describing real clients rather than test artefacts:

- `POST /auth/logout` with nothing in hand returned `403`. But logout is the one
  call a client must *always* be able to make: a browser cannot delete an
  `httpOnly` cookie itself, so a client whose session lapsed while the tab was
  backgrounded would be permanently unable to clear itself.
- `POST /auth/token/refresh` with no cookies returned `403 CSRF_FAILED` where the
  honest answer is `401` — the client has no refresh token, and telling it the CSRF
  check failed sends it to fix the wrong thing.

## Decision

Skip the CSRF check when the request carries **no session cookie at all** — not the
`csrf` cookie, not `__Host-at`, not `__Host-rt`. Enforce it in every other case.

The reasoning is that a cross-site attacker cannot *remove* the victim's cookies.
The browser attaches whatever it holds, so a request arriving with none provably
cannot act on an ambient credential, and there is nothing for CSRF to protect. The
check exists to stop a forged request from *using* a session; a request with no
session is not that.

Checking all three cookie names, rather than only `csrf`, closes the gap the naive
version would leave: a request that somehow carries `__Host-rt` without `csrf` is
still refused.

## Alternatives rejected

**Exempt `/auth/logout` by path.** Simplest, and it fixes the visible symptom.
Rejected because it exempts logout even when the caller *does* hold a session,
which is precisely when forced-logout CSRF is worth preventing. The rule adopted
here protects logout for anyone with a session and waves through only requests that
could not have done anything.

**Return `401` instead of `403` when the CSRF cookie is missing.** Fixes the
confusing status on refresh, but leaves logout broken and quietly moves a
"credential problem" answer into a hook that knows nothing about credentials.

**Drop CSRF on `/auth/token/refresh`.** Tempting because the refresh cookie is
already `Path`-scoped. Rejected: a forged refresh still rotates the chain, and a
rotation the real client does not learn about signs it out. Availability attacks
are attacks.

**Accept the breakage and require clients to keep a non-httpOnly copy.** Pushes a
security decision onto every client, and the copy would have to live somewhere
JavaScript can reach — which is the thing `httpOnly` exists to prevent.

## Addendum, 2026-08-01: bearer requests are exempt too

The same reasoning, reached from the other direction. In `both` mode a caller
authenticating with `Authorization: Bearer` still has session cookies sitting in
the browser, so the rule above saw a cookie and demanded the echo header — and
every write from Swagger UI's Authorize button failed with `CSRF_FAILED`.

A bearer header is not ambient authority: a browser never attaches one by itself,
setting it cross-origin requires a preflight the target has to permit, and an
attacker who has the token does not need CSRF. So a request carrying
`Authorization: Bearer` skips the check in any mode that accepts bearer.

⚑ This is only sound because `readAccessToken` agrees: when a `Bearer ` header is
present in such a mode, that is the credential used — it never falls back to the
cookie for a malformed header. If those two ever disagree, the exemption becomes a
bypass. Both are commented to say so.

## Consequences

An attacker can force a logout only for a user who has no session, which is not an
attack. Everything else stays protected.

The rule is stated in terms of what the browser *can* do rather than in terms of
route names, so a new route inherits the right behaviour without being added to a
list. Path-based exemptions still exist for pre-session routes, and that list does
have to be maintained.

A client that manually deletes its `csrf` cookie while keeping `__Host-at` gets a
`403` rather than a bypass, which is the correct end of the trade.

## Related

[[API and Swagger#How CSRF is actually enforced]] · [[Security headers]] ·
[[AUTH-MODULE-PLAN#8.3 Cookies & CSRF (cookie mode)]] · [[Built so far]]
