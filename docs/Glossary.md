---
tags: [reference]
updated: 2026-07-31
---

# Glossary

Terms that mean something specific here, where the general meaning would mislead.

## Auth

**Access token** — EdDSA-signed JWT, 10 minutes, stateless. Carries `sub`, `sid`,
`org`, `roles`, `perms`, `amr`. Verifiable by any resource server via the
JWKS endpoint below, without calling us.

**`amr`** — *authentication methods references*. The list of factors a session
actually used: `['pwd','otp']`. Drives the rule that one channel cannot count as
both factors.

**Absolute expiry** — the hard cap on a session's life, never extended for any
reason. Distinct from **idle expiry**, which slides on each refresh. A stolen
session that is used continuously still dies at the absolute cap.

**Challenge token** — the short-lived thing `/auth/login` returns when 2FA is
required. Not a session: it carries no `sid`, no permissions, and authorizes
exactly two endpoints. Five wrong attempts destroy the *challenge*, not just the
attempt.

**Enumeration resistance** — returning identical responses, with identical timing,
whether or not an account exists. Costs a dummy Argon2 verification on the
unknown-user path. See [[Auth module]].

**JWKS** — JSON Web Key Set at `/.well-known/jwks.json`. Public keys only.
The hottest endpoint in a fleet: every resource server polls it, every pod
re-fetches on cold start. Rate-limiting it tightly breaks token verification
cluster-wide.

**Quarantine session** — what a user gets when policy requires 2FA and they have
none enrolled. Real session, but reaches only `/auth/me` and the enrolment
endpoints. Avoids the classic bug where enforcement locks users out of the screen
that satisfies enforcement.

**Refresh rotation** — every refresh invalidates the token it was given and issues a
successor. Makes theft *detectable*: whoever presents second trips the alarm.

**Reuse detection** — presenting an already-used refresh token. Treated as presumed
theft; the whole session family dies. → [[Refresh token reuse detected]]

**Single-flight** — one in-flight refresh per client, across all tabs. Mandatory,
not an optimisation: parallel refreshes trip your own reuse detection.

**Step-up** — re-authenticating for a sensitive action even though already signed
in. Gated on `mfa_satisfied_at` being recent. A trusted device never satisfies it.

**Trusted device** — "don't ask for 2FA here for 30 days". Off by default. Dies on
any credential change and is never accepted for step-up — otherwise it is a 2FA
bypass with a friendly name.

## Infrastructure

**Fail closed / fail open** — what a control does when its backend is unreachable.
Rate limiting fails **closed**: an outage must not become an open brute-force
window. Mail fails **soft**: delivery must never fail a login.

**Load shedding** — returning 503 + `Retry-After` before the process degrades, so a
load balancer can route elsewhere. Health, metrics and docs are exempt.
→ [[ADR-0004 Own the load-shedding decision]]

**Liveness vs readiness** — liveness answers "is this process wedged?" and touches
nothing. Readiness answers "should traffic come here now?" and checks everything.
Confusing them turns a database blip into a full restart cascade.

**Partial index** — a Postgres index with a `WHERE` clause. Used here to enforce
*at most one live refresh token per session* and to keep hot indexes small as dead
rows accumulate.

**`§`** — a section number in [[AUTH-MODULE-PLAN]]. Cited from source comments,
error bodies and alert notes. Stable by convention: add sections, never renumber.

**`⚑`** — marks a security-critical line in the source. The sentence attached
explains why the obvious implementation is wrong.

## Billing domain

From [[Zoho Invoice and Billing modules]], the reference the product is modelled on.

**Dunning** — automated recovery of failed subscription payments: retries, card-update
requests, expiry warnings. The difference between churn and *involuntary* churn.

**MRR** — monthly recurring revenue. The headline subscription metric.

**Proration** — the fair mid-cycle price adjustment when a subscription changes plan.

**Credit note** — money owed *to* the customer: a downgrade, a return, an
overcharge. Applied to a future invoice or refunded.

**Retainer** — an advance payment held against future invoices.

## Related

[[Home]] · [[Auth module]] · [[Architecture]]
