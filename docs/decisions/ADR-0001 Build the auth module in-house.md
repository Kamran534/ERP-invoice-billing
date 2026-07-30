---
tags: [adr, auth, strategy]
status: assumed
date: 2026-07-30
---

# ADR-0001 — Build the auth module in-house

**Status:** ⚠️ **Assumed, not confirmed** · Blocks everything

## Context

Every option was open: Auth0, Clerk, Keycloak, Supabase Auth, or building. The
project was greenfield with no code, and the request was for an auth module
"generic for any project" — which reads as build.

## Decision

Build. Recorded as an **assumption** rather than a decision, because nobody has
confirmed it. It is flagged at the top of
[[AUTH-MODULE-PLAN#0. Assumptions (veto any of these before Phase 0 starts)]] as
A10 and in [[Decisions#Still open]].

## Consequences

- Roughly 80% of the plan exists because of this. If a managed provider is
  acceptable, most of Phases 3–7 collapse into a thin adapter and the threat model
  becomes someone else's problem.
- The cost is ongoing: 2FA, OTP, passkeys, SSO, key rotation, dunning of security
  email, and the audit trail are all ours to maintain.
- The benefit is control over the exact flows a billing product needs — OTP for
  customer-portal accounts but password + 2FA for owners, per-org policy, and an
  audit trail that survives GDPR erasure.
- **Reversal cost is very high after Phase 1.** Migrating hashed passwords out is
  possible; migrating sessions, MFA enrolments and audit history is not.

If this is wrong, it is cheapest to say so now.

## Related

[[Auth module]] · [[AUTH-MODULE-PLAN#18. Delivery phases]]
