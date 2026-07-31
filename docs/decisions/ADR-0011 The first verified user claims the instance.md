---
tags: [adr]
status: accepted
date: 2026-08-01
deciders: [Muhammad Kamran]
---

# ADR-0011 — The first verified user claims the instance

**Status:** Accepted · **Supersedes:** — · **Related:** [[ADR-0006 Ports and adapters for portability]]

## Context

Every account arrives belonging to nothing. Something has to decide who may create
the first organization, and that decision is unusually consequential: the creator
becomes its owner, and the owner holds `*`.

The deployments this module targets pull in opposite directions. An internal ERP
install has one tenant and a handful of staff; a SaaS product has a tenant per
customer and expects self-service signup. A rule that suits one is a security hole
in the other — "anyone who verifies an email may create a tenant" is correct for
the second and, for the first, means anyone who can receive mail at the right
domain can appear inside the company's system as an owner of something.

## Decision

`orgs.selfService`, defaulting to **`first-user`**: an organization may be created
only while **none exists**. The first verified account claims the instance and
becomes its owner; everyone after joins by invitation. `anyone` and `never` cover
the SaaS and out-of-band cases.

The check is `count(orgs) = 0` evaluated inside the creating transaction, under a
transaction-scoped advisory lock. Creation of the org, its three system roles and
the owner's membership all happen in that same transaction.

## Alternatives rejected

**Auto-create a personal organization at registration.** Every user always has
somewhere to be, and no onboarding step. Rejected because a tenant is a billing and
data boundary, and one created implicitly has never had anyone decide who owns it —
the question resurfaces later as "whose workspace is this and why can't we delete
it". It also makes `first-user` meaningless, because the first registration would
consume it.

**A dedicated bootstrap CLI or seed script.** Unambiguous, and no window at all.
Rejected as the *default* because it puts a terminal between someone and their
first login on a product that otherwise needs none; it remains available as
`selfService: 'never'` plus direct provisioning.

**An `isInstanceOwner` flag on the user row, set for the first registration.**
Simpler to read. Rejected because it answers the wrong question — "was this person
first" rather than "is the instance unclaimed" — and it cannot be checked
transactionally against the thing it is actually protecting.

**A bootstrap token in the environment.** Strongest, and the pattern several
self-hosted products use. Rejected for the default because it fails closed in the
worst way: an operator who loses it before first login has to redeploy.

## Consequences

⚑ There is a window on a fresh install in which anyone who can register and verify
can claim the instance. It is exactly one organization wide and shuts permanently
the moment the first is created. On a deployment that is publicly reachable before
its first admin signs up, that window is real — set `never` and provision instead.

`count(*)` under READ COMMITTED takes no lock, so two racing claims both read zero
and both insert. An integration test proved it, and the fix is a
`pg_advisory_xact_lock` on the bootstrap path. Without it the default would have
been silently useless in exactly the situation it exists for.

Switching `first-user` → `anyone` later is safe and needs no migration. Going the
other way does nothing retroactively; existing orgs remain.

An organization can never exist without an owner, because the membership is
inserted in the same transaction. There is no repair path through the API if it
could — appointing an owner is itself an owner permission — which is also why the
last owner cannot be removed or demoted (§10.7).

## Related

[[AUTH-MODULE-PLAN#10.5 Where an organization comes from]] ·
[[AUTH-MODULE-PLAN#10.7 Rules that keep an organization usable]] ·
[[Auth module]] · [[Built so far]]
