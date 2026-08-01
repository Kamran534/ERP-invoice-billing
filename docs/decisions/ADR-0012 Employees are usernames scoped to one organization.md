---
tags: [adr]
status: accepted
date: 2026-08-01
deciders: [Muhammad Kamran]
---

# ADR-0012 — Employees are usernames scoped to one organization

**Status:** Accepted · **Supersedes:** — · **Related:** [[ADR-0011 The first verified user claims the instance]] · [[AUTH-MODULE-PLAN#10.12 Employee accounts]] · [[AUTH-MODULE-PLAN#10.13 Tenant addressing: one subdomain per organization]]

## Context

The product has exactly two kinds of person in it, and until now the auth module
only knew about one.

An **owner** signs up with their own email address, verifies it, and creates the
organization they will run. Everything about that flow assumes a mailbox: the
verification link, the password reset, the "someone tried to register with your
email" notice.

Their **staff** are not customers of this product. They do not choose to sign up,
they may not have a company email address at all, and in the businesses this is
built for they are as likely to be handed a username on a piece of paper as to be
sent an invitation. Modelling them as "a user who was invited by email" makes the
owner do work — collect addresses, chase acceptances — for a relationship where the
owner already has full authority to say who works there.

Two constraints shaped the answer:

- **Usernames cannot be globally unique.** `ahmed` is not a scarce resource that
  the first tenant to arrive gets to keep. But uniqueness has to be enforceable by
  the database, and a unique index cannot reach through `auth_memberships` to
  discover which organization a user row belongs to.
- **A username with no context identifies nobody.** If the same name exists in
  fifty tenants, a login form that takes only a username and a password is
  ambiguous, and resolving the ambiguity by "whichever matched the password" is an
  account-takeover mechanism, not a login.

## Decision

An employee is a user row with `username` and `org_scope_id` set, no email address,
and `status: 'active'` from the moment the owner creates it.

- `unique (org_scope_id, username)` — uniqueness per tenant, enforced by Postgres,
  with `CHECK ((username IS NULL) = (org_scope_id IS NULL))` stating that the name
  and its scope travel together. ⚑ Deliberately *no* "must have an email or a
  username" check: passkey-only and SSO-only accounts have neither, and the schema
  integration test caught the first version of this migration for saying otherwise.
- **Each organization gets a subdomain**, `<slug>.<root domain>`, and that address
  is what supplies the missing context: the web app reads the host, resolves the
  slug, and passes it to `POST /auth/login` as an explicit `org` field.
- At a tenant address, an **email** login is accepted only from that organization's
  owner (`WRONG_LOGIN_PORTAL` otherwise). At the apex, a **username** login is
  refused outright — indistinguishably from a wrong password.
- No employee may hold `owner`.

## Alternatives rejected

**Invite every employee by email.** What the module already did. It fails the
actual case: staff without addresses, and an owner who is not trying to *invite*
anyone — they are creating an account for someone who works for them. It also puts
a mailbox in the critical path of onboarding a shop floor.

**Globally unique usernames.** One index, no scope column, no subdomain needed for
login. Rejected because the first tenant to register `ahmed` takes it from every
tenant afterwards, and because in a product sold to many small businesses the
collision rate on ordinary first names approaches certainty.

**A workspace picker on the login form.** Type a username, choose the organization
from a dropdown. Rejected because populating it means an endpoint that lists
tenants — an enumeration oracle for every organization on the instance — and
because the address bar already carries the answer without asking.

**Resolving the tenant from the `Host` header inside the API.** Rejected because
the API sits behind a BFF: the host it sees is the proxy's, so the value would be
either wrong or attacker-supplied. The tenant is an explicit parameter, verified
against the membership.

**A `kind: 'owner' | 'employee'` column.** Rejected as a second source of truth.
"Has no email" and "has a username scoped to an org" are already the facts that
matter, and every rule falls out of them — an employee cannot use the apex form
because there is nothing to type into it.

## Consequences

- An employee's only recovery path is the owner: `POST …/employees/:id/password`.
  There is no self-service reset, by design, and it revokes their sessions.
- The slug is now a **DNS label**, so it is validated as one and checked against a
  reserved list (`www`, `api`, `mail`, …). It was already immutable; now it matters
  more, because it is an address people type.
- Session cookies are issued for the apex domain so one sign-in works across the
  apex and every workspace. ⚑ In development this rules out `localhost` — it is a
  reserved TLD and Chrome silently downgrades `Domain=localhost` to host-only — so
  local development runs on `lvh.me`, whose every subdomain resolves to 127.0.0.1.
- Two doors mean two login forms, and the front end has to decide which to show
  from the host. It does not decide who may pass: the API does.
