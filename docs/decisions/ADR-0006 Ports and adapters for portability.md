---
tags: [adr, architecture]
status: accepted
date: 2026-07-30
---

# ADR-0006 — Ports and adapters for portability

**Status:** Accepted · **Related:** [[AUTH-MODULE-PLAN#6. Ports (the genericity contract)]]

## Context

The brief was an auth module "generic for any project", not one welded to this
billing app. Genericity claims are cheap; the test is whether the core can be
compiled and unit-tested with no framework, no driver and no network.

## Decision

`@auth/core` imports nothing but zod. It holds the port interfaces, the typed error
model and the config schema. Adapters implement the ports; the app composes them.

The dependency rule is one-directional and mechanical: **core → nothing, adapters →
core, app → everything.** `@auth/db` re-exports the drizzle operators others need so
the ORM choice stays behind that boundary.

## Alternatives rejected

**One package, folders for structure.** Simpler to navigate, and the discipline
lasts about a month — nothing stops a "core" file importing Fastify, and nothing
tells you when it happens.

**Interfaces without separate packages** (ports in the same package as adapters).
Same drift problem: the compiler never objects.

## Consequences

- Core is unit-testable with a fake clock and in-memory doubles, no containers.
- Swapping Postgres for another store means implementing the repo ports, not
  rewriting use-cases.
- pnpm's strict isolation enforces the rule: it caught `@auth/testing` importing
  `drizzle-orm` without declaring it, which is exactly the boundary violation the
  layout exists to prevent.
- The cost is real: more `package.json` files, and a new port means editing an
  interface plus every implementation.
- Ports are type-only, so they are excluded from coverage — they compile to nothing.

## Related

[[Architecture]] · [[Auth module]]
