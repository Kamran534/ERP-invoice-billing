---
tags: [adr, testing]
status: accepted
date: 2026-07-31
---

# ADR-0007 — Three test layers split by dependency

**Status:** Accepted · **Related:** [[Testing]]

## Context

Tests that need Docker are slower, flakier and unrunnable on a train. Tests that
mock the database prove nothing about the guarantees that live *in* the database —
and in an auth system, several of the most important ones do: atomic token
consumption, the partial unique index behind refresh rotation, `citext` identity.

Mixing both kinds in one suite means the whole suite inherits the worst properties
of each.

## Decision

Three vitest projects, split by what each is **allowed to need**:

| Project | Pattern | May use |
|---|---|---|
| `unit` | `*.test.ts` | nothing |
| `integration` | `*.int.test.ts` | Postgres, Mailpit |
| `e2e` | `*.e2e.test.ts` | the whole stack |

`pnpm test` runs unit only, so the default is fast and dependency-free. Workspace
packages alias to **source**, not `dist/`, so no build is needed first.

## Consequences

- Integration and e2e run **serially** — they share a database and truncate between
  tests.
- A shared global setup checks the infrastructure once and fails with one
  actionable message instead of dozens of timeouts.
- Coverage must be measured across **all three** (`pnpm test:coverage` needs
  Docker). A unit-only number is meaningless: the HTTP layer is covered by e2e and
  the schema by integration.
- Anything touching rate limits needs its own `REDIS_KEY_PREFIX`, or it inherits
  the budget the previous run spent.
- E2E relaxes the load-shedding thresholds, because a vitest worker's startup
  genuinely blocks the event loop past the production limit. Shedding is tested
  separately with a deliberately unreachable threshold — see
  [[ADR-0004 Own the load-shedding decision]].

## Related

[[Testing]] · [[Architecture]]
