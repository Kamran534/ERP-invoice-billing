---
tags: [moc, decisions]
updated: 2026-07-31
---

# Decisions

Architecture decision records. One decision per note, written when the reasoning is
still fresh — the value is in the *rejected* alternatives, which are invisible six
months later.

New one: `templates/ADR` (Templates → Insert template).

| # | Decision | Status |
|---|---|---|
| [[ADR-0001 Build the auth module in-house\|0001]] | Build auth rather than buy | Accepted, **assumed** |
| [[ADR-0002 Hybrid access and refresh tokens\|0002]] | Short JWT access + opaque rotating refresh | Accepted |
| [[ADR-0003 Bound Argon2 concurrency instead of adding a worker pool\|0003]] | Semaphore, not piscina | Accepted |
| [[ADR-0004 Own the load-shedding decision\|0004]] | Our hook, not the plugin's handler | Accepted |
| [[ADR-0005 Zod as the single source for validation, serialization and docs\|0005]] | One schema, three jobs | Accepted |
| [[ADR-0006 Ports and adapters for portability\|0006]] | Pure core, adapters at the edge | Accepted |
| [[ADR-0007 Three test layers split by dependency\|0007]] | unit / integration / e2e | Accepted |
| [[ADR-0008 Gate HTTPS-only headers behind one flag\|0008]] | One `HTTPS_ENABLED` drives HSTS, CSP upgrade, COOP, cookie `Secure` | Accepted |
| [[ADR-0009 Decide refresh-token theft on recency, not on read ordering\|0009]] | The repo reports `usedAt`; core forgives a claim from the last 2 s | Accepted |

## Still open

These are assumptions, not decisions — flagged in
[[AUTH-MODULE-PLAN#19. Open decisions I need from you]] and waiting on a human:

- **Build vs buy** (blocks everything) — 0001 is an *assumption*. A managed
  provider collapses most of Phases 3–7.
- **OTP as primary login for admins** — assumed no (`excludeRoles`).
- **SMS channel** — assumed off. Enabling means a provider contract and SIM-swap risk.
- **Trusted devices** — assumed off. For a product handling money, probably keep
  them off for admin roles regardless.
- **Enterprise SSO / SCIM** — real demand, or defer?

## Related

[[Architecture]] · [[Auth module]] · [[AUTH-MODULE-PLAN#0. Assumptions (veto any of these before Phase 0 starts)]]
