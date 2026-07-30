---
aliases: [Start here, Index, Dashboard]
tags: [moc]
updated: 2026-07-31
---

# Invoice & Billing — documentation

Open the `docs/` folder as an Obsidian vault. Everything here is plain markdown, so
it reads fine on GitHub too — the wikilinks just render as literal `[[text]]` there.

> [!tip] New to the project?
> Read [[Architecture]] first, then [[Running locally]]. Everything else is
> reference you can reach for when you need it.

## Map

| Area | Start at |
|---|---|
| How the code is shaped | [[Architecture]] |
| Getting it running | [[Running locally]] · [[Docker stack]] |
| The auth subsystem | [[Auth module]] → [[AUTH-MODULE-PLAN]] |
| Public API | [[API and Swagger]] |
| Response headers | [[Security headers]] |
| Tests | [[Testing]] |
| Speed and capacity | [[Performance and scaling]] |
| Metrics and alerts | [[Observability]] |
| Why things are the way they are | [[Decisions]] |
| When something breaks | [[Runbooks]] |
| Unfamiliar term | [[Glossary]] |

## Current state

The auth **contracts** are final and published as OpenAPI; the **handlers** are
phased. Only health, metrics and JWKS are implemented — every `/auth/*` route
answers `501 NOT_IMPLEMENTED` with a pointer to the spec section that defines it.
See [[Auth module#Implementation status]].

Next up is **Phase 1**: password login plus the full refresh flow
([[AUTH-MODULE-PLAN#18. Delivery phases]]).

## Keeping this vault true

> [!important] Docs change in the same commit as the code
> Not afterwards. A note that lags is worse than no note, because it is believed.
> Read the relevant note before changing something, and update it in the same pass.

Which note a change touches, so this is mechanical rather than a judgement call:

| If you change… | Update |
|---|---|
| A package boundary, a plugin, the request pipeline | [[Architecture]] |
| An auth flow, table or config knob | [[AUTH-MODULE-PLAN]] (add `§`, never renumber) + [[Auth module]] if status moves |
| A route, schema, status code or error shape | [[API and Swagger]] |
| A response header | [[Security headers]] |
| Test counts, layers, coverage floors, house rules | [[Testing]] |
| A threshold, pool size, cost parameter, measured timing | [[Performance and scaling]] |
| A metric name, label or alert | [[Observability]] |
| A compose service, image or Dockerfile stage | [[Docker stack]] |
| An env var or a `package.json` script | [[Running locally]] |
| Anything with a rejected alternative worth remembering | new ADR in [[Decisions]] |
| A new way to be paged at 3am | new runbook in [[Runbooks]] |
| A term someone will have to look up | [[Glossary]] |

**Figures that go stale** and must be re-checked when touched: test counts and
coverage in [[Testing]], the measured Argon2 timing and k6 numbers in
[[Performance and scaling]], the path count in [[API and Swagger]], and the
implementation status table in [[Auth module]].

`pnpm docs:check` resolves every wikilink the way Obsidian does — including heading
links, aliases and links that accidentally wrap across a line. It runs as part of
`pnpm verify`.

## Conventions

- **`§` numbers are a contract.** Code comments, error messages and Prometheus
  alert notes cite sections of [[AUTH-MODULE-PLAN]] by number. Renumbering that
  document breaks references scattered across the codebase, so add sections
  rather than renumber them.
- **`⚑` marks a security-critical detail.** If you are changing a line near one,
  read the sentence attached to it first — it is there because the obvious
  implementation is wrong.
- One decision per note in [[Decisions]], one incident shape per note in
  [[Runbooks]]. Both have templates.

## Recently written

- [[Security headers]] and [[ADR-0008 Gate HTTPS-only headers behind one flag]] —
  the CSP directive that broke the docs UI for everyone except localhost
- [[ADR-0004 Own the load-shedding decision]] — a plugin whose types and
  implementation disagree, and the startup bug that hid behind it
- [[Refresh token reuse detected]] — the one alert that pages a human
