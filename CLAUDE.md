# Working agreement

## Docs change with the code, in the same pass

`docs/` is an Obsidian vault and is the project's memory, not a report about it.

**Before** changing something, read the note that covers it. **In the same turn** as
the change, update that note. Not afterwards — a note that lags is worse than no
note, because it is believed.

`docs/Home.md` has the change → note map under **"Keeping this vault true"**. Use
it; it exists so this is mechanical rather than a judgement call each time.

When reporting back, say which notes were read and which were updated.

## Rules that are easy to break by accident

- **Never renumber `§` sections in `docs/AUTH-MODULE-PLAN.md`.** They are cited
  from source comments, `501` response bodies, Prometheus alert notes and k6
  thresholds. Add sections instead.
- **`⚑` in source marks a security-critical line.** The sentence attached explains
  why the obvious implementation is wrong. Read it before editing nearby.
- **Figures go stale.** Test counts and coverage in `Testing`, the measured Argon2
  timing and k6 numbers in `Performance and scaling`, the path count in
  `API and Swagger`, the status table in `Auth module`. Re-check when touched.
- A decision with a rejected alternative worth remembering → new ADR in
  `docs/decisions/` (template in `docs/templates/ADR.md`).
- A new way to be paged → new runbook in `docs/runbooks/`.

## Verify

```bash
pnpm verify        # build + typecheck + unit tests + docs:check
pnpm test:all      # all three test projects (needs Docker)
pnpm docs:check    # resolves every wikilink the way Obsidian does
```

`pnpm docs:check` catches renamed notes, edited headings, and wikilinks that
accidentally wrap across a line — which render as literal text and look fine in the
source.

## Orientation

| | |
|---|---|
| Vault entry point | `docs/Home.md` |
| How the code is shaped | `docs/Architecture.md` |
| Auth specification | `docs/AUTH-MODULE-PLAN.md` (via `docs/Auth module.md`) |
| Why things are as they are | `docs/Decisions.md` |
