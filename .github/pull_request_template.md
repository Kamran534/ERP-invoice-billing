## What and why

<!-- What changed, and the reason. The diff shows the what; this is for the why. -->

## Documentation

<!-- Docs change in the same PR as the code — see CLAUDE.md and docs/Home.md
     ("Keeping this vault true") for the change → note map. -->

- [ ] Updated the notes this change touches, **or** it genuinely touches none
- Notes updated:

<!-- Delete any that do not apply. -->
- [ ] New decision with a rejected alternative worth remembering → ADR in `docs/decisions/`
- [ ] New way to be paged → runbook in `docs/runbooks/`
- [ ] A figure that goes stale changed (test counts, coverage, measured timings,
      path count, implementation status) → re-checked against a real run

## Checks

- [ ] `pnpm verify` passes (build, typecheck, unit tests, docs links)
- [ ] `pnpm test:all` passes locally, or CI is green
- [ ] Public API changed → `pnpm openapi` re-run and the result committed

## Risk

<!-- Anything reviewers should look hardest at. In particular:
     - a line marked ⚑ in the source (security-critical; the comment says why)
     - a `§` section number cited from code (never renumber — add sections)
     - a migration (must stay backward-compatible for one release so N-1 pods serve)
     - a rate limit, TTL, or threshold change
     Write "none" if none. -->
