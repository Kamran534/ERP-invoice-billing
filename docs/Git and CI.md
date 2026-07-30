---
tags: [operations, ci]
updated: 2026-07-31
---

# Git and CI

Repository: `git@github.com:Kamran534/ERP-invoice-billing.git`, default branch
`main`.

## Line endings

`.gitattributes` normalises everything to LF in the repository. Without it,
files authored on Windows land with CRLF, and a CRLF Dockerfile or shell script
fails inside a Linux container with an error that points nowhere near the cause.
`.ps1`, `.cmd` and `.bat` keep CRLF so they still run on Windows.

If `git status` shows a file as modified with no visible change, it is almost
always this. `git ls-files --eol <path>` shows what is stored (`i/`) versus what
is in the working tree (`w/`).

## What is committed, and what is not

| Committed | Why |
|---|---|
| `apps/api/openapi/openapi.json` | The contract baseline. CI regenerates it and fails on a diff, so a breaking API change cannot merge silently |
| `docs/.obsidian/{app,core-plugins,graph,templates}.json` | Shared vault behaviour — everyone gets the same plugins, link format and graph colours |
| `.env.example` | The documented shape of the environment |
| `pnpm-lock.yaml` | Reproducible installs; `--frozen-lockfile` in CI |

Not committed: `node_modules`, `dist`, `coverage`, `.turbo`, `.env`, and
Obsidian's per-user `workspace.json`.

> [!note] `docs/.obsidian/graph.json` will occasionally show as modified
> Obsidian stores the graph's zoom level in the same file as the colour groups.
> The colour groups are worth sharing; the zoom level is noise. Discard it with
> `git checkout -- docs/.obsidian/graph.json`, or commit it — neither matters.

## CI

`.github/workflows/ci.yml`, on push to `main` and on every pull request. Three
jobs.

**`static`** — install, build, typecheck, unit tests, `docs:check`. No
infrastructure, so a typo fails in about a minute instead of after containers
boot. Everything else waits on it.

**`integration`** — writes a `.env` with a generated `AUTH_KEK`, brings up the
compose stack, migrates, then runs all three test projects with coverage
thresholds, and finally regenerates the OpenAPI document and fails on a diff.

> [!tip] Why `docker compose` and not GitHub service containers
> Our Postgres needs `shared_preload_libraries=pg_stat_statements` and the init SQL
> that creates `citext`. Service containers can run neither. Reusing the compose
> file means CI tests the same database developers run — see [[Docker stack]].

**`image`** — builds the Dockerfile, then runs our own Argon2 hasher inside the
result. That last step catches a failure mode no test can: the native binding not
loading on alpine/musl. It only ever appears inside the image.

It goes through `@auth/crypto` rather than requiring `@node-rs/argon2` directly, so
it exercises the real graph (`@auth/crypto` → `@auth/core` → native binding) and
also fails if a production dependency is missing from the shipped image.

> [!warning] Resolve from a package that declares the dependency
> The step runs with `-w /app/apps/api`. pnpm's isolated `node_modules` puts
> `@node-rs/argon2` under `packages/crypto`, not the repository root, so a bare
> `require('@node-rs/argon2')` from `/app` fails with **"Cannot find module"** even
> though the package is unquestionably installed. This is not a broken image; it is
> resolution working as designed.

> [!note] Reproducing this step on Windows
> Git Bash rewrites `-w /app/apps/api` into `C:/Program Files/Git/app/...` through
> MSYS path conversion, and docker rejects it. Prefix with `MSYS_NO_PATHCONV=1`.
> Linux runners are unaffected.

## Three things that broke a CI run

The first two were found before pushing, by reading the config rather than waiting
for a red build. The third needed a real run.

- **`pnpm/action-setup@v4` errors** when a `version` input *and*
  `package.json#packageManager` both specify a version — even when they agree.
  The manifest is the single source of truth.
- **`pnpm db:migrate` read `DATABASE_URL` from the process environment only.** It
  worked locally purely because it had been exported by hand, and would have
  failed in CI. It now loads `.env` like every other script.
- **The image job's Argon2 probe used a bare `require`.** It had been verified by
  hand with an explicit `.pnpm` path, and the workflow was then written with the
  short form — which does not resolve. The Docker build itself was green; only the
  step after it failed.

The lesson generalises: something that works locally *because of what you typed
around it* — an exported variable, a resolved path — is a step that fails in CI.
Verify the command in the exact form the workflow will run it.

## Reviewing Dependabot PRs

Green CI is necessary, not sufficient. Three questions, in order:

1. **Is it a `0.x` package?** Then a *minor* bump is the de-facto major and deserves
   real review, whatever the PR title says. List them with:

   ```bash
   node -e "for (const f of ['package.json','apps/api/package.json','packages/core/package.json','packages/crypto/package.json','packages/db/package.json','packages/mail/package.json','packages/testing/package.json']) { const p = require('./' + f); for (const k of ['dependencies','devDependencies']) for (const [n, r] of Object.entries(p[k] || {})) if (/^[\^~]?0\./.test(r)) console.log(n, r, f); }"
   ```

   Today that is `drizzle-orm` and `drizzle-kit`, which are excluded from the
   grouped PR in `dependabot.yml` for exactly this reason. **Add to that exclusion
   list when a new `0.x` dependency appears.**

2. **Does it touch data?** For a drizzle bump, passing tests are not enough — the
   schema must still produce the same DDL:

   ```bash
   pnpm --filter @auth/db exec drizzle-kit generate   # expect: No schema changes
   git status --porcelain packages/db/migrations      # expect: empty
   ```

   A new migration file here means the upgrade changed how the schema is
   interpreted, which is a migration you did not write and did not intend.

3. **Can it be tested locally?** Bump it on a throwaway branch and run
   `pnpm test:coverage`. Cheaper than a revert.

> [!example] Worked example: drizzle-orm 0.44.7 → 0.45.2
> Arrived in the grouped "minor-and-patch" PR despite being a de-facto major.
> Tested on a branch: build, typecheck, 234/234 tests, coverage unchanged, and
> `drizzle-kit generate` reported no schema changes — byte-identical DDL. Safe.
> The grouping was then fixed so the next one arrives on its own.

The `actions` group is the low-risk case: CI validates itself, so a green run *is*
the evidence.

## Node 20 deprecation warnings

Every job logs a warning that `actions/checkout@v4`, `actions/setup-node@v4` and
friends target Node 20 and are being forced onto Node 24. They are warnings, not
failures, and the actions still work. Dependabot's `github-actions` ecosystem opens
the version bumps on a monthly schedule; guessing at major versions by hand risks
referencing a tag that does not exist and turning a warning into a hard failure.

## Pull requests

`.github/pull_request_template.md` carries the documentation checklist — the
change → note map lives in [[Home#Keeping this vault true]]. The template also
prompts for the risk areas worth a second look: `⚑` lines, `§` renumbering,
migrations, and changes to a rate limit or TTL.

## Branch protection

`main` is unprotected until someone imports a ruleset — GitHub does not read them
from the repository. Two are committed under `.github/rulesets/`, and importing is
Settings → Rules → Rulesets → New ruleset → **Import a ruleset**.

| File | Blocks | Leaves working |
|---|---|---|
| `main-baseline.json` | force-push, branch deletion | pushing straight to `main` |
| `main-full.json` | the above, plus merging without a PR or with red CI | only merges through a pull request |

**Start with the baseline.** It prevents the two things that lose history and costs
nothing while one person pushes directly to `main`.

> [!warning] The full ruleset changes how you work
> Requiring status checks blocks direct pushes, because the checks cannot have
> passed for a commit that does not exist upstream yet. Everything then goes via a
> branch and a pull request. Right end state; wrong thing to enable the day before
> you need to push a fix.

> [!danger] Renaming a CI job silently breaks the full ruleset
> Its required checks name the jobs by their `name:` in `ci.yml` — *"Build,
> typecheck, unit tests"*, *"Integration, e2e and coverage"*, *"Docker image"*.
> Rename one and the ruleset waits forever for a check that never reports, leaving
> `main` unmergeable. Re-import after any rename.

## Still to do in the GitHub UI

Neither can be done from here — there is no `gh` CLI and the SSH key authenticates
pushes, not the REST API.

- **Repository description and topics.**
- **Dependabot alerts and secret scanning** — Settings → Advanced Security. The
  `dependabot.yml` in this repository schedules *version* updates; *alerts* for
  known vulnerabilities are a separate switch.

## Related

[[Docker stack]] · [[Testing]] · [[Running locally]]
