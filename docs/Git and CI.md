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

**`image`** — builds the Dockerfile and then runs Argon2 inside the result. That
last step catches a failure mode no test can: the native binding not loading on
alpine/musl. It only ever appears inside the image.

## Two things that broke the first run

Both were found before pushing, by reading the config rather than waiting for a
red build:

- **`pnpm/action-setup@v4` errors** when a `version` input *and*
  `package.json#packageManager` both specify a version — even when they agree.
  The manifest is the single source of truth.
- **`pnpm db:migrate` read `DATABASE_URL` from the process environment only.** It
  worked locally purely because it had been exported by hand, and would have
  failed in CI. It now loads `.env` like every other script.

The lesson generalises: a script that works locally *because of something you
typed earlier* is a script that fails in CI.

## Pull requests

`.github/pull_request_template.md` carries the documentation checklist — the
change → note map lives in [[Home#Keeping this vault true]]. The template also
prompts for the risk areas worth a second look: `⚑` lines, `§` renumbering,
migrations, and changes to a rate limit or TTL.

## Not set up yet

These need the GitHub web UI or the `gh` CLI, which is not installed here:

- **Branch protection on `main`** — require the `static`, `integration` and
  `image` checks, require a PR, and forbid force-push. Worth doing before anyone
  else has push access.
- **Repository description and topics.**
- **Dependabot alerts and secret scanning** — Settings → Advanced Security.

## Related

[[Docker stack]] · [[Testing]] · [[Running locally]]
