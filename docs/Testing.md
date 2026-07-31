---
tags: [testing]
updated: 2026-07-31
---

# Testing

**333 tests in three layers**, separated by what they need to run — because a suite
you can only run when Docker is up is a suite people stop running.

| Project | Files | Needs | Time | Count |
|---|---|---|---|---|
| `unit` | `*.test.ts` | nothing | ~5 s | 183 |
| `integration` | `*.int.test.ts` | Postgres, Mailpit | ~25 s | 89 |
| `e2e` | `*.e2e.test.ts` | full stack | ~5 s | 61 |

Configured as three vitest **projects** in `vitest.config.ts`. Workspace packages
alias to their **source**, not `dist/`, so tests never need a prior build, coverage
maps to real files, and a stale `dist/` cannot make a passing test lie.

## Unit

No I/O, so they run anywhere. The interesting ones assert *properties*:

- A **χ² test over 60,000 generated OTP digits** catches a regression to
  `random % 10`, which biases digits 0–5 upward by ~1.6% each and shrinks the
  keyspace. Rejection sampling is not obviously necessary until you measure it.
- **UUIDv7 ids must sort in generation order** — that index locality is the entire
  reason for choosing v7 over v4.
- **`verifyDummy()` is timed against a real verification.** The lower bound is the
  load-bearing assertion: it catches the regression where the dummy path is stubbed
  out and returns instantly, reopening the enumeration oracle.

The token tests are mostly **forgery attempts**: `alg: none`, HS-vs-EdDSA confusion
using the public key as an HMAC secret, an unknown `kid`, a tampered payload, wrong
issuer and audience. Each is a *configuration* mistake rather than a cryptographic
break, which is exactly why each needs a test.

## Integration

Run against the real Postgres and the real Mailpit, because the guarantees under
test are not in application code:

- 12 concurrent redemptions of one password-reset token → **exactly one wins**.
- 40 parallel guesses against a 5-attempt OTP cap → **exactly 5 recorded**.
- Two live refresh tokens for one session → rejected by a partial unique index, so
  the [[Auth module|rotation invariant]] is enforced by the database rather than by
  discipline.
- `citext` means `Ada@Example.com` and `ada@example.com` are one account.
- Deleting a user cascades to sessions and tokens but **leaves the audit trail** —
  GDPR erasure must not be able to delete security history.
- Mail keeps its fail-soft promise: `send()` to a dead relay resolves and reports
  failure through its callback rather than throwing into a login.

> [!tip] Assert on SQLSTATE, not on message text
> `expectUniqueViolation(op, 'uq_refresh_active_per_session')` checks SQLSTATE
> `23505` **and the constraint name**. That proves the specific index fired, and
> survives a Postgres version bump that rewords the message.

## E2E

Drive the real app through `app.inject()` — real plugin chain, real ajv validation,
real serializers, real dependencies, no sockets. They cover what no single route
owns: the error envelope and its `traceId`, security headers, `no-store` on `/auth`
but `max-age` on JWKS, unknown-field stripping, `coerceTypes` being off so `"1"`
never becomes `1`, and that a stub never sets a cookie or returns a token shape.

They also treat the **OpenAPI document as a contract**: every operation has a
summary, a tag and a *unique* `operationId` (generators collide otherwise), every
referenced security scheme is declared, every operation documents the error
envelope, and `/auth/token/refresh` explains the single-flight requirement.

## Coverage

Roughly **96% statements, 88% branches, 94% functions** across the whole suite.

> [!note] Deliberately approximate
> The exact figures move by a hundredth on almost every commit, so a precise number
> written here is guaranteed to be wrong and nobody notices. The **enforced** floors
> live in `vitest.config.ts`, where CI fails if they are breached — that is the
> number that means something. Read the current figure from `pnpm test:coverage`.

Measured over the **whole** suite, which is why `pnpm test:coverage` runs every
project and needs Docker. A unit-only number would be meaningless: the HTTP layer
is covered by e2e and the schema by integration.

Thresholds are floors just below the current measurement — high enough to catch a
regression, not so high that an unrelated refactor turns CI red and teaches people
to lower them. Stricter per-file floors apply to the four modules where an
off-by-one is a vulnerability rather than a bug: `semaphore.ts` (100 %),
`random.ts`, `errors.ts`, `duration.ts`.

Excluded as non-runtime: type-only `ports.ts`, barrel `index.ts` files, the
migration CLI, the process bootstrap.

## Running without Docker

`pnpm test` needs nothing. Integration and e2e share a global setup that checks the
stack **once** and fails with one actionable message instead of dozens of timeouts:

```
Integration/e2e tests need the docker stack running.
  - Postgres unreachable at postgres://***@localhost:55432/billing
  - Redis unreachable at redis://localhost:56379
  Start it with:  pnpm up && pnpm db:migrate
  Unit tests need none of this:  pnpm test
```

## Serialising the projects that share a database

Integration and e2e run **one file at a time**. They share a single Postgres and
truncate in `beforeEach`, so two files in parallel means one file's truncate
deleting rows another is mid-way through asserting on.

> [!danger] `fileParallelism: false` does not do this inside a project
> That option is honoured only at the **root** of the vitest config. Inside a
> `projects[]` entry it is silently ignored — no warning, no error. The setting sat
> in the integration project looking correct for as long as there was exactly one
> integration file, and broke the instant a second appeared: 18 failures whose
> messages all pointed at the repository code and had nothing to do with it.
>
> `pool: 'forks'` plus `poolOptions.forks.singleFork` is what actually serialises.
> Both are set, with `fileParallelism` left alongside them to state the intent.

The tell: each file passes alone, and they fail together. If you see that, suspect
shared state before suspecting the code — and check whether the option you rely on
is one vitest only accepts at root level.

## When the runner itself fails

`spawn UNKNOWN`, `ERR_IPC_CHANNEL_CLOSED`, or a project reporting **no tests** at
all is not a test failure — it is vitest being unable to fork worker processes.
Almost always memory. `pnpm test:coverage` runs three projects and forks three sets
of workers, so it is the first thing to break on a loaded machine.

```powershell
docker compose stop prometheus grafana adminer   # the obs profile is not needed to test
```

Then run the projects one at a time: `pnpm test`, `pnpm test:int`, `pnpm test:e2e`.
If they pass individually, nothing is wrong with the code.

## House rules for new tests

- **Name by layer**: `foo.test.ts`, `foo.int.test.ts`, `foo.e2e.test.ts`. The
  `include` patterns key off it.
- **Integration and e2e run serially** via `poolOptions.forks.singleFork` — they
  share one database and truncate between tests. See the warning above about why
  `fileParallelism` is not the setting that achieves this.
- **Anything touching rate limits needs its own `REDIS_KEY_PREFIX`.** Counters are
  shared state with a one-hour window; without isolation a suite inherits the
  budget the previous run spent, and unrelated tests start seeing `429`.
- **Wait for conditions, never for durations.** The e2e helpers poll
  `/health/ready` and the pressure reading rather than sleeping a guessed interval
  that breaks on a slower box.
- **Put diagnostics in the failure message.** "Rate limit never triggered" tells
  you nothing; the observed status sequence and the first 5xx body tell you whether
  the limiter was bypassed, mis-keyed, or erroring because its store was down.
- **Timing-sensitive assertions take the minimum of N runs**, not the mean — the
  minimum approximates the uncontended cost and barely moves under load.
- Test files are excluded from every package build, so they would go entirely
  unchecked. `tsconfig.test.json` typechecks them as part of `pnpm typecheck`.

## Bugs this suite has already caught

See [[Decisions]] for the full stories.

- [[ADR-0004 Own the load-shedding decision|Load shedding was completely broken]] —
  returned 500 instead of 503, and a freshly-started process shed *every* request.
- **Fail-closed rate limiting leaked a 500** when Redis had not connected yet.
- **The readiness cache was module-scoped**, so two app instances shared a verdict.
- **A JWKS rate limit of 60/min** would have broken token verification fleet-wide —
  caught by [[Performance and scaling#5. Load testing]], not by these tests.
- **`upgrade-insecure-requests` broke the docs UI** for every non-localhost
  visitor. Now covered by four tests, including one that checks the docs CSP
  separately from the API CSP — see [[Security headers]].

## Related

[[Architecture]] · [[Performance and scaling]] · [[Auth module]]
