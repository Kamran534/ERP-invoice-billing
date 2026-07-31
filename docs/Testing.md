---
tags: [testing]
updated: 2026-07-31
---

# Testing

**501 tests in three layers**, separated by what they need to run — because a suite
you can only run when Docker is up is a suite people stop running.

| Project | Files | Needs | Time | Count |
|---|---|---|---|---|
| `unit` | `*.test.ts` | nothing | ~15 s | 310 |
| `integration` | `*.int.test.ts` | Postgres, Mailpit, **outbound internet** | ~25 s | 96 |
| `e2e` | `*.e2e.test.ts` | full stack | ~55 s | 95 |

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
- **⚑ A TOTP test cannot reuse the code that confirmed the enrolment.**
  Confirming burns that timestep, so the next login has to use the *next* one —
  which is the replay guard working, not a test artefact. The unit suite moves the
  fake clock; e2e computes the code from `timestepAt() + 1` rather than
  `now + 30s`, because the latter lands two steps out when the call happens near a
  window boundary and then falls outside the ±1 drift tolerance.
- **⚑ Give each e2e test its own client address.** Rate limits key off
  `request.ip` and `app.inject()` reports 127.0.0.1 for everything, so on one
  address a suite shares a single five-registrations-per-hour bucket and fails as
  429s that look like broken handlers. `remoteAddress` per test is also the more
  honest model — these *are* different clients.
- **⚑ Do not hardcode a value the code derives.** The e2e suite asserted
  `__Host-at` literally, so it kept passing while the server emitted a name no
  browser would accept. Read it from config (`app.auth.config.cookies.names`) and
  assert the *rule* separately — there is now a test that walks every `Set-Cookie`
  and checks each prefix against what its attributes actually deliver.
- **⚑ Do not assert an ordering the code does not enforce.** A concurrency test that
  passes because your laptop happened to schedule the reads first is asserting an
  accident, and it will fail on a machine with different core counts — or, worse,
  keep passing while the behaviour it claims to protect is already broken. Assert
  the invariant the code guarantees (exactly one winner) and the *facts* the losers
  carry, not which branch they happened to take. See
  [[ADR-0009 Decide refresh-token theft on recency, not on read ordering|ADR-0009]].
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
- **⚑ Every auth cookie was silently discarded by browsers.** `__Host-at` went out
  without `Secure` over plain HTTP, and `__Host-rt` with `Path=/auth/token` — both
  violate the prefix rules, and a browser's response to that is to drop the cookie
  and say nothing. Login returned `200` and set nothing. 93 e2e tests passed
  throughout, because `app.inject()` parses `Set-Cookie` strings and enforces no
  browser policy at all. Found by opening Swagger UI and clicking Try it out.
- **⚑ The test env inherited `.env`.** `testEnv()` spreads `process.env`, which
  vitest has already populated from `.env` — so setting `COOKIE_MODE=both` locally
  changed what the suite asserted. Anything the tests make claims about is now
  pinned explicitly.
- **⚑ The random test double returned the same bytes on every call.** Ten
  "random" recovery codes were ten copies of one code, so "a code works exactly
  once" passed while nine identical spares kept working. Deterministic is not the
  same as constant — `createSequentialRandom().bytes()` now advances its counter,
  and the test asserts the ten codes are distinct.
- **⚑ The breach check was never wired.** `password.checkBreached` was `true`,
  no `BreachChecker` was constructed, and the use-case treats a missing checker as
  a third-party outage — so it failed open on every signup while the config read
  "enabled". Caught the first time an e2e test registered with a corpus password.
  The boot audit now refuses that combination outright.
- **Refresh rotation called four legitimate tabs thieves.** Ten concurrent claims
  against real Postgres returned four `reuse` verdicts on CI and zero locally, for
  months, because the assertion depended on the connection pool's scheduling rather
  than on anything the code promised —
  [[ADR-0009 Decide refresh-token theft on recency, not on read ordering|ADR-0009]].

## The test database is not your database

`pnpm db:test:setup` once, then `pnpm db:migrate:test`. It creates `billing_test`
alongside your development database, installs the extensions the compose init only
adds on first boot, and writes `TEST_DATABASE_URL` into `.env`.

⚑ This is not tidiness. `truncateAll` empties every `auth_*` table between tests,
and it used to fall back to `DATABASE_URL` — so `pnpm test:int` wiped the database
the developer was working in. It deleted a real account someone had registered
through Swagger UI minutes earlier, between one command and the next, and nothing
in the output suggested it had happened. The suite was green, because it was.

`createTestDb()` now refuses to run at all unless the target is disposable:

- `CI` is set — there, `DATABASE_URL` is an ephemeral service container.
- `TEST_DATABASE_URL` was set deliberately.
- The database name ends in `_test`.

Otherwise it throws before the first `TRUNCATE`, with the fix in the message.
Refusing to run is a worse morning than a failing test and a much better one than a
missing table.

The e2e project points its app at the same throwaway database when one is
configured. It does not truncate, but it does create accounts on every run, and
those have no business accumulating where someone is working.

## The one test that needs the internet

`packages/crypto/src/breach.int.test.ts` talks to the real
`api.pwnedpasswords.com`. Everything else in the integration project needs only
Docker.

It is deliberate: the thing worth verifying is the *protocol* — that a padded
response's zero-count rows are not read as hits, that a `429` throws rather than
returning "clean" — and a stub of HIBP would only assert that our stub matches our
reading of the docs. The reading is the part that could be wrong.

The corresponding e2e assertion tolerates a `202`, because the use-case fails open
when the service is unreachable and a network blip must not turn into a red build.
It is the integration test that holds the line.

## Related

[[Architecture]] · [[Performance and scaling]] · [[Auth module]]
