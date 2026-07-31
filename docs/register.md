---
aliases: [POST /auth/register, Registration, Sign up]
tags: [api, auth]
updated: 2026-07-31
---

# register

`POST /auth/register` — creates a pending account and emails a verification link.

Specified in [[AUTH-MODULE-PLAN#5.1 Registration]], implemented
in `packages/core/src/use-cases/register.ts`, wired in
`apps/api/src/routes/auth/session.ts`.

> [!important] The one thing to understand before using it
> **A `202` does not mean an account was created.** It means "if that address can
> be registered, a link is on its way". The response is byte-for-byte identical
> whether the address was free or already belonged to someone — and so is the time
> it takes. Everything below that looks redundant exists to keep that true.

## Request

```http
POST /auth/register
Content-Type: application/json

{
  "email": "ada@example.com",
  "password": "a passphrase of at least twelve characters",
  "name": "Ada Lovelace"
}
```

| Field | Rules |
|---|---|
| `email` | Required. RFC-shaped, ≤320 chars. Stored `citext`, so case-insensitive forever |
| `password` | Required. 12–200 characters. No composition rules |
| `name` | Optional, 1–200 characters |

Unknown fields are **stripped, not rejected** — so a hopeful `"isAdmin": true` is
removed before the handler sees it, and there is an e2e test asserting exactly that.

Rate limit: **5 per hour per IP**. The response carries `x-ratelimit-remaining` and
`x-ratelimit-reset` (seconds).

### Password rules, and what is deliberately absent

12 characters minimum, 200 maximum, and no requirement for symbols, digits or
mixed case. That follows NIST 800-63B: composition rules reliably produce
`Password1!` rather than anything stronger, and they annoy the people who were
already choosing well.

The 200-character maximum is **not** about strength. It stops a megabyte of input
becoming a memory-hard Argon2 hash large enough to take the process down.

What replaces composition rules is a **breach check**: the password is looked up in
the Have I Been Pwned corpus by k-anonymity — only the first five hex characters of
its SHA-1 leave the process, and the comparison happens locally. A long, memorable,
*published* passphrase is rejected with `PASSWORD_BREACHED`.

⚑ The check **fails open**. If HIBP is unreachable the signup proceeds and a
warning is logged, because a third-party outage must not stop people using the
product. That is a deliberate trade, and it is the reason
`auditProductionConfig` refuses to boot a production process where
`password.checkBreached` is on but no checker is wired — a control that is
configured-on and silently absent is worse than one that is honestly off.

## Responses

| Status | Meaning |
|---|---|
| `202` | Accepted. Says nothing about whether the account is new |
| `400` | Malformed request — not JSON, missing `email`, wrong type |
| `422` | Well-formed but unacceptable: `WEAK_PASSWORD`, `PASSWORD_BREACHED` |
| `429` | Rate limited. `Retry-After` and the `x-ratelimit-*` headers say when |
| `503` | The Argon2 queue is saturated. Retryable — see [[Performance and scaling]] |

```json
{
  "status": "verification_sent",
  "message": "If that address can be registered, a verification link is on its way."
}
```

⚑ No cookie is set and no token is returned. Registering does not sign anyone in.

## What actually happens

1. **The password is checked** against the length bounds and the breach corpus.
2. **The password is hashed** — ⚑ *before* the account is looked up, and on both
   branches. Hashing is by far the most expensive step in the request, so hashing
   only when the address turns out to be free would make "already registered"
   reliably faster to detect. The identical body is worthless if the clock gives
   the answer away.
3. **The address is looked up.**
   - *Taken* → a "someone tried to register with your email" notice goes to the
     **real owner**, an audit row is written with `reason: email_taken`, and the
     caller gets the same `202`. The person who learns something is the account
     holder; the caller learns nothing.
   - *Free* → a user row is created with `status: 'pending'`,
     `password_algo: 'argon2id'`, `email_verified_at: null`.
4. **A verification token is issued** — 256 bits of CSPRNG randomness, stored as a
   SHA-256 digest with a 24-hour expiry. ⚑ The database never holds the token
   itself, so a database leak yields no usable links.
5. **The email is sent**, with the link built from `APP_ORIGIN`.
6. **`user.registered` is audited and emitted.**

### ⚑ The link is built from config, never from the request

```
${APP_ORIGIN}${VERIFY_PATH}?token=…
```

Not from the `Host` header, not from `X-Forwarded-Host`. An attacker who can set
`Host: evil.test` on a registration request would otherwise receive a link
pointing at their own server *in the victim's mailbox* — this is exactly how
password-reset poisoning works, and the defence is to never read the origin from
the request at all.

The practical consequence: **`APP_ORIGIN` must be the origin your users' browsers
actually use.** If it says `http://localhost:5173` and you are testing from
`http://172.27.192.1:3000`, the emailed link will point at a `localhost` that
resolves to the wrong machine. That is the setting working correctly; the value is
what needs changing.

## Verifying the address

The link goes to a **front-end** route, not to this API. The page reads the `token`
query parameter and posts it:

```http
POST /auth/verify-email
Content-Type: application/json

{ "token": "Kui993l0paJRM-dO2Dw_TMEnDAk53USVDYbiRuCnnwY" }
```

`200 { "ok": true }` promotes `pending` → `active`. Then the user logs in;
verification issues no session of its own, because proving control of a mailbox is
not proving knowledge of a password.

⚑ Single use. A second call with the same token returns `410`, and so does a token
that never existed or has expired — the three are deliberately indistinguishable,
because the client offers a resend in all three cases and distinguishing them
leaks. ⚑ Verification only promotes a `pending` account; a `suspended` one stays
suspended, or confirming an address would become a way to undo moderation.

`POST /auth/resend-verification` takes `{ email }`, always answers `202`, and
invalidates any previous link so only the newest one works.

## Trying it end to end, locally

```bash
pnpm up                    # Postgres, Redis, Mailpit
pnpm db:migrate
pnpm start                 # or pnpm dev
```

```bash
curl -X POST http://localhost:3000/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","password":"a passphrase of at least twelve"}'
```

The mail lands in **Mailpit**, not in a real inbox — dev SMTP catches everything and
sends nothing. Open the Mailpit UI (`MAILPIT_HTTP_PORT` in `.env`, `58025` in this
checkout) and take the token out of the link.

> [!warning] Registering the same address twice will look like it worked
> That is the enumeration guarantee, not a bug. To check whether an account exists,
> query the database — `select email, status from auth_users where email = '…'` —
> or watch for the "someone tried to register" mail in Mailpit, which only goes out
> on the taken branch.

> [!warning] Five per hour per IP
> Clicking through the form a few times while testing earns a `429` that looks like
> a broken endpoint. Use a different address *and* a different client, or wait.

## Things that surprise people

**The account you registered may vanish.** Until 2026-07-31 the integration suite
truncated every `auth_*` table in whatever `DATABASE_URL` pointed at — the database
you are developing against. Running `pnpm test:int` deleted real accounts with no
sign in the output. The helpers now refuse a database that is not disposable; run
`pnpm db:test:setup` once. See [[Testing#The test database is not your database]].

**`202`, not `201`.** A `201 Created` would be a lie on the taken branch, and the
difference between `201` and `202` would itself be the enumeration oracle.

**The response takes ~400 ms.** Almost all of it is Argon2, deliberately. The
parameters are tuned in [[Performance and scaling]]; concurrency is capped so that
`memoryCost × maxConcurrency` cannot exhaust the process.

## Tests that hold this up

| Property | Where |
|---|---|
| Identical response for a taken address | `register.test.ts`, `auth-flows.e2e.test.ts` |
| Hashing happens on both branches | `register.test.ts` — counts hasher calls |
| Link built from config, not the request | `register.test.ts` |
| Breach check fails open, and says so | `register.test.ts`, `breach.int.test.ts` |
| Token is single-use; 410 for used/unknown/expired | both |
| Verification never un-suspends | `register.test.ts` |
| No cookie, no token in the body | `auth-flows.e2e.test.ts` |

## Related

[[API and Swagger]] · [[Auth module]] · [[Built so far]] · [[Testing]] ·
[[AUTH-MODULE-PLAN#5.1 Registration]] ·
[[AUTH-MODULE-PLAN#5.2 Email verification]]
