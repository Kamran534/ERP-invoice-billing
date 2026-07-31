---
tags: [security, operations]
updated: 2026-07-31
---

# Security headers

Set by `apps/api/src/plugins/security.ts` (helmet) and, on `/docs/*` only, by
`@fastify/swagger-ui`. Two separate sources — a change to one does not affect the
other, which is how the bug below survived.

## Always sent

| Header | Value | Why |
|---|---|---|
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` | An API serves JSON; it needs nothing else. `useDefaults: false` — see below |
| `X-Content-Type-Options` | `nosniff` | — |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | — |
| `Cross-Origin-Resource-Policy` | `same-origin` | — |
| `Cache-Control` | `no-store, no-cache, must-revalidate, private` on `/auth/*` | A cached auth response in a CDN or the back button is a session leak. JWKS is deliberately exempt and sets `max-age` |
| `X-Powered-By` | *removed* | — |

## Sent only when `HTTPS_ENABLED`

> [!danger] These three are harmful on a plain-HTTP origin
> `HTTPS_ENABLED` defaults to `true` in production and `false` otherwise. Set it to
> `true` when clients reach the API over HTTPS **including through a
> TLS-terminating proxy** — the app itself may still speak HTTP internally.

| Header | Why it is gated |
|---|---|
| CSP `upgrade-insecure-requests` | Rewrites every `http://` subresource to `https://`. With no TLS listener on the port, every asset fails with `ERR_SSL_PROTOCOL_ERROR` |
| `Strict-Transport-Security` | Browsers ignore it entirely when it arrives over HTTP |
| `Cross-Origin-Opener-Policy` | Ignored on a non-trustworthy origin, and logs a console warning saying so |

The cookie `Secure` flag rides the same flag. A `Secure` cookie is silently dropped
over plain HTTP, so it must never disagree with the headers — before this, it keyed
off `NODE_ENV` separately and could.

## The localhost trap

> [!bug] Why this broke only for someone else
> `localhost` is a [potentially trustworthy origin](https://www.w3.org/TR/powerful-features/#potentially-trustworthy-origin)
> and is **exempt** from `upgrade-insecure-requests`. So the docs UI worked
> perfectly on `http://localhost:3000/docs` and collapsed completely on
> `http://192.168.x.x:3000/docs` — every stylesheet and script upgraded to
> `https://` and failed. Nothing about the failure pointed at a CSP directive.

If a page works on localhost and dies on a LAN address, check
`Content-Security-Policy` for `upgrade-insecure-requests` before anything else.

## Two things that quietly reintroduce it

**helmet merges its defaults.** Passing custom `directives` without
`useDefaults: false` merges them *into* helmet's defaults, which silently
reintroduces `upgrade-insecure-requests` along with `script-src` and `style-src`
allowances an API has no use for. An e2e test asserts the API CSP contains neither.

**swagger-ui sets its own CSP.** `staticCSP: true` replaces the API policy on
`/docs/*`, and its policy carries the directive too. The `transformStaticCSP` hook
strips it unless `HTTPS_ENABLED`. Fixing helmet alone leaves the docs UI broken —
they are tested separately for exactly this reason.

## `Set-Cookie`, which is also a response header

Three cookies, set together by `apps/api/src/lib/cookies.ts` and never by a
handler directly — the flags *are* the security property, and they must not drift
between the route that sets a cookie and the route that clears it.

| Cookie (over HTTPS) | `HttpOnly` | `Path` | Why that path |
|---|---|---|---|
| `__Host-at` | yes | `/` | Sent on every API call, which is the point |
| `__Secure-rt` | yes | `/auth/token` | ⚑ Scoped, so the credential that mints sessions never rides along on ordinary requests |
| `csrf` | **no** | `/` | ⚑ Readable on purpose — the client must echo it in a header, and a cross-origin attacker can cause it to be sent but not read |

⚑ The prefixes are **derived from the attributes, not configured**. `__Host-` requires `Secure`,
`Path=/` and no `Domain`; `__Secure-` requires `Secure`. A cookie that claims a prefix it cannot
back is discarded by the browser without a word — so over plain HTTP the names drop to `at`, `rt`,
`td`, and the refresh cookie never takes `__Host-` at all, because its whole point is a scoped
`Path`. See [[AUTH-MODULE-PLAN#8.3 Cookies & CSRF (cookie mode)]].

`Secure` on all three follows the same `HTTPS_ENABLED` flag as HSTS and the CSP
upgrade ([[ADR-0008 Gate HTTPS-only headers behind one flag]]) — a `Secure` cookie
over plain HTTP is silently dropped, and the resulting "login appears to do
nothing" is genuinely unpleasant to diagnose.

⚑ Clearing must repeat the exact `path` and `domain`. A browser treats
`(name, domain, path)` as the identity, so clearing the refresh cookie at `/` leaves
the real one at `/auth/token` alive — a logout that returns `204` and signs nobody out.

## Not covered here

CORS allowlisting and rate limiting live in the same plugin but are part of the
auth surface — see
[[AUTH-MODULE-PLAN#8.2 Rate limiting (token bucket, per rule; Redis-backed in prod)]].
How the CSRF check decides what to enforce is in
[[API and Swagger#How CSRF is actually enforced]] and
[[ADR-0010 Skip CSRF when a request carries no session cookie]].

Response compression is deliberately absent —
[[Performance and scaling#6. No response compression]].

## Related

[[ADR-0008 Gate HTTPS-only headers behind one flag]] · [[API and Swagger]] · [[Running locally]]
