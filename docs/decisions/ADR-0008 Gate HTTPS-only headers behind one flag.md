---
tags: [adr, security, operations]
status: accepted
date: 2026-07-31
---

# ADR-0008 — Gate HTTPS-only headers behind one flag

**Status:** Accepted · **Related:** [[Security headers]]

## Context

Four settings are only meaningful on a secure origin, and three of them are
actively harmful on a plain-HTTP one:

- CSP `upgrade-insecure-requests` — rewrites every `http://` subresource to
  `https://`,
- `Strict-Transport-Security` — ignored when received over HTTP,
- `Cross-Origin-Opener-Policy` — ignored on a non-trustworthy origin, with a
  console warning,
- the cookie `Secure` flag — the cookie is silently dropped over HTTP.

They were configured independently: HSTS and the CSP unconditionally, `Secure` from
`NODE_ENV`. That let them disagree, and they did.

Opening Swagger UI at `http://192.168.x.x:3000/docs` produced
`ERR_SSL_PROTOCOL_ERROR` for every stylesheet and script. The cause was
`upgrade-insecure-requests` upgrading each asset to a port with no TLS listener.
It had never been noticed because `localhost` is a *potentially trustworthy origin*
and exempt from the upgrade — so the same page worked perfectly during development
and failed the moment anyone opened it from another machine.

It came from **two** independent sources, so fixing either alone would have left it
broken: helmet (whose defaults merge in unless `useDefaults: false`) and
`@fastify/swagger-ui` (whose `staticCSP` replaces the API policy on `/docs/*`).

## Decision

One boolean, `HTTPS_ENABLED`, drives all four. It answers a single question —
*are clients reaching this API over HTTPS, directly or via a TLS-terminating
proxy?* — and defaults to `true` in production, `false` otherwise.

helmet gets `useDefaults: false` so the policy is exactly what is declared, and
swagger-ui's copy is stripped through `transformStaticCSP` under the same gate.

## Alternatives rejected

**Detect from the request** (`req.protocol === 'https'`). Wrong behind a
TLS-terminating proxy, where the app sees HTTP while the client is on HTTPS — the
common production topology. It would also make the headers vary per request, which
is exactly what HSTS must not do.

**Derive from `NODE_ENV`.** Conflates two unrelated things. A staging box on plain
HTTP with `NODE_ENV=production`, or a locally-run production build, both get it
wrong — and the failure is invisible on localhost.

**Derive from `APP_ORIGIN`.** That is the *frontend* origin, not this API's. They
are frequently different hosts with different TLS setups.

**Just drop `upgrade-insecure-requests`.** Fixes the symptom, loses a genuinely
useful defence in production, and leaves HSTS and the cookie flag still able to
disagree.

## Consequences

- The four settings can no longer contradict each other.
- Deployments behind a TLS proxy must set `HTTPS_ENABLED=true` explicitly; the
  `NODE_ENV=production` default covers the common case.
- Four e2e tests: the headers are absent when off, present when on, the docs CSP is
  checked **separately** from the API CSP, and the API CSP is asserted to contain
  no `script-src`/`style-src` — which is what catches a `useDefaults` regression.
- A side benefit: the API's CSP is now strictly what was written, rather than
  helmet's defaults with our directives layered on.

## Related

[[Security headers]] · [[API and Swagger]] · [[Testing]]
