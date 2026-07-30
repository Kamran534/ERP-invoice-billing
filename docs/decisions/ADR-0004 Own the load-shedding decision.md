---
tags: [adr, performance, availability]
status: accepted
date: 2026-07-30
deciders: [engineering]
---

# ADR-0004 — Own the load-shedding decision

**Status:** Accepted · **Supersedes:** nothing · **Related:** [[Performance and scaling#3. Load shedding before collapse]]

## Context

The API sheds load before it collapses: past a threshold on event-loop delay, heap
or RSS, it returns `503` + `Retry-After` so a load balancer can route elsewhere,
rather than degrading until requests time out. `@fastify/under-pressure` samples
those signals.

The obvious wiring is its `pressureHandler` option. Two things made that wrong.

**Its types and its implementation disagree.** The published type is
`(request, reply, type, value) => Promise<void> | void`. The implementation:

```js
const result = pressureHandler(req, reply, type, value)
if (result instanceof Promise) result.then(() => next(), next)
else if (result == null) next()
else reply.send(result)
```

Returning nothing means *continue*. So a handler that calls `reply.send()` — the
natural reading of a `void` signature — sends a reply **and** lets the request
continue, which Fastify turns into a `500`. Shedding only works if you return a
value, which the types forbid. Our load-shedding path was silently broken: it
returned 500 instead of 503 under pressure, and nothing noticed because nothing was
under pressure in normal use.

**A non-finite reading is not pressure.** Chasing the first bug surfaced a worse
one:

```js
eventLoopDelay = Math.max(0, histogram.mean / 1e6 - resolution)
if (Number.isNaN(eventLoopDelay)) eventLoopDelay = Infinity
```

An empty histogram — the state a process is in for its first sampling window —
yields `NaN`, which becomes `Infinity`. `Infinity` beats any threshold, so a
**freshly started process sheds every request** until its first sample lands.
Exactly when a load balancer begins sending it traffic. Readiness would report
healthy throughout, because health checks are exempt from shedding.

## Decision

Use under-pressure as a **sampler only**. Its `pressureHandler` returns `undefined`
unconditionally, and an `onRequest` hook in our observability plugin makes the
decision from `app.memoryUsage()`:

```ts
const delayExceeded =
  Number.isFinite(usage.eventLoopDelay) && usage.eventLoopDelay > env.MAX_EVENT_LOOP_DELAY_MS;
const heapExceeded = usage.heapUsed > env.MAX_HEAP_USED_BYTES;
const rssExceeded  = usage.rssBytes  > env.MAX_RSS_BYTES;
if (!delayExceeded && !heapExceeded && !rssExceeded) return;
```

`Number.isFinite` is the fix for the second bug: "no measurement yet" is not
evidence of a wedged event loop.

## Alternatives rejected

**Cast around the type mismatch** — `pressureHandler: handler as never`. Works, but
buries a library contradiction behind a cast that the next reader has to
re-discover, and leaves the exemption list and the shed metric split across two
places.

**Use the plugin's default handler** (omit `pressureHandler` entirely). Correct
status codes, but no way to exempt `/health`, `/metrics` and `/docs` — and shedding
liveness makes the orchestrator kill a container that is merely busy, converting
back-pressure into an outage.

**Per-route `config.pressureHandler` for the exempt routes.** Works for our own
routes, but `/docs/*` is registered by `@fastify/swagger-ui` and we do not control
its route options.

## Consequences

- The shed policy, the exemption list and the `http_requests_shed_total` metric all
  live in one function.
- We depend on `memoryUsage()` and `isUnderPressure()` staying decorated, both of
  which are in under-pressure's public type declarations.
- Three e2e tests cover it: shedding returns a typed 503 with `Retry-After`; health
  and metrics are never shed; and a freshly built app answers `501` rather than
  `503` — the regression guard for the `Infinity` bug.
- Thresholds are relaxed in the e2e environment because a vitest worker's startup
  genuinely blocks the loop past 200 ms. Shedding gets its own tests with a
  deliberately unreachable threshold instead.

## Related

[[Performance and scaling]] · [[Observability]] · [[Testing#Bugs this suite has already caught]]
