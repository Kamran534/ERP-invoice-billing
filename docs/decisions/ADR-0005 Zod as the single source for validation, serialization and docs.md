---
tags: [adr, api, tooling]
status: accepted
date: 2026-07-30
---

# ADR-0005 — Zod as the single source for validation, serialization and docs

**Status:** Accepted · **Related:** [[API and Swagger#One schema, three jobs]]

## Context

Three artefacts describe every endpoint payload: the runtime validator, the
response serializer, and the OpenAPI document. Maintained separately they drift,
and the drift is invisible until a client breaks — documentation that lies is worse
than none.

## Decision

One zod schema per payload, converted to JSON Schema and handed to Fastify. Fastify
compiles it with ajv for validation, uses it with fast-json-stringify for
serialization, and `@fastify/swagger` reads the same route schemas to build the
document.

Zod 4 emits JSON Schema **natively** (`z.toJSONSchema`), so no third-party
transform sits between zod and Fastify to fall out of sync with either.

## Alternatives rejected

**`fastify-type-provider-zod`** — the conventional choice, and it gives end-to-end
inference. But it couples us to a third package tracking both zod's and Fastify's
majors. Since zod 4 does the conversion itself, the dependency buys inference we
can get from `z.infer` anyway.

**Hand-written JSON Schema** — no drift between validator and docs, but no
TypeScript types, and JSON Schema by hand is miserable to review.

**TypeBox** — a reasonable alternative; zod won on ecosystem familiarity and
because the config layer already uses it.

## Consequences

- Response serialization **strips undeclared fields**, a quiet defence against
  leaking an internal column by adding it to a row.
- `route()` injects the shared 400/429/500/503 responses so every operation
  documents them.
- Schemas must stay JSON-Schema-representable: no `z.date()`, no transforms in
  route schemas. `unrepresentable: 'throw'` makes a violation fail at boot rather
  than silently documenting `{}`.
- ajv strict mode rejects unknown keywords, so `example` (an OpenAPI annotation) is
  registered as a no-op. `examples` is already in ajv's vocabulary and registering
  it throws — a five-minute debug the comment now prevents.
- E2E tests assert document-level properties: unique `operationId`s, declared
  security schemes, documented error envelope.

## Related

[[API and Swagger]] · [[Testing#E2E]]
