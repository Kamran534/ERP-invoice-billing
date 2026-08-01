/**
 * Zod → Fastify/OpenAPI bridge.
 *
 * One zod schema per payload gives us three things from a single definition:
 *   1. runtime validation (Fastify compiles the JSON Schema with ajv)
 *   2. response serialization (fast-json-stringify drops undeclared fields,
 *      which is a quiet but real defence against leaking internal columns)
 *   3. the OpenAPI document (@fastify/swagger reads the same route schemas)
 *
 * Zod 4 emits JSON Schema natively, so there is no third-party transform layer to
 * drift out of sync with either zod or fastify.
 */

import { z } from 'zod';

type JsonSchema = Record<string, unknown>;

/**
 * `io: 'input'` describes what the client sends (before defaults/transforms);
 * `io: 'output'` describes what we return. Using the wrong one is how a required
 * field ends up documented as optional.
 */
export function toJson(schema: z.ZodType, io: 'input' | 'output' = 'input'): JsonSchema {
  return inlineDefinitions(
    z.toJSONSchema(schema, {
      target: 'draft-7',
      io,
      reused: 'inline',
      // Anything unrepresentable (a transform, a Date) should be caught here at
      // boot rather than silently documented as `{}`.
      unrepresentable: 'throw',
    }) as JsonSchema,
  );
}

/**
 * ⚑ Resolves `$ref`s into the schema itself, so every route schema is
 * self-contained.
 *
 * `reused: 'inline'` is not enough: zod extracts any schema carrying an `id` from
 * `.meta({ id: 'PublicUser' })` into `definitions` and points a `$ref` at it,
 * whatever `reused` says. That is fine for ajv, which sees the `definitions` block
 * sitting right there — but `@fastify/swagger` rewrites `#/definitions/X` to
 * `#/components/schemas/X` while building the OpenAPI document and does **not**
 * carry the definitions across. The result is a document whose refs all dangle:
 * runtime validation keeps working, so nothing fails, and the published contract
 * is quietly broken. Swagger UI reports it as `key not found in object`.
 *
 * The alternative is `fastify.addSchema()` for each definition, which does produce
 * named `components.schemas` — but it has to run before any route registers, and
 * the definitions are only discovered *as* routes register. Inlining has no
 * ordering problem and cannot half-work.
 *
 * The `id` is kept as `title`, so a generated client still gets a name rather than
 * an anonymous inline type.
 */
function inlineDefinitions(schema: JsonSchema): JsonSchema {
  const { definitions, $defs, ...rest } = schema as JsonSchema & {
    definitions?: Record<string, JsonSchema>;
    $defs?: Record<string, JsonSchema>;
  };
  const defs = definitions ?? $defs;
  if (!defs) return schema;

  // A schema that refers to itself cannot be inlined. None here do; if one ever
  // does, this says so at boot instead of hanging the process.
  const expanding = new Set<string>();

  const resolve = (node: unknown): unknown => {
    if (Array.isArray(node)) return node.map(resolve);
    if (node === null || typeof node !== 'object') return node;

    const ref = (node as { $ref?: unknown }).$ref;
    if (typeof ref === 'string') {
      const name = /^#\/(?:definitions|\$defs)\/(.+)$/.exec(ref)?.[1];
      const target = name ? defs[name] : undefined;
      if (name && target) {
        if (expanding.has(name)) {
          throw new Error(
            `Cannot inline the recursive schema "${name}" — give it a $id and register it with fastify.addSchema instead.`,
          );
        }
        expanding.add(name);
        const expanded = { title: name, ...(resolve(target) as JsonSchema) };
        expanding.delete(name);
        return expanded;
      }
    }

    return Object.fromEntries(
      Object.entries(node as Record<string, unknown>).map(([key, value]) => [key, resolve(value)]),
    );
  };

  return resolve(rest) as JsonSchema;
}

export interface RouteSchemaInput {
  summary: string;
  description?: string;
  tags: string[];
  operationId: string;
  body?: z.ZodType;
  querystring?: z.ZodType;
  params?: z.ZodType;
  headers?: z.ZodType;
  /** Status code → payload schema. Use `null` for an empty body (204). */
  response: Record<number, z.ZodType | null>;
  security?: Array<Record<string, string[]>>;
  /** Documented rate limit, rendered into the description so it is discoverable. */
  rateLimit?: string;
  /**
   * Request content types, for the one route that does not take JSON.
   *
   * ⚑ Documentation only. Fastify decides what it can parse from its registered
   * content-type parsers; this is what Swagger UI needs to render a file picker
   * instead of a JSON textarea.
   */
  consumes?: string[];
  deprecated?: boolean;
}

/** Errors share one shape everywhere (plan §1.7). */
export const errorSchema = z
  .object({
    error: z.object({
      code: z.string().meta({ description: 'Stable machine-readable code. Branch on this, not on the message.', example: 'INVALID_CREDENTIALS' }),
      message: z.string().meta({ description: 'Developer-facing default. User-facing copy comes from your i18n bundle, keyed by code.' }),
      details: z.record(z.string(), z.unknown()).optional().meta({ description: 'Safe, code-specific context. Never contains secrets.' }),
      traceId: z.string().meta({ description: 'Matches the `x-request-id` response header — quote it in a bug report.' }),
    }),
  })
  .meta({ id: 'Error' });

/** Status codes every route can produce, so they are not re-declared per route. */
const commonResponses = {
  400: errorSchema,
  429: errorSchema,
  500: errorSchema,
  503: errorSchema,
};

export function route(input: RouteSchemaInput): Record<string, unknown> {
  const response: Record<string, JsonSchema> = {};

  for (const [status, schema] of Object.entries({ ...commonResponses, ...input.response })) {
    if (schema === null) {
      response[status] = { type: 'null', description: 'No content' };
      continue;
    }
    response[status] = toJson(schema as z.ZodType, 'output');
  }

  const description = [
    input.description,
    input.rateLimit ? `\n\n**Rate limit:** ${input.rateLimit}` : '',
  ]
    .filter(Boolean)
    .join('');

  return {
    summary: input.summary,
    description: description || undefined,
    tags: input.tags,
    operationId: input.operationId,
    ...(input.deprecated ? { deprecated: true } : {}),
    ...(input.security ? { security: input.security } : {}),
    ...(input.consumes ? { consumes: input.consumes } : {}),
    ...(input.body ? { body: toJson(input.body, 'input') } : {}),
    ...(input.querystring ? { querystring: toJson(input.querystring, 'input') } : {}),
    ...(input.params ? { params: toJson(input.params, 'input') } : {}),
    ...(input.headers ? { headers: toJson(input.headers, 'input') } : {}),
    response,
  };
}
