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
  return z.toJSONSchema(schema, {
    target: 'draft-7',
    io,
    // Inline reused schemas: no $defs, so ajv and swagger-ui both stay simple.
    reused: 'inline',
    // Anything unrepresentable (a transform, a Date) should be caught here at
    // boot rather than silently documented as `{}`.
    unrepresentable: 'throw',
  }) as JsonSchema;
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
    ...(input.body ? { body: toJson(input.body, 'input') } : {}),
    ...(input.querystring ? { querystring: toJson(input.querystring, 'input') } : {}),
    ...(input.params ? { params: toJson(input.params, 'input') } : {}),
    ...(input.headers ? { headers: toJson(input.headers, 'input') } : {}),
    response,
  };
}
