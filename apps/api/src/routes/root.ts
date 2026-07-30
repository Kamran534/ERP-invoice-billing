/**
 * Service index.
 *
 * `GET /` on a JSON API should not be a 404. Someone who opens the base URL in a
 * browser — a new developer, an on-call engineer, a health checker pointed at the
 * wrong path — deserves to be told what this service is and where the docs are,
 * not handed an error.
 *
 * Deliberately minimal: name, version, and links. No environment, no dependency
 * detail, no build metadata. Those belong on `/health/ready`, which is the
 * endpoint you would actually gate if you cared who could see them.
 */

import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { route } from '../lib/schema.js';
import { TAGS } from '../plugins/swagger.js';

const indexResponse = z
  .object({
    name: z.string(),
    version: z.string(),
    status: z.literal('ok'),
    links: z.object({
      docs: z.string().nullable().meta({
        description: 'Swagger UI, or null when the docs are disabled (as they should be in production).',
      }),
      openapi: z.string().nullable(),
      health: z.string(),
      ready: z.string(),
      jwks: z.string(),
    }),
  })
  .meta({ id: 'ServiceIndex' });

export async function rootRoutes(app: FastifyInstance): Promise<void> {
  const docsEnabled = app.env.SWAGGER_ENABLED;

  app.get(
    '/',
    {
      config: { rateLimit: { max: 60, timeWindow: '1 minute' } },
      schema: route({
        summary: 'Service index',
        description:
          'What this service is and where the rest of it lives. Unauthenticated, and safe to leave ' +
          'public: it exposes no configuration and no dependency state.\n\n' +
          '`links.docs` is null when `SWAGGER_ENABLED=false`, so the index never advertises an ' +
          'endpoint that is not actually there.',
        tags: [TAGS.meta],
        operationId: 'getServiceIndex',
        response: { 200: indexResponse },
      }),
    },
    async () => ({
      name: `${app.env.APP_NAME} — Auth API`,
      version: process.env['npm_package_version'] ?? '0.1.0',
      status: 'ok' as const,
      links: {
        docs: docsEnabled ? app.env.SWAGGER_ROUTE_PREFIX : null,
        openapi: docsEnabled ? `${app.env.SWAGGER_ROUTE_PREFIX}/json` : null,
        health: '/health/live',
        ready: '/health/ready',
        jwks: '/.well-known/jwks.json',
      },
    }),
  );
}
