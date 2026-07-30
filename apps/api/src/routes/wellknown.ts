/**
 * Public key material for token verification.
 *
 * This is fully implemented — resource servers need it to verify access tokens
 * without calling back here on every request.
 */

import type { FastifyInstance } from 'fastify';
import { route } from '../lib/schema.js';
import { TAGS } from '../plugins/swagger.js';
import { jwksResponse } from '../schemas/auth.js';

export async function wellKnownRoutes(app: FastifyInstance): Promise<void> {
  app.get(
    '/.well-known/jwks.json',
    {
      // ⚑ This is the hottest endpoint in a fleet: every resource server fetches
      // it to verify tokens, and so does every new pod on cold start. A tight
      // limit here does not protect anything (the payload is public key material)
      // but it does break token verification cluster-wide — a 60/min cap made a
      // load test fail after exactly 60 requests. Keep a high backstop and let
      // the 5-minute Cache-Control below do the real work.
      config: { rateLimit: { max: 1_200, timeWindow: '1 minute' } },
      schema: route({
        summary: 'JSON Web Key Set',
        description:
          'Public keys for verifying access tokens. Cache this — it changes only on key rotation, ' +
          'and a new key is published here at least one access-token lifetime *before* it starts ' +
          'signing, so a verifier that caches for 5 minutes never sees an unknown `kid`.\n\n' +
          '⚑ Verifier rules: pin `alg` to `EdDSA` (never read it from the token header), resolve ' +
          '`kid` only against this document, and verify `iss`, `aud`, `exp` and `nbf`.',
        tags: [TAGS.keys],
        operationId: 'getJwks',
        response: { 200: jwksResponse },
      }),
    },
    async (_request, reply) => {
      const jwks = await app.tokens.jwks();
      // Short cache: long enough to matter under load, short enough that an
      // emergency rotation propagates in minutes.
      return reply.header('cache-control', 'public, max-age=300, stale-while-revalidate=60').send(jwks);
    },
  );
}
