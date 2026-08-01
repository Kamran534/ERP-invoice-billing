/**
 * The organization logo (§10.11).
 *
 * The only endpoint in this API that accepts bytes rather than JSON, which makes
 * it the only one with this shape of risk: what arrives is a file, chosen by
 * someone, and everything about it — its name, its declared type, its size — is
 * theirs to lie about.
 *
 * ⚑ So nothing the caller says is believed. The type is sniffed from the leading
 * bytes, the name is discarded and replaced with a uuid, the size is capped by
 * the multipart parser before the buffer exists, and the key is namespaced by the
 * organization from the **token**, never from the request.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AuthError, updateOrganization } from '@auth/core';
import { route, errorSchema } from '../../lib/schema.js';
import { TAGS } from '../../plugins/swagger.js';
import { organization } from '../../schemas/orgs.js';
import { requestContext } from '../../lib/present.js';
import { createStorage, sniffImage } from '../../lib/storage.js';

const cookieSecurity: Array<Record<string, string[]>> = [
  { cookieAuth: [], csrfToken: [] },
  { bearerAuth: [] },
];

export async function logoRoutes(app: FastifyInstance): Promise<void> {
  const { auth, env } = app;
  const storage = createStorage(env);

  function activeOrg(request: FastifyRequest): string {
    const orgId = request.auth?.org;
    if (!orgId) {
      throw new AuthError('ORG_CONTEXT_REQUIRED', 'Create or join an organization before calling this');
    }
    return orgId;
  }

  app.post(
    '/auth/orgs/current/logo',
    {
      preHandler: app.requirePermission('org:update'),
      config: { rateLimit: { max: 30, timeWindow: '1 hour' } },
      // ⚑ This route alone escapes the 64 KiB body limit the rest of the API
      // runs with. The multipart parser enforces the real ceiling below; this
      // just stops Fastify refusing the request before it gets there.
      bodyLimit: env.UPLOAD_MAX_BYTES + 64 * 1024,
      schema: route({
        summary: 'Upload the organization logo',
        description:
          'A `multipart/form-data` request with one `file` part. PNG, JPEG, WebP or GIF, up to ' +
          `${Math.round(env.UPLOAD_MAX_BYTES / 1024)} KiB.\n\n` +
          '⚑ The type is determined from the file\'s own bytes, not from the declared content type ' +
          'or the filename — both of which the caller controls. **SVG is refused**: it is a document ' +
          'format that can carry script, and a browser rendering one from this origin would run it.\n\n' +
          'The previous logo is deleted. Returns the organization, with `logoUrl` pointing at the ' +
          'public object store.',
        tags: [TAGS.auth],
        operationId: 'uploadOrgLogo',
        security: cookieSecurity,
        rateLimit: '30 per hour per IP',
        /**
         * ⚑ `consumes` and **no body schema**. `schema.body` is what Fastify
         * *validates* against, not merely what Swagger renders — and with
         * multipart handled by `request.file()`, `request.body` is undefined. A
         * body schema here therefore fails every upload with
         * "Request validation failed" before the handler runs, which is exactly
         * what it did.
         *
         * The shape of the part is described in the text above instead; the file
         * itself is validated by sniffing its bytes, which is the only check that
         * means anything.
         */
        consumes: ['multipart/form-data'],
        response: {
          200: z.object({ org: organization }),
          400: errorSchema,
          401: errorSchema,
          403: errorSchema,
          413: errorSchema,
          415: errorSchema,
        },
      }),
    },
    async (request) => {
      const orgId = activeOrg(request);

      const file = await request.file({ limits: { fileSize: env.UPLOAD_MAX_BYTES, files: 1 } });
      if (!file) {
        throw new AuthError('VALIDATION_FAILED', 'Attach a file in a `file` field', {
          details: { field: 'file' },
        });
      }

      const bytes = await file.toBuffer();

      // ⚑ `truncated` rather than checking `bytes.length` afterwards: the parser
      // stops reading at the limit, so a 5 GB upload never becomes a 5 GB buffer.
      // Comparing lengths after the fact would mean having already held it.
      if (file.file.truncated) {
        throw new AuthError(
          'PAYLOAD_TOO_LARGE',
          `That image is larger than ${Math.round(env.UPLOAD_MAX_BYTES / 1024)} KiB`,
          { details: { field: 'file', maxBytes: env.UPLOAD_MAX_BYTES } },
        );
      }

      const sniffed = sniffImage(bytes);
      if (!sniffed) {
        throw new AuthError(
          'VALIDATION_FAILED',
          'That file is not a PNG, JPEG, WebP or GIF image',
          { status: 415, details: { field: 'file' } },
        );
      }

      const previous = (await auth.repos.orgs.findById(orgId))?.logoUrl ?? null;

      const stored = await storage.putPublic({
        orgId,
        kind: 'logos',
        bytes,
        contentType: sniffed.type,
        extension: sniffed.extension,
      });

      const org = await updateOrganization(auth, {
        actorId: request.auth!.sub,
        orgId,
        patch: { logoUrl: stored.url },
        ...requestContext(request),
      });

      // After the row points at the new one, so a failure here leaves an orphan
      // rather than an organization whose logo 404s.
      if (previous) await storage.remove(previous);

      return { org: { ...org, createdAt: org.createdAt.toISOString() } };
    },
  );

  app.delete(
    '/auth/orgs/current/logo',
    {
      preHandler: app.requirePermission('org:update'),
      schema: route({
        summary: 'Remove the organization logo',
        description: 'Clears `logoUrl` and deletes the stored object.',
        tags: [TAGS.auth],
        operationId: 'deleteOrgLogo',
        security: cookieSecurity,
        response: { 200: z.object({ org: organization }), 401: errorSchema, 403: errorSchema },
      }),
    },
    async (request) => {
      const orgId = activeOrg(request);
      const previous = (await auth.repos.orgs.findById(orgId))?.logoUrl ?? null;

      const org = await updateOrganization(auth, {
        actorId: request.auth!.sub,
        orgId,
        // ⚑ `null`, not `undefined` — the update use-case treats an absent field
        // as "leave it alone" and an explicit null as "clear it" (§10.11).
        patch: { logoUrl: null },
        ...requestContext(request),
      });

      if (previous) await storage.remove(previous);

      return { org: { ...org, createdAt: org.createdAt.toISOString() } };
    },
  );
}
