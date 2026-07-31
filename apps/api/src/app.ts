/**
 * Application factory.
 *
 * `buildApp()` returns a fully wired but un-listened Fastify instance, so tests
 * can drive it through `app.inject()` with no sockets and no ports. Registration
 * order matters: infra first (later plugins decorate off it), then security,
 * observability, docs, routes.
 */

import Fastify, { type FastifyInstance } from 'fastify';
import { randomUUID } from 'node:crypto';
import type { Env } from './env.js';
import { infraPlugin } from './plugins/infra.js';
import { securityPlugin } from './plugins/security.js';
import { authPlugin } from './plugins/auth.js';
import { csrfPlugin } from './plugins/csrf.js';
import { observabilityPlugin } from './plugins/observability.js';
import { swaggerPlugin } from './plugins/swagger.js';
import { errorsPlugin } from './plugins/errors.js';
import { rootRoutes } from './routes/root.js';
import { healthRoutes } from './routes/health.js';
import { wellKnownRoutes } from './routes/wellknown.js';
import { sessionRoutes } from './routes/auth/session.js';
import { otpRoutes } from './routes/auth/otp.js';

export interface BuildAppOptions {
  /**
   * Test seam: register extra routes or plugins after the real ones but before
   * `ready()`. Fastify refuses new routes once an instance is ready, so a test
   * that needs a deliberately-throwing route (to exercise the generic 500 path)
   * has no other way in short of duplicating this whole assembly.
   */
  extend?: (app: FastifyInstance) => Promise<void> | void;
}

export async function buildApp(
  env: Env,
  options: BuildAppOptions = {},
): Promise<FastifyInstance> {
  const app = Fastify({
    logger: {
      level: env.LOG_LEVEL,
      ...(env.LOG_PRETTY
        ? { transport: { target: 'pino-pretty', options: { translateTime: 'HH:MM:ss.l', ignore: 'pid,hostname' } } }
        : {}),
      // ⚑ Redaction is not optional. Without it, a debug log of a request body
      // puts plaintext passwords and live tokens in your log aggregator, which is
      // then a credential store you didn't mean to build.
      redact: {
        paths: [
          'req.headers.authorization',
          'req.headers.cookie',
          'res.headers["set-cookie"]',
          'req.body.password',
          'req.body.newPassword',
          'req.body.currentPassword',
          'req.body.code',
          'req.body.refreshToken',
          'req.body.mfaToken',
          'req.body.token',
          '*.password',
          '*.secret',
          '*.accessToken',
          '*.refreshToken',
          '*.recoveryCodes',
        ],
        censor: '[redacted]',
      },
      serializers: {
        req(request) {
          return {
            method: request.method,
            url: request.url,
            // Route pattern, not the concrete path — keeps ids out of log indexes.
            route: request.routeOptions?.url,
            ip: request.ip,
          };
        },
      },
    },

    // Correlate a client report with a log line. Accept an inbound id from the
    // edge proxy so a trace spans services.
    // The id appears in logs as `reqId`, in the `x-request-id` response header,
    // and as `error.traceId` in every error body — one value, three places, so a
    // user-reported id leads straight to the log line.
    genReqId: (request) => (request.headers['x-request-id'] as string | undefined) ?? randomUUID(),
    requestIdHeader: 'x-request-id',

    // ⚑ Only meaningful behind a proxy you control. Left on with a direct
    // internet-facing socket, a client can forge X-Forwarded-For and walk around
    // every per-IP rate limit.
    trustProxy: env.TRUST_PROXY,

    // Auth payloads are a few hundred bytes. A small limit is free DoS reduction.
    bodyLimit: env.BODY_LIMIT_BYTES,
    requestTimeout: env.REQUEST_TIMEOUT_MS,
    // Slightly above the load balancer's idle timeout so we are not the side that
    // drops a connection mid-response.
    keepAliveTimeout: 72_000,
    connectionTimeout: 0,

    ajv: {
      customOptions: {
        removeAdditional: 'all', // silently strip unknown fields rather than 400
        coerceTypes: false, // ⚑ "1" must not become 1 in an auth payload
        allErrors: false, // first error only — no oracle for schema probing
        // `example` is an OpenAPI documentation annotation with no validation
        // semantics, and ajv's strict mode rejects unknown keywords. Registering
        // it as a no-op keeps strict mode ON for everything else, so a genuine
        // typo in a schema still fails the build instead of being ignored.
        // (`examples` is already part of ajv's vocabulary — adding it throws.)
        keywords: ['example'],
      },
    },
  });

  // Echo the id back so a user can quote it in a bug report.
  app.addHook('onRequest', async (request, reply) => {
    reply.header('x-request-id', request.id);
  });

  await app.register(errorsPlugin);
  await app.register(infraPlugin, { env });
  await app.register(securityPlugin, { env });
  await app.register(authPlugin);
  await app.register(csrfPlugin);
  await app.register(observabilityPlugin, { env });
  await app.register(swaggerPlugin, { env });

  await app.register(rootRoutes);
  await app.register(healthRoutes);
  await app.register(wellKnownRoutes);
  await app.register(sessionRoutes);
  await app.register(otpRoutes);

  if (options.extend) await options.extend(app);

  await app.ready();
  return app;
}
