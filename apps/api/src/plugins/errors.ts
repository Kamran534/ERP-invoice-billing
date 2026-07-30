/**
 * One error handler, one wire format (AUTH-MODULE-PLAN.md §1.7).
 *
 * ⚑ 5xx messages are never forwarded to the client. An internal error leaks
 * schema names, file paths and query fragments; the client gets a traceId and the
 * detail stays in the log.
 */

import fp from 'fastify-plugin';
import type { FastifyError, FastifyReply, FastifyRequest } from 'fastify';
import { AuthError, isAuthError, isClientSafe } from '@auth/core';

interface WireError {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    traceId: string;
  };
}

function wire(
  code: string,
  message: string,
  traceId: string,
  details?: Record<string, unknown>,
): WireError {
  return { error: { code, message, ...(details ? { details } : {}), traceId } };
}

export const errorsPlugin = fp(
  async (app) => {
    app.setErrorHandler(function handler(
      error: FastifyError,
      request: FastifyRequest,
      reply: FastifyReply,
    ) {
      const traceId = request.id;

      // ── Our own typed errors ────────────────────────────────────────────
      if (isAuthError(error)) {
        if (error.retryAfter !== undefined) {
          reply.header('retry-after', String(error.retryAfter));
        }
        if (!isClientSafe(error)) {
          request.log.error({ err: error, code: error.code }, 'auth error (server-side)');
          return reply.code(error.status).send(wire('INTERNAL', 'Internal server error', traceId));
        }
        // 4xx are expected traffic, not incidents — log at info/warn, not error.
        request.log[error.status === 429 ? 'warn' : 'info'](
          { code: error.code, status: error.status },
          'auth error',
        );
        return reply
          .code(error.status)
          .send(wire(error.code, error.message, traceId, error.details));
      }

      // ── Fastify validation (ajv) ─────────────────────────────────────────
      if (error.validation !== undefined) {
        const issues = error.validation.map((v) => ({
          path: v.instancePath || v.schemaPath,
          message: v.message ?? 'invalid',
        }));
        request.log.info({ issues }, 'request validation failed');
        return reply
          .code(400)
          .send(wire('VALIDATION_FAILED', 'Request validation failed', traceId, { issues }));
      }

      // ── Framework errors worth mapping precisely ─────────────────────────
      if (error.code === 'FST_ERR_CTP_BODY_TOO_LARGE') {
        return reply.code(413).send(wire('PAYLOAD_TOO_LARGE', 'Request body too large', traceId));
      }
      if (error.code === 'FST_ERR_CTP_INVALID_MEDIA_TYPE') {
        return reply.code(415).send(wire('VALIDATION_FAILED', 'Unsupported content type', traceId));
      }
      if (error.statusCode === 429) {
        return reply.code(429).send(wire('RATE_LIMITED', 'Too many requests', traceId));
      }

      // ⚑ Rate limiting fails CLOSED (plan §8.2) — a limiter outage must not
      // become an open brute-force window. But "closed" should mean a retryable
      // 503, not a leaked internal error: the store being unreachable is an
      // availability problem, and the client can usefully retry elsewhere.
      // ioredis raises this as a plain Error, so the message is the only signal.
      if (error.message.includes("Stream isn't writeable")) {
        request.log.error({ err: error.message }, 'rate-limit store unavailable — failing closed');
        reply.header('retry-after', '2');
        return reply
          .code(503)
          .send(wire('SERVICE_UNAVAILABLE', 'Temporarily unavailable — retry shortly', traceId));
      }
      if (error.statusCode !== undefined && error.statusCode >= 400 && error.statusCode < 500) {
        request.log.info({ err: error.message }, 'client error');
        return reply
          .code(error.statusCode)
          .send(wire(error.code ?? 'VALIDATION_FAILED', error.message, traceId));
      }

      // ── Anything else is ours, and stays ours ───────────────────────────
      request.log.error({ err: error }, 'unhandled error');
      return reply.code(500).send(wire('INTERNAL', 'Internal server error', traceId));
    });

    // 404 probing is reconnaissance, but the global rate limiter (registered in
    // the security plugin, with `global: true`) already covers unmatched routes,
    // so no extra preHandler is needed here.
    app.setNotFoundHandler((request, reply) => {
      // A bare "not found" leaves a developer guessing whether the path is wrong,
      // the method is wrong, or the service is. Point at the index — but only
      // advertise the docs when they actually exist.
      //
      // `env` is decorated by the infra plugin, which registers *after* this one.
      // It is present by the time a request arrives; the guard is so that this
      // handler can never itself throw.
      const hasEnv = app.hasDecorator('env');
      const details: Record<string, unknown> = { index: '/' };
      if (hasEnv && app.env.SWAGGER_ENABLED) {
        details['docs'] = app.env.SWAGGER_ROUTE_PREFIX;
      }

      return reply
        .code(404)
        .send(
          wire('NOT_FOUND', `Route ${request.method} ${request.url} not found`, request.id, details),
        );
    });
  },
  { name: 'errors' },
);

export { AuthError };
