/**
 * Probes and metrics.
 *
 * ⚑ Liveness must NOT check dependencies. If /health/live pinged Postgres, a
 * 30-second database blip would make the orchestrator kill and restart every
 * replica simultaneously — turning a recoverable dependency wobble into a full
 * outage. Liveness answers "is this process wedged?"; readiness answers "should
 * traffic come here right now?".
 */

import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { route } from '../lib/schema.js';
import { TAGS } from '../plugins/swagger.js';

const liveResponse = z.object({
  status: z.literal('ok'),
  uptimeSeconds: z.number(),
  pid: z.number(),
});

const dependency = z.object({
  ok: z.boolean(),
  latencyMs: z.number().optional(),
  detail: z.string().optional(),
});

const readyResponse = z.object({
  status: z.enum(['ready', 'degraded']),
  version: z.string(),
  checks: z.object({
    postgres: dependency,
    redis: dependency,
    smtp: dependency,
  }),
  pool: z.object({ total: z.number(), idle: z.number(), waiting: z.number() }),
});

async function timed(fn: () => Promise<boolean>): Promise<{ ok: boolean; latencyMs: number }> {
  const startedAt = performance.now();
  const ok = await fn().catch(() => false);
  return { ok, latencyMs: Math.round(performance.now() - startedAt) };
}

const READY_CACHE_MS = 1_000;

interface ReadyBody {
  status: 'ready' | 'degraded';
  version: string;
  checks: Record<string, { ok: boolean; latencyMs?: number; detail?: string }>;
  pool: { total: number; idle: number; waiting: number };
}

export async function healthRoutes(app: FastifyInstance): Promise<void> {
  /**
   * Readiness costs three network round-trips, one of them an SMTP handshake. An
   * orchestrator probing every few seconds is fine, but a load-balancer check
   * plus a burst of monitoring would multiply that load onto the very
   * dependencies we are asking about — an expensive probe becomes a way to
   * exhaust the connection pool.
   *
   * One second of caching keeps the answer honest (an orchestrator polls far
   * slower than that) while making probe volume irrelevant, and the in-flight
   * promise means a hundred simultaneous probes trigger exactly one check.
   *
   * ⚑ Scoped to the instance, not the module. Module-level state would be shared
   * by every app built in the same process — harmless in production where there
   * is one, but in tests two instances would serve each other's cached verdict.
   */
  let readyCache: { at: number; body: ReadyBody; ready: boolean } | null = null;
  let readyInFlight: Promise<{ body: ReadyBody; ready: boolean }> | null = null;

  app.get(
    '/health/live',
    {
      config: { rateLimit: false },
      schema: route({
        summary: 'Liveness probe',
        description:
          'Returns 200 whenever the process is running and the event loop is responsive. ' +
          'Deliberately does not touch Postgres, Redis or SMTP — see the note in the source.',
        tags: [TAGS.health],
        operationId: 'healthLive',
        response: { 200: liveResponse },
      }),
    },
    async () => ({
      status: 'ok' as const,
      uptimeSeconds: Math.round(process.uptime()),
      pid: process.pid,
    }),
  );

  app.get(
    '/health/ready',
    {
      config: { rateLimit: false },
      schema: route({
        summary: 'Readiness probe',
        description:
          'Checks every dependency the request path needs. Returns **503** with per-dependency ' +
          'detail when any hard dependency is down, so a load balancer stops sending traffic here. ' +
          'SMTP is treated as soft: mail delivery must never gate authentication, so a broken ' +
          'relay reports `degraded` and still serves traffic.',
        tags: [TAGS.health],
        operationId: 'healthReady',
        response: { 200: readyResponse, 503: readyResponse },
      }),
    },
    async (request, reply) => {
      const runChecks = async (): Promise<{ body: ReadyBody; ready: boolean }> => {
        const [postgres, redis, smtp] = await Promise.all([
          timed(() => app.dbHandle.ping()),
          timed(async () => (await app.redis.ping()) === 'PONG'),
          timed(() => app.mailer.verify()),
        ]);

        // Hard dependencies gate readiness; SMTP does not.
        const ready = postgres.ok && redis.ok;
        const body: ReadyBody = {
          status: ready && smtp.ok ? 'ready' : 'degraded',
          version: process.env['npm_package_version'] ?? '0.1.0',
          checks: {
            postgres: { ...postgres, ...(postgres.ok ? {} : { detail: 'ping failed' }) },
            redis: { ...redis, ...(redis.ok ? {} : { detail: 'ping failed' }) },
            smtp: { ...smtp, ...(smtp.ok ? {} : { detail: 'handshake failed (non-blocking)' }) },
          },
          pool: app.dbHandle.stats(),
        };
        if (!ready) request.log.error({ checks: body.checks }, 'readiness check failed');
        return { body, ready };
      };

      const now = Date.now();
      if (readyCache && now - readyCache.at < READY_CACHE_MS) {
        return reply
          .code(readyCache.ready ? 200 : 503)
          .header('x-cache', 'hit')
          .send(readyCache.body);
      }

      // Coalesce concurrent probes onto one dependency check.
      readyInFlight ??= runChecks()
        .then((result) => {
          readyCache = { at: Date.now(), ...result };
          return result;
        })
        .finally(() => {
          readyInFlight = null;
        });

      const { body, ready } = await readyInFlight;
      return reply.code(ready ? 200 : 503).header('x-cache', 'miss').send(body);
    },
  );

  // Prometheus scrape target. Untagged, so it stays out of the public API docs —
  // it is an operational surface, not part of the product contract.
  if (app.env.METRICS_ENABLED) {
    app.get(app.env.METRICS_ROUTE, { config: { rateLimit: false }, schema: { hide: true } }, async (_request, reply) => {
      const body = await app.metrics.registry.metrics();
      return reply.header('content-type', app.metrics.registry.contentType).send(body);
    });
  }
}
