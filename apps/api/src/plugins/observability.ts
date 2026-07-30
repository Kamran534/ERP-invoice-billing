/**
 * Metrics and load shedding.
 *
 * Metric naming follows AUTH-MODULE-PLAN.md §16 so the dashboards and alerts
 * described there work against this without renaming anything.
 *
 * Two deliberate choices:
 *  - Route labels use the *route pattern* (`/auth/sessions/:id`), never the
 *    concrete URL. Labelling by URL turns an id into a new time series and melts
 *    Prometheus.
 *  - Load shedding replies 503 with Retry-After *before* the box degrades, so a
 *    load balancer can send the request to a healthier replica. Health and
 *    metrics endpoints are exempt: shedding those would make the orchestrator
 *    kill a container that is merely busy.
 */

import fp from 'fastify-plugin';
import underPressure from '@fastify/under-pressure';
import { Registry, collectDefaultMetrics, Histogram, Counter, Gauge } from 'prom-client';
import type { Env } from '../env.js';

declare module 'fastify' {
  interface FastifyInstance {
    metrics: {
      registry: Registry;
      httpDuration: Histogram<'method' | 'route' | 'status_code'>;
      httpTotal: Counter<'method' | 'route' | 'status_code'>;
      shedTotal: Counter<'reason'>;
      authLogin: Counter<'result' | 'method'>;
      authRefresh: Counter<'result'>;
      authOtp: Counter<'channel' | 'purpose' | 'result'>;
      authMfa: Counter<'type' | 'result'>;
    };
  }
}

const EXEMPT_PREFIXES = ['/health', '/metrics', '/docs'];

export const observabilityPlugin = fp(
  async (app, opts: { env: Env }) => {
    const { env } = opts;
    const registry = new Registry();
    registry.setDefaultLabels({ service: 'billing-api' });

    if (env.METRICS_ENABLED) {
      collectDefaultMetrics({ register: registry, prefix: 'node_' });
    }

    const httpDuration = new Histogram({
      name: 'http_request_duration_seconds',
      help: 'HTTP request duration in seconds',
      labelNames: ['method', 'route', 'status_code'] as const,
      // Buckets shaped for an auth API: sub-10ms token checks up to argon2 logins.
      buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
      registers: [registry],
    });

    const httpTotal = new Counter({
      name: 'http_requests_total',
      help: 'HTTP requests by outcome',
      labelNames: ['method', 'route', 'status_code'] as const,
      registers: [registry],
    });

    const shedTotal = new Counter({
      name: 'http_requests_shed_total',
      help: 'Requests rejected by load shedding before handling',
      labelNames: ['reason'] as const,
      registers: [registry],
    });

    // Auth-domain counters (plan §16). Wired now so the dashboards exist before
    // the use-cases land; they stay at zero until then.
    const authLogin = new Counter({
      name: 'auth_login_total',
      help: 'Login attempts by result and method',
      labelNames: ['result', 'method'] as const,
      registers: [registry],
    });
    const authRefresh = new Counter({
      name: 'auth_refresh_total',
      help: 'Refresh-token rotations by result (ok|unknown|reuse|concurrent|expired)',
      labelNames: ['result'] as const,
      registers: [registry],
    });
    const authOtp = new Counter({
      name: 'auth_otp_total',
      help: 'OTP challenges by channel, purpose and result',
      labelNames: ['channel', 'purpose', 'result'] as const,
      registers: [registry],
    });
    const authMfa = new Counter({
      name: 'auth_mfa_total',
      help: 'Second-factor verifications by type and result',
      labelNames: ['type', 'result'] as const,
      registers: [registry],
    });

    // Pool saturation. `waiting` sustained above 0 means the pool is the
    // bottleneck — raise DB_POOL_MAX or add pgBouncer, don't add replicas.
    new Gauge({
      name: 'db_pool_connections',
      help: 'Postgres pool connections by state',
      labelNames: ['state'] as const,
      registers: [registry],
      collect() {
        const s = app.dbHandle.stats();
        this.set({ state: 'total' }, s.total);
        this.set({ state: 'idle' }, s.idle);
        this.set({ state: 'waiting' }, s.waiting);
      },
    });

    // Argon2 admission control. A rising queue means logins are memory-bound;
    // `shed` climbing means HASH_MAX_CONCURRENCY is too low for real traffic.
    new Gauge({
      name: 'auth_hash_queue',
      help: 'Password-hash admission queue',
      labelNames: ['state'] as const,
      registers: [registry],
      collect() {
        const s = app.hasher.stats();
        this.set({ state: 'depth' }, s.queueDepth);
        this.set({ state: 'peak' }, s.peakQueueDepth);
        this.set({ state: 'shed' }, s.shed);
      },
    });

    app.decorate('metrics', {
      registry,
      httpDuration,
      httpTotal,
      shedTotal,
      authLogin,
      authRefresh,
      authOtp,
      authMfa,
    });

    // ── Request timing ──────────────────────────────────────────────────────
    app.addHook('onResponse', async (request, reply) => {
      const route = request.routeOptions.url ?? 'unmatched';
      const labels = {
        method: request.method,
        route,
        status_code: String(reply.statusCode),
      };
      httpDuration.observe(labels, reply.elapsedTime / 1_000);
      httpTotal.inc(labels);
    });

    // ── Load shedding ───────────────────────────────────────────────────────
    //
    // under-pressure does the sampling; the shed decision lives in our own hook
    // below. Its `pressureHandler` is deliberately unused: its published type is
    // `=> void`, but the implementation only sheds if the handler *returns a
    // value* — return nothing and it calls `next()`, so a handler that does
    // `reply.send()` both sends a reply and lets the request continue, which
    // Fastify turns into a 500. Rather than cast around that mismatch, we let the
    // plugin measure and keep the policy here, where the exemption list and the
    // metric already live.
    await app.register(underPressure, {
      maxEventLoopDelay: env.MAX_EVENT_LOOP_DELAY_MS,
      maxHeapUsedBytes: env.MAX_HEAP_USED_BYTES,
      maxRssBytes: env.MAX_RSS_BYTES,
      // Sample often enough to react inside a request burst.
      sampleInterval: 500,
      retryAfter: 5,
      exposeStatusRoute: false,
      pressureHandler: () => undefined,
    });

    app.addHook('onRequest', async (request, reply) => {
      // ⚑ Health, metrics and docs are never shed: a 503 on liveness makes the
      // orchestrator kill a container that is merely busy, turning back-pressure
      // into an outage.
      if (EXEMPT_PREFIXES.some((prefix) => request.url.startsWith(prefix))) return;

      const usage = app.memoryUsage();

      // ⚑ under-pressure reports Infinity when its histogram has no samples for
      // the interval (`Number.isNaN(mean) → Infinity`), which is the state a
      // freshly-started process is in. Infinity beats any threshold, so trusting
      // it verbatim makes a new pod shed *every* request until the first sample
      // lands — precisely when a load balancer is starting to send it traffic.
      // "No measurement yet" is not evidence of a wedged event loop.
      const delayExceeded =
        Number.isFinite(usage.eventLoopDelay) && usage.eventLoopDelay > env.MAX_EVENT_LOOP_DELAY_MS;
      const heapExceeded = usage.heapUsed > env.MAX_HEAP_USED_BYTES;
      const rssExceeded = usage.rssBytes > env.MAX_RSS_BYTES;

      if (!delayExceeded && !heapExceeded && !rssExceeded) return;

      const reason = delayExceeded ? 'eventLoopDelay' : heapExceeded ? 'heapUsed' : 'rssBytes';

      shedTotal.inc({ reason });
      request.log.warn({ reason, usage }, 'shedding request under pressure');

      return reply
        .code(503)
        .header('retry-after', '5')
        .send({
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Server is shedding load — retry shortly',
            details: { pressure: reason },
            traceId: request.id,
          },
        });
    });
  },
  { name: 'observability', dependencies: ['infra'] },
);
