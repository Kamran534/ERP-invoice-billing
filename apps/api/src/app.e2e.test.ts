/**
 * End-to-end tests for the HTTP surface.
 *
 * These drive the real app — real plugin chain, real ajv validation, real
 * serializers, real Postgres/Redis/SMTP — through `app.inject()`. No sockets, no
 * ports, no flaky waiting on a server to come up, but every layer executes
 * exactly as it does in production.
 *
 * They cover the cross-cutting behaviour that no single route owns and that is
 * easy to break without noticing: the error envelope, the security headers, the
 * cache directives, unknown-field stripping, and the OpenAPI contract itself.
 *
 *   pnpm up && pnpm db:migrate && pnpm test:e2e
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { loadEnv } from './env.js';
import { buildApp } from './app.js';

let app: FastifyInstance;

/**
 * Base test environment.
 *
 * ⚑ Load shedding and dependency timeouts are deliberately relaxed here. A
 * vitest worker spends its first seconds transforming and collecting modules,
 * which pushes event-loop delay well past the production 200 ms threshold — so
 * with production settings `@fastify/under-pressure` sheds unrelated requests and
 * every assertion fails with a non-deterministic 503. That is the test harness
 * being measured, not the application.
 *
 * Shedding still gets tested, in its own case below, with an app configured to
 * shed deliberately.
 */
function testEnv(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    ...process.env,
    NODE_ENV: 'test',
    LOG_LEVEL: 'silent',
    LOG_PRETTY: 'false',
    SWAGGER_ENABLED: 'true',
    METRICS_ENABLED: 'true',
    CORS_ORIGINS: 'http://localhost:5173',
    // ⚑ A per-run Redis namespace. Rate-limit counters are shared state with a
    // one-hour window, so without this the suite inherits the budget consumed by
    // the previous run (and by the dev server) and unrelated tests start seeing
    // 429 instead of the status they assert.
    REDIS_KEY_PREFIX: `e2e-${Date.now()}:`,
    MAX_EVENT_LOOP_DELAY_MS: '60000',
    MAX_HEAP_USED_BYTES: String(8 * 1024 ** 3),
    MAX_RSS_BYTES: String(8 * 1024 ** 3),
    DB_CONNECT_TIMEOUT_MS: '30000',
    REDIS_COMMAND_TIMEOUT_MS: '10000',
    ...overrides,
  } as NodeJS.ProcessEnv;
}

/**
 * Wait until readiness reports every dependency up.
 *
 * ioredis connects asynchronously, so immediately after `buildApp()` the Redis
 * ping can legitimately fail — readiness correctly says "not ready yet". An
 * orchestrator waits for that; so does this suite, rather than asserting against
 * a half-connected app.
 */
async function waitForReady(instance: FastifyInstance, timeoutMs = 20_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let last = '';
  while (Date.now() < deadline) {
    const response = await instance.inject({ method: 'GET', url: '/health/ready' });
    if (response.statusCode === 200) {
      const body = JSON.parse(response.payload) as { checks: Record<string, { ok: boolean }> };
      if (Object.values(body.checks).every((check) => check.ok)) return;
    }
    last = response.payload;
    // Longer than the 1s readiness cache, or we would just re-read the cached no.
    await new Promise((resolve) => setTimeout(resolve, 1_100));
  }
  throw new Error(`dependencies never became ready within ${timeoutMs}ms. Last: ${last}`);
}

beforeAll(async () => {
  app = await buildApp(loadEnv(testEnv()));
  await waitForReady(app);
});

afterAll(async () => {
  await app?.close();
});

const json = (response: { payload: string }): Record<string, unknown> =>
  JSON.parse(response.payload) as Record<string, unknown>;

// ───────────────────────────────────────────────────────────────────────────
describe('service index', () => {
  it('answers GET / with what this service is and where things are', async () => {
    // Opening the base URL in a browser must not be a 404.
    const response = await app.inject({ method: 'GET', url: '/' });
    expect(response.statusCode).toBe(200);

    const body = json(response) as {
      name: string;
      version: string;
      status: string;
      links: Record<string, string | null>;
    };
    expect(body.name).toContain('Auth API');
    expect(body.status).toBe('ok');
    expect(body.links['health']).toBe('/health/live');
    expect(body.links['jwks']).toBe('/.well-known/jwks.json');
    expect(body.links['docs']).toBe('/docs');
  });

  it('advertises every link it lists', async () => {
    const body = json(await app.inject({ method: 'GET', url: '/' })) as {
      links: Record<string, string | null>;
    };
    // A link that 404s is worse than no link at all.
    for (const [name, path] of Object.entries(body.links)) {
      if (path === null) continue;
      const response = await app.inject({ method: 'GET', url: path });
      expect([200, 302], `${name} -> ${path} returned ${response.statusCode}`).toContain(
        response.statusCode,
      );
    }
  });

  it('exposes no configuration or dependency state', async () => {
    const payload = (await app.inject({ method: 'GET', url: '/' })).payload;
    // Everything operationally sensitive belongs on /health/ready, which is the
    // endpoint you would gate.
    expect(payload).not.toMatch(/postgres|redis|smtp|password|DATABASE_URL|localhost:5/i);
  });

  it('does not advertise the docs when they are disabled', async () => {
    const probe = await buildProbeApp({ SWAGGER_ENABLED: 'false' });
    try {
      const body = json(await probe.inject({ method: 'GET', url: '/' })) as {
        links: Record<string, string | null>;
      };
      expect(body.links['docs']).toBeNull();
      expect(body.links['openapi']).toBeNull();
    } finally {
      await probe.close();
    }
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('health probes', () => {
  it('liveness answers without touching any dependency', async () => {
    const response = await app.inject({ method: 'GET', url: '/health/live' });
    expect(response.statusCode).toBe(200);
    const body = json(response);
    expect(body['status']).toBe('ok');
    expect(typeof body['uptimeSeconds']).toBe('number');
    expect(typeof body['pid']).toBe('number');
  });

  it('readiness reports each dependency with a latency', async () => {
    const response = await app.inject({ method: 'GET', url: '/health/ready' });
    expect([200, 503]).toContain(response.statusCode);
    const body = json(response) as {
      status: string;
      checks: Record<string, { ok: boolean; latencyMs?: number }>;
      pool: { total: number; idle: number; waiting: number };
    };

    expect(Object.keys(body.checks).sort()).toEqual(['postgres', 'redis', 'smtp']);
    expect(body.checks['postgres']!.ok).toBe(true);
    expect(body.checks['redis']!.ok).toBe(true);
    expect(typeof body.checks['postgres']!.latencyMs).toBe('number');
    expect(body.pool).toHaveProperty('waiting');
    expect(response.statusCode).toBe(200);
  });

  it('serves readiness from a short cache so probe bursts do not hammer dependencies', async () => {
    // First call may be a hit from an earlier test; force a known sequence.
    const first = await app.inject({ method: 'GET', url: '/health/ready' });
    const second = await app.inject({ method: 'GET', url: '/health/ready' });
    // Whatever the first was, an immediately following call must be cached.
    expect(second.headers['x-cache']).toBe('hit');
    expect(first.statusCode).toBe(second.statusCode);
  });

  it('exposes the metrics Prometheus scrapes', async () => {
    const response = await app.inject({ method: 'GET', url: '/metrics' });
    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/plain');
    for (const metric of [
      'http_request_duration_seconds',
      'http_requests_total',
      'db_pool_connections',
      'auth_hash_queue',
      'auth_login_total',
      'auth_refresh_total',
      'auth_otp_total',
      'auth_mfa_total',
    ]) {
      expect(response.payload, `missing metric ${metric}`).toContain(metric);
    }
  });

  it('labels request metrics by route pattern, never by concrete URL', async () => {
    await app.inject({ method: 'DELETE', url: '/auth/sessions/0191f0aa-0000-7000-8000-000000000000' });
    const metrics = await app.inject({ method: 'GET', url: '/metrics' });
    // A raw id in a label turns every request into a new time series.
    expect(metrics.payload).toContain('/auth/sessions/:id');
    expect(metrics.payload).not.toContain('0191f0aa-0000-7000-8000-000000000000');
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('JWKS', () => {
  it('publishes an EdDSA public key and nothing private', async () => {
    const response = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
    expect(response.statusCode).toBe(200);
    const body = json(response) as { keys: Array<Record<string, unknown>> };
    expect(body.keys.length).toBeGreaterThan(0);
    const key = body.keys[0]!;
    expect(key['alg']).toBe('EdDSA');
    expect(key['use']).toBe('sig');
    expect(key['kid']).toBeTruthy();
    expect(key).not.toHaveProperty('d'); // the private scalar
  });

  it('is cacheable, unlike every /auth route', async () => {
    const response = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
    // Verifiers must be able to cache this or token checks become a round-trip
    // to this service on every request.
    expect(response.headers['cache-control']).toMatch(/max-age=\d+/);
    expect(response.headers['cache-control']).not.toContain('no-store');
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('auth routes: contracts are live even where handlers are not', () => {
  const unimplemented: Array<[string, string, Record<string, unknown> | undefined, string]> = [
    ['POST', '/auth/password/forgot', { email: 'ada@example.com' }, '§5.7'],
    ['POST', '/auth/otp/request', { destination: 'ada@example.com' }, '§5.11'],
    ['POST', '/auth/otp/verify', { challengeId: '0191f0aa-0000-7000-8000-000000000000', code: '123456' }, '§5.11'],
    // §5.4's own endpoints are live; email OTP *as a second factor* still routes
    // through the OTP engine, which is not.
    ['POST', '/auth/mfa/verify', { mfaToken: 'x', method: 'email_otp', code: '123456' }, '§5.11'],
  ];

  it.each(unimplemented)(
    '%s %s answers 501 pointing at the plan',
    async (method, url, payload, section) => {
      const response = await app.inject({
        method: method as 'GET' | 'POST',
        url,
        ...(payload ? { payload } : {}),
      });

      expect(response.statusCode).toBe(501);
      const body = json(response) as { error: { code: string; message: string; details?: Record<string, unknown> } };
      // A 501 masked as INTERNAL would be a confusing lie; the section pointer
      // makes the gap unambiguous.
      expect(body.error.code).toBe('NOT_IMPLEMENTED');
      expect(body.error.message).toContain('AUTH-MODULE-PLAN.md');
      expect(String(body.error.details?.['plannedIn'])).toContain(section);
    },
  );

  it('never returns a partially-authenticated response from a route that refused', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: 'nobody-at-all@example.test', password: 'correct horse battery staple' },
    });

    // ⚑ The failure mode this guards against changed shape but not substance:
    // it used to be a stub that set a cookie while verifying nothing, and it is
    // now a handler that sets one on a path that should have refused.
    expect(response.statusCode).toBe(401);
    expect(response.headers['set-cookie']).toBeUndefined();
    expect(response.payload).not.toMatch(/accessToken|refreshToken/);
  });

  it('answers the still-unbuilt routes with a pointer rather than a 404', async () => {
    // The contract is published for routes whose handler is a later phase, so a
    // client can generate against the final shape today.
    const response = await app.inject({
      method: 'POST',
      url: '/auth/password/forgot',
      payload: { email: 'ada@example.com' },
    });
    expect(response.statusCode).toBe(501);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('error envelope', () => {
  it('uses one shape for every error, with a traceId', async () => {
    const response = await app.inject({ method: 'GET', url: '/does-not-exist' });
    expect(response.statusCode).toBe(404);
    const body = json(response) as {
      error: { code: string; message: string; traceId: string; details?: Record<string, unknown> };
    };
    expect(body.error.code).toBe('NOT_FOUND');
    expect(body.error.message).toContain('GET /does-not-exist');
    expect(body.error.traceId).toBeTruthy();
    // The traceId must be the same value the client sees in the header and the
    // operator sees in the log.
    expect(body.error.traceId).toBe(response.headers['x-request-id']);
    // A 404 should say where to look instead of leaving you guessing.
    expect(body.error.details?.['index']).toBe('/');
    expect(body.error.details?.['docs']).toBe('/docs');
  });

  it('does not point a 404 at docs that are disabled', async () => {
    const probe = await buildProbeApp({ SWAGGER_ENABLED: 'false' });
    try {
      const body = json(await probe.inject({ method: 'GET', url: '/nope' })) as {
        error: { details?: Record<string, unknown> };
      };
      expect(body.error.details?.['index']).toBe('/');
      expect(body.error.details?.['docs']).toBeUndefined();
    } finally {
      await probe.close();
    }
  });

  it('honours an inbound x-request-id so a trace spans services', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/does-not-exist',
      headers: { 'x-request-id': 'trace-from-edge-proxy' },
    });
    expect(response.headers['x-request-id']).toBe('trace-from-edge-proxy');
    expect((json(response) as { error: { traceId: string } }).error.traceId).toBe(
      'trace-from-edge-proxy',
    );
  });

  // ⚑ These deliberately spread across routes instead of all hitting
  // /auth/register. Register is the tightest limit in the table (5/hour), so a
  // cluster of tests on it exhausts the budget and later tests see 429 instead of
  // the status they assert. Rate limiting gets its own app below.
  it('reports validation failures with the offending path', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email: 'ada@example.com', password: 'short' },
    });
    expect(response.statusCode).toBe(400);
    const body = json(response) as {
      error: { code: string; details: { issues: Array<{ path: string; message: string }> } };
    };
    expect(body.error.code).toBe('VALIDATION_FAILED');
    expect(body.error.details.issues[0]?.path).toContain('password');
  });

  it('rejects a malformed email', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/password/forgot',
      payload: { email: 'not-an-email' },
    });
    expect(response.statusCode).toBe(400);
  });

  it('rejects a missing required field', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/otp/verify',
      payload: { code: '123456' }, // no challengeId
    });
    expect(response.statusCode).toBe(400);
  });

  it('does not coerce types — "1" must never become 1 in an auth payload', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: 12345, password: 'correct horse battery staple' },
    });
    expect(response.statusCode).toBe(400);
  });

  it('rejects a non-numeric OTP code', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/otp/verify',
      payload: { challengeId: '0191f0aa-0000-7000-8000-000000000000', code: 'abcdef' },
    });
    expect(response.statusCode).toBe(400);
  });

  it('rejects a non-uuid path parameter', async () => {
    // ⚑ With a CSRF pair, or the onRequest hook refuses at 403 before the
    // schema is ever consulted — which would make this assert the wrong layer.
    const response = await app.inject({
      method: 'DELETE',
      url: '/auth/sessions/not-a-uuid',
      headers: { cookie: 'csrf=probe', 'x-csrf-token': 'probe' },
    });
    expect(response.statusCode).toBe(400);
  });

  it('strips unknown fields rather than rejecting the request', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: {
        email: 'ada@example.com',
        password: 'correct horse battery staple',
        isAdmin: true, // a hopeful privilege-escalation attempt
      },
    });
    // Reaching the handler proves the extra field was removed, not honoured: a
    // 401 is the handler refusing an unknown account, which means it ran.
    expect(response.statusCode).toBe(401);
  });

  it('rejects a non-JSON body with a typed error, not a stack trace', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/login',
      headers: { 'content-type': 'application/json' },
      payload: '{not json',
    });
    expect(response.statusCode).toBeGreaterThanOrEqual(400);
    const body = json(response) as { error: { code: string; traceId: string } };
    expect(body.error.code).toBeTruthy();
    expect(response.payload).not.toContain('at Object.');
  });

  it('rejects an oversized body', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: 'ada@example.com', password: 'x'.repeat(200_000) },
    });
    // 413 from the bodyLimit, or 400 if validation rejects the length first.
    expect([400, 413]).toContain(response.statusCode);
  });

  it('never leaks an internal message on a 5xx', async () => {
    // Registered here rather than in the app: a route that throws a raw error is
    // the only honest way to test the generic 500 path.
    const probe = await buildProbeApp();
    try {
      const response = await probe.inject({ method: 'GET', url: '/boom' });
      expect(response.statusCode).toBe(500);
      const body = json(response) as { error: { code: string; message: string } };
      expect(body.error.code).toBe('INTERNAL');
      expect(body.error.message).toBe('Internal server error');
      expect(response.payload).not.toContain('secret-connection-string');
    } finally {
      await probe.close();
    }
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('security headers and cache directives', () => {
  it('sets the baseline hardening headers', async () => {
    const response = await app.inject({ method: 'GET', url: '/health/live' });
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
    expect(response.headers['cross-origin-resource-policy']).toBe('same-origin');
    expect(response.headers['x-powered-by']).toBeUndefined();
  });

  it('keeps the API content-security-policy strict, with no merged-in defaults', async () => {
    const csp = String((await app.inject({ method: 'GET', url: '/' })).headers['content-security-policy']);
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    // helmet merges its defaults unless useDefaults:false — which would quietly
    // reintroduce script-src/style-src allowances an API has no use for.
    expect(csp).not.toContain('script-src');
    expect(csp).not.toContain('style-src');
  });

  // ⚑ These three are meaningless on a plain-HTTP origin and actively harmful:
  // upgrade-insecure-requests rewrites every subresource to https:// and breaks
  // the page for anyone not on localhost. See env.ts HTTPS_ENABLED.
  it('omits HTTPS-only headers when not served over HTTPS', async () => {
    const response = await app.inject({ method: 'GET', url: '/health/live' });
    expect(response.headers['strict-transport-security']).toBeUndefined();
    expect(response.headers['cross-origin-opener-policy']).toBeUndefined();
    expect(String(response.headers['content-security-policy'])).not.toContain(
      'upgrade-insecure-requests',
    );
  });

  it('does not let the docs UI upgrade its own assets over plain HTTP', async () => {
    // swagger-ui replaces the API's CSP on its own routes and its policy includes
    // upgrade-insecure-requests — a second, separate source of the same breakage.
    for (const url of ['/docs', '/docs/static/swagger-ui.css']) {
      const csp = String((await app.inject({ method: 'GET', url })).headers['content-security-policy'] ?? '');
      expect(csp, `${url} still upgrades its assets`).not.toContain('upgrade-insecure-requests');
    }
  });

  it('sends the HTTPS-only headers when HTTPS_ENABLED is set', async () => {
    const probe = await buildProbeApp({ HTTPS_ENABLED: 'true', SWAGGER_ENABLED: 'true' });
    try {
      const response = await probe.inject({ method: 'GET', url: '/health/live' });
      expect(response.headers['strict-transport-security']).toContain('max-age=63072000');
      expect(response.headers['cross-origin-opener-policy']).toBe('same-origin');
      expect(String(response.headers['content-security-policy'])).toContain(
        'upgrade-insecure-requests',
      );
      const docsCsp = String((await probe.inject({ method: 'GET', url: '/docs' })).headers['content-security-policy']);
      expect(docsCsp).toContain('upgrade-insecure-requests');
    } finally {
      await probe.close();
    }
  });

  it('marks every auth response no-store', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: 'ada@example.com', password: 'correct horse battery staple' },
    });
    // A cached auth response in a CDN or browser back-button is a session leak.
    expect(response.headers['cache-control']).toContain('no-store');
    expect(response.headers['pragma']).toBe('no-cache');
  });

  it('reflects only allowlisted CORS origins', async () => {
    const allowed = await app.inject({
      method: 'OPTIONS',
      url: '/auth/login',
      headers: {
        origin: 'http://localhost:5173',
        'access-control-request-method': 'POST',
      },
    });
    expect(allowed.headers['access-control-allow-origin']).toBe('http://localhost:5173');
    expect(allowed.headers['access-control-allow-credentials']).toBe('true');

    const denied = await app.inject({
      method: 'OPTIONS',
      url: '/auth/login',
      headers: { origin: 'https://evil.test', 'access-control-request-method': 'POST' },
    });
    // ⚑ Reflecting an arbitrary origin with credentials:true hands an attacker a
    // cookie-authenticated read of the API.
    expect(denied.headers['access-control-allow-origin']).not.toBe('https://evil.test');
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('rate limiting', () => {
  it('returns a typed 429 with Retry-After once the route limit is hit', async () => {
    // A dedicated app with its own Redis namespace, so this test starts with a
    // full budget no matter what ran before it. /auth/register has the tightest
    // limit in the table (5/hour), so it is the cheapest to exercise.
    const probe = await buildProbeApp();
    try {
      await waitForReady(probe);

      const payload = { email: 'ratelimit@example.com', password: 'correct horse battery staple' };
      const observed: number[] = [];
      let unexpected = '';
      let limited: Awaited<ReturnType<typeof probe.inject>> | undefined;

      for (let i = 0; i < 12 && !limited; i += 1) {
        const response = await probe.inject({ method: 'POST', url: '/auth/register', payload });
        observed.push(response.statusCode);
        if (response.statusCode === 429) limited = response;
        else if (response.statusCode >= 500 && !unexpected) unexpected = response.payload;
      }

      // The observed sequence and the first 5xx body go into the failure message:
      // "never triggered" alone does not say whether the limiter was bypassed,
      // mis-keyed, or erroring because its store was unreachable.
      expect(
        limited,
        `no 429 in 12 attempts; saw ${observed.join(',')}${unexpected ? ` | first 5xx: ${unexpected}` : ''}`,
      ).toBeDefined();
      // The limit is 5, so the first five must be let through.
      expect(observed.filter((status) => status !== 429)).toHaveLength(5);

      const body = json(limited!) as { error: { code: string; traceId: string } };
      expect(body.error.code).toBe('RATE_LIMITED');
      expect(limited!.headers['retry-after']).toBeTruthy();
      expect(body.error.traceId).toBeTruthy();
    } finally {
      await probe.close();
    }
  });

  it('counts limits per cluster, not per replica', async () => {
    // Two instances sharing a Redis namespace must share one budget — otherwise
    // N replicas silently multiply every limit by N.
    const namespace = `shared-${Date.now()}:`;
    const a = await buildProbeApp({ REDIS_KEY_PREFIX: namespace });
    const b = await buildProbeApp({ REDIS_KEY_PREFIX: namespace });
    try {
      await waitForReady(a);
      const payload = { email: 'cluster@example.com', password: 'correct horse battery staple' };

      // Spend the whole 5/hour budget on instance A.
      for (let i = 0; i < 5; i += 1) {
        await a.inject({ method: 'POST', url: '/auth/register', payload });
      }
      // Instance B must already be out of budget.
      const response = await b.inject({ method: 'POST', url: '/auth/register', payload });
      expect(response.statusCode).toBe(429);
    } finally {
      await Promise.all([a.close(), b.close()]);
    }
  });

  it('does not rate limit health or metrics', async () => {
    for (let i = 0; i < 40; i += 1) {
      const response = await app.inject({ method: 'GET', url: '/health/live' });
      expect(response.statusCode).toBe(200);
    }
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('load shedding', () => {
  /**
   * under-pressure samples memory on an interval (500 ms here), so immediately
   * after boot its readings are still zero and nothing looks like pressure.
   * Waiting for the condition itself is deterministic; sleeping a guessed
   * duration is how a test becomes flaky on a slower CI box.
   */
  async function waitForPressure(instance: FastifyInstance, timeoutMs = 10_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (instance.memoryUsage().heapUsed > 1) return;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(`app never reported pressure within ${timeoutMs}ms`);
  }

  it('does not shed merely because the event loop has not been sampled yet', async () => {
    // Regression guard. under-pressure reports Infinity for "no samples in this
    // window", which beats any threshold — a freshly started process would shed
    // every request until its first sample landed.
    const probe = await buildProbeApp();
    try {
      const response = await probe.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'ada@example.com', password: 'correct horse battery staple' },
      });
      // Reaching the handler at all is the proof; a 503 here means the guard
      // regressed. The 401 is just this unknown account being refused.
      expect(response.statusCode).toBe(401);
    } finally {
      await probe.close();
    }
  });

  it('sheds with a retryable 503 once a pressure threshold is crossed', async () => {
    // A 1-byte heap ceiling is guaranteed to be exceeded, which makes this
    // deterministic instead of depending on how loaded the machine happens to be.
    const probe = await buildProbeApp({ MAX_HEAP_USED_BYTES: '1' });
    try {
      await waitForPressure(probe);
      const response = await probe.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'ada@example.com', password: 'correct horse battery staple' },
      });

      expect(response.statusCode).toBe(503);
      const body = json(response) as { error: { code: string; details?: Record<string, unknown> } };
      expect(body.error.code).toBe('SERVICE_UNAVAILABLE');
      // Retry-After is what makes this a load-balancer-retryable failure rather
      // than a lost request.
      expect(response.headers['retry-after']).toBeTruthy();
      expect(body.error.details?.['pressure']).toBeTruthy();
    } finally {
      await probe.close();
    }
  });

  it('never sheds health or metrics, even under pressure', async () => {
    const probe = await buildProbeApp({ MAX_HEAP_USED_BYTES: '1', METRICS_ENABLED: 'true' });
    try {
      await waitForPressure(probe);
      // ⚑ Shedding liveness would make the orchestrator kill a container that is
      // merely busy — turning back-pressure into an outage.
      expect((await probe.inject({ method: 'GET', url: '/health/live' })).statusCode).toBe(200);
      expect((await probe.inject({ method: 'GET', url: '/metrics' })).statusCode).toBe(200);
    } finally {
      await probe.close();
    }
  });

  it('counts shed requests so the metric can drive an alert', async () => {
    const probe = await buildProbeApp({ MAX_HEAP_USED_BYTES: '1', METRICS_ENABLED: 'true' });
    try {
      await waitForPressure(probe);
      await probe.inject({ method: 'GET', url: '/auth/me' });
      const metrics = await probe.inject({ method: 'GET', url: '/metrics' });
      expect(metrics.payload).toContain('http_requests_shed_total');
    } finally {
      await probe.close();
    }
  });
});

// ───────────────────────────────────────────────────────────────────────────

interface OpenApiOperation {
  summary?: string;
  description?: string;
  tags?: string[];
  operationId?: string;
  security?: Array<Record<string, string[]>>;
  responses: Record<string, unknown>;
}

interface OpenApiDoc {
  openapi: string;
  info: { title: string; version: string; description: string };
  servers: unknown[];
  tags: unknown[];
  paths: Record<string, Record<string, OpenApiOperation>>;
  components: { securitySchemes: Record<string, unknown> };
}

/**
 * `app.swagger()` is typed as the generic `Document` from the OpenAPI types,
 * which does not structurally overlap with the shape we assert on — so the cast
 * goes through `unknown` once, here, rather than being repeated per test.
 */
const openApiDoc = (): OpenApiDoc => app.swagger() as unknown as OpenApiDoc;

describe('OpenAPI document', () => {
  it('is a valid OpenAPI 3.1 document with servers and tags', () => {
    const doc = openApiDoc();
    expect(doc.openapi).toBe('3.1.0');
    expect(doc.info.title).toContain('Auth API');
    expect(doc.info.version).toBeTruthy();
    expect(doc.servers.length).toBeGreaterThan(0);
    expect(doc.tags.length).toBeGreaterThan(0);
  });

  it('uses a relative server url so "Try it out" works from any origin', () => {
    // ⚑ An absolute `http://localhost:3000` makes every Try-it-out request from
    // http://<lan-ip>:3000/docs cross-origin, which CORS blocks with an unhelpful
    // "Failed to fetch". It works on localhost, so the breakage is invisible until
    // someone opens the docs from another machine.
    const servers = openApiDoc().servers as Array<{ url: string }>;
    expect(servers[0]?.url).toBe('/');
    for (const server of servers) {
      expect(server.url, `${server.url} is absolute`).not.toMatch(/^https?:\/\//);
    }
  });

  it('declares every security scheme the routes reference', () => {
    const doc = openApiDoc();
    const declared = new Set(Object.keys(doc.components.securitySchemes));
    expect(declared).toEqual(new Set(['bearerAuth', 'cookieAuth', 'csrfToken', 'mfaChallenge']));

    // A scheme referenced but not declared renders as a broken auth button in
    // Swagger UI and breaks generated clients.
    for (const [path, methods] of Object.entries(doc.paths)) {
      for (const [method, operation] of Object.entries(methods)) {
        for (const requirement of operation.security ?? []) {
          for (const scheme of Object.keys(requirement)) {
            expect(declared, `${method.toUpperCase()} ${path} references ${scheme}`).toContain(scheme);
          }
        }
      }
    }
  });

  it('documents every registered route, and only real ones', () => {
    const doc = openApiDoc();
    const documented = Object.keys(doc.paths);

    for (const expected of [
      '/',
      '/health/live',
      '/health/ready',
      '/.well-known/jwks.json',
      '/auth/register',
      '/auth/login',
      '/auth/token/refresh',
      '/auth/logout',
      '/auth/me',
      '/auth/otp/request',
      '/auth/otp/verify',
      '/auth/mfa/verify',
      '/auth/mfa/totp/setup',
      '/auth/trusted-devices',
    ]) {
      expect(documented, `undocumented route ${expected}`).toContain(expected);
    }

    // /metrics is an operational surface, not part of the product contract.
    expect(documented).not.toContain('/metrics');
    expect(documented.length).toBeGreaterThanOrEqual(26);
  });

  it('gives every operation a summary, a tag and a unique operationId', () => {
    const doc = openApiDoc();
    const ids: string[] = [];

    for (const [path, methods] of Object.entries(doc.paths)) {
      for (const [method, operation] of Object.entries(methods)) {
        const where = `${method.toUpperCase()} ${path}`;
        expect(operation.summary, `${where} has no summary`).toBeTruthy();
        expect(operation.tags?.length, `${where} has no tag`).toBeGreaterThan(0);
        // Client generators name functions from operationId; duplicates collide.
        expect(operation.operationId, `${where} has no operationId`).toBeTruthy();
        ids.push(operation.operationId!);
      }
    }
    expect(new Set(ids).size, 'duplicate operationId').toBe(ids.length);
  });

  it('documents the error envelope on every operation that can fail', () => {
    const doc = openApiDoc();
    for (const [path, methods] of Object.entries(doc.paths)) {
      for (const [method, operation] of Object.entries(methods)) {
        const codes = Object.keys(operation.responses);
        // Callers need to know these are possible everywhere, not discover them.
        for (const status of ['400', '429', '500', '503']) {
          expect(codes, `${method.toUpperCase()} ${path} omits ${status}`).toContain(status);
        }
      }
    }
  });

  it('documents rate limits where they are tight enough to matter', () => {
    const doc = openApiDoc();
    for (const path of ['/auth/register', '/auth/login', '/auth/otp/request', '/auth/otp/verify']) {
      const description = doc.paths[path]?.['post']?.description ?? '';
      expect(description, `${path} does not document its rate limit`).toMatch(/Rate limit/i);
    }
  });

  it('explains the refresh single-flight requirement, which clients must implement', () => {
    const doc = openApiDoc();
    const description = doc.paths['/auth/token/refresh']?.['post']?.description ?? '';
    // A client that misses this logs users out on every multi-tab race.
    expect(description).toMatch(/single-flight/i);
    expect(description).toContain('409');
  });

  it('is served as JSON at the documented URL', async () => {
    const response = await app.inject({ method: 'GET', url: '/docs/json' });
    expect(response.statusCode).toBe(200);
    const doc = json(response) as { openapi: string };
    expect(doc.openapi).toBe('3.1.0');
  });

  it('serves the Swagger UI page', async () => {
    const response = await app.inject({ method: 'GET', url: '/docs' });
    expect([200, 302]).toContain(response.statusCode);
  });
});

/**
 * A second instance with an extra throwing route, for the tests that need a
 * genuine 5xx and a fresh rate-limit budget. Uses the `extend` seam because
 * Fastify refuses new routes after `ready()`.
 */
async function buildProbeApp(overrides: Record<string, string> = {}): Promise<FastifyInstance> {
  const env = loadEnv(
    testEnv({
      SWAGGER_ENABLED: 'false',
      METRICS_ENABLED: 'false',
      // A distinct Redis namespace so this instance's rate-limit counters are its
      // own and cannot bleed into the main app's tests.
      REDIS_KEY_PREFIX: `probe-${Date.now()}-${Math.floor(performance.now())}:`,
      ...overrides,
    }),
  );

  return buildApp(env, {
    extend: (probe) => {
      probe.get('/boom', { schema: { hide: true } }, async () => {
        throw new Error('secret-connection-string leaked in a message');
      });
    },
  });
}
