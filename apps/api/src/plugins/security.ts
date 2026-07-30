/**
 * HTTP security surface (AUTH-MODULE-PLAN.md §8.2, §8.3, §8.5).
 *
 * A note on what is deliberately *absent*: response compression. Compressing a
 * response that mixes a secret (a token) with attacker-influenced input is the
 * BREACH side channel, and auth payloads are a few hundred bytes anyway — there
 * is nothing to win and something real to lose.
 */

import fp from 'fastify-plugin';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import { sha256 } from '@auth/crypto';
import type { Env } from '../env.js';

export const securityPlugin = fp(
  async (app, opts: { env: Env }) => {
    const { env } = opts;

    // ── Headers ─────────────────────────────────────────────────────────────
    //
    // Three of these are meaningful only on a secure origin and actively harmful
    // on a plain-HTTP one, so they are gated on HTTPS_ENABLED (see env.ts):
    //
    //   upgrade-insecure-requests  rewrites every http:// subresource to https://.
    //                              Over plain HTTP this breaks the page for anyone
    //                              not on localhost — which is exempt as a
    //                              trustworthy origin, so the breakage is
    //                              invisible until someone opens a LAN address.
    //   Strict-Transport-Security  ignored by browsers when received over HTTP.
    //   Cross-Origin-Opener-Policy ignored on a non-trustworthy origin, and logs
    //                              a console warning saying so.
    const https = env.HTTPS_ENABLED;

    await app.register(helmet, {
      contentSecurityPolicy: {
        // ⚑ Without this, helmet merges its defaults into ours and quietly
        // reintroduces script-src/style-src allowances — and
        // upgrade-insecure-requests. An API that serves JSON needs none of it.
        useDefaults: false,
        directives: {
          defaultSrc: ["'none'"],
          frameAncestors: ["'none'"],
          baseUri: ["'none'"],
          formAction: ["'none'"],
          ...(https ? { upgradeInsecureRequests: [] } : {}),
        },
      },
      hsts: https ? { maxAge: 63_072_000, includeSubDomains: true, preload: true } : false,
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      crossOriginOpenerPolicy: https ? { policy: 'same-origin' } : false,
      crossOriginResourcePolicy: { policy: 'same-origin' },
      permittedCrossDomainPolicies: false,
      xPoweredBy: false,
    });

    // ⚑ No auth response may ever be cached — not by the browser, not by a CDN.
    // JWKS is deliberately excluded: it is public key material and *should* be
    // cached, and it sets its own Cache-Control.
    app.addHook('onSend', async (request, reply, payload) => {
      if (request.url.startsWith('/auth')) {
        reply.header('cache-control', 'no-store, no-cache, must-revalidate, private');
        reply.header('pragma', 'no-cache');
      }
      return payload;
    });

    // ── CORS ────────────────────────────────────────────────────────────────
    // Explicit allowlist only. `credentials: true` with a reflected origin is the
    // classic way to hand an attacker a cookie-authenticated read of your API.
    await app.register(cors, {
      origin: env.CORS_ORIGINS.length > 0 ? env.CORS_ORIGINS : false,
      credentials: true,
      methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['content-type', 'authorization', 'x-csrf-token', 'x-request-id'],
      exposedHeaders: ['x-request-id', 'retry-after'],
      maxAge: 600,
    });

    // ── Cookies ─────────────────────────────────────────────────────────────
    await app.register(cookie, {
      // Signing is unnecessary: every cookie we set holds either an opaque
      // 256-bit secret verified against a stored hash, or a JWT. A signature
      // would add a second secret to manage for no gain.
      parseOptions: {
        httpOnly: true,
        // Same signal as HSTS above: a `Secure` cookie is simply dropped over
        // plain HTTP, so these two must never disagree.
        secure: https,
        sameSite: 'lax',
        path: '/',
      },
    });

    // ── Rate limiting ───────────────────────────────────────────────────────
    await app.register(rateLimit, {
      global: true,
      // Generous global ceiling; the strict per-endpoint limits from plan §8.2
      // are declared per route via `config.rateLimit`.
      max: 300,
      timeWindow: '1 minute',
      // Shared store, so the limit is per-cluster and not per-replica. Without
      // this, N replicas silently multiply every limit by N.
      redis: app.redis,
      nameSpace: 'rl:',
      // ⚑ Fail CLOSED: a Redis outage must not become an open brute-force window
      // (plan §8.2). Note this is a *global* switch in @fastify/rate-limit —
      // per-route overrides are not supported. Plan §8.2 wants refresh to fail
      // open instead (availability over strictness there); that needs a second
      // rate-limit instance scoped to /auth/token, which is a Phase 1 task.
      skipOnError: false,
      // Hash the identifier so Redis holds no raw IPs or addresses.
      keyGenerator: (request) => {
        const ip = request.ip || 'unknown';
        return Buffer.from(sha256(ip)).toString('base64url');
      },
      errorResponseBuilder: (request, context) => ({
        statusCode: 429,
        error: {
          code: 'RATE_LIMITED',
          message: `Too many requests — retry in ${Math.ceil(context.ttl / 1000)}s`,
          details: { limit: context.max, windowMs: context.ttl },
          traceId: request.id,
        },
      }),
      addHeadersOnExceeding: {
        'x-ratelimit-limit': true,
        'x-ratelimit-remaining': true,
        'x-ratelimit-reset': true,
      },
    });
  },
  { name: 'security', dependencies: ['infra'] },
);
