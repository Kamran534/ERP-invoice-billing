/**
 * OpenAPI 3.1 document + Swagger UI.
 *
 * The document is generated from the same zod schemas that validate and serialize
 * each request, so it cannot drift from the implementation — if a route's
 * contract changes, the docs change with it or the build fails.
 *
 * Served at:
 *   GET /docs           Swagger UI
 *   GET /docs/json      the OpenAPI document (machine-readable, for codegen)
 *   GET /docs/yaml      same, YAML
 *
 * ⚑ Production: SWAGGER_ENABLED=false, or gate it. An always-on public docs page
 * hands an attacker a complete map of your auth surface, including which fields
 * are optional and which codes each endpoint returns.
 */

import fp from 'fastify-plugin';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import type { Env } from '../env.js';

export const TAGS = {
  meta: 'Meta',
  health: 'Health',
  auth: 'Auth · session',
  otp: 'Auth · OTP & 2FA',
  account: 'Auth · account',
  keys: 'Auth · keys',
} as const;

export const securitySchemes = {
  bearerAuth: {
    type: 'http',
    scheme: 'bearer',
    bearerFormat: 'JWT',
    description:
      'Access token (EdDSA-signed JWT, 10 min). Used in `bearer` transport mode. ' +
      'Verify with the JWKS at `/.well-known/jwks.json`; pin `alg` to EdDSA and resolve `kid` locally.',
  },
  cookieAuth: {
    type: 'apiKey',
    in: 'cookie',
    name: '__Host-at',
    description: 'Access token cookie (httpOnly). Default mode. Pair with `csrfToken` on writes.',
  },
  csrfToken: {
    type: 'apiKey',
    in: 'header',
    name: 'X-CSRF-Token',
    description:
      'Double-submit CSRF token: must equal the readable `csrf` cookie. Required on every ' +
      'state-changing request in cookie mode (§8.3). SameSite alone is not sufficient.',
  },
  mfaChallenge: {
    type: 'http',
    scheme: 'bearer',
    description:
      'Short-lived (5 min, single-use) challenge token from `/auth/login`. Authorizes *only* ' +
      '`/auth/mfa/verify` and `/auth/mfa/otp/send` — it carries no session and no permissions (§5.4.2).',
  },
} as const;

export const swaggerPlugin = fp(
  async (app, opts: { env: Env }) => {
    const { env } = opts;
    if (!env.SWAGGER_ENABLED) {
      app.log.info('swagger disabled (SWAGGER_ENABLED=false)');
      return;
    }

    await app.register(swagger, {
      openapi: {
        openapi: '3.1.0',
        // ⚑ Deliberately no `description` or `summary` prose here. A long
        // narrative in `info` renders as a wall of text above the operation list
        // and pushes the endpoints below the fold — the one thing a reader opened
        // this page for. Client-facing guidance belongs on the operation that
        // needs it (see the single-flight warning on /auth/token/refresh), and the
        // background lives in the docs vault, linked via externalDocs below.
        info: {
          title: `${env.APP_NAME} — Auth API`,
          version: '0.1.0',
          license: { name: 'UNLICENSED', identifier: 'UNLICENSED' },
        },
        // ⚑ Relative, so "Try it out" targets whatever origin the docs were loaded
        // from. A hardcoded `http://localhost:3000` means every request from
        // http://<lan-ip>:3000/docs is cross-origin, gets no
        // Access-Control-Allow-Origin, and fails with a bare "Failed to fetch" —
        // and it works perfectly on localhost, so the breakage only appears once
        // someone opens the docs from another machine.
        //
        // Deliberately no staging/production entries: placeholder hostnames are
        // worse than none, because they are selectable in the UI and would fire
        // real requests at a domain we do not own. Real environments belong here
        // once they exist.
        servers: [{ url: '/', description: 'This server — the origin serving these docs' }],
        tags: [
          { name: TAGS.meta, description: 'Service discovery. Where everything else lives.' },
          { name: TAGS.health, description: 'Liveness and readiness probes. Unauthenticated.' },
          {
            name: TAGS.auth,
            description:
              'Registration, login, logout, refresh rotation and device/session management (§5.1–§5.9).',
          },
          {
            name: TAGS.otp,
            description:
              'One-time passcodes as a primary factor (§5.11) and as a second factor, plus TOTP ' +
              'enrollment, recovery codes and trusted devices (§5.4).',
          },
          { name: TAGS.account, description: 'Profile, password and email lifecycle.' },
          { name: TAGS.keys, description: 'Public keys for token verification.' },
        ],
        components: {
          securitySchemes,
        },
        // No global `security`: most auth endpoints are deliberately public, and
        // a blanket requirement would document them wrongly. Each operation
        // declares what it needs.
        externalDocs: {
          url: 'https://github.com/your-org/invoice-billing/blob/main/docs/AUTH-MODULE-PLAN.md',
          description: 'Auth module design plan (threat model, flows, phases)',
        },
      },
      hideUntagged: true,
    });

    await app.register(swaggerUi, {
      routePrefix: env.SWAGGER_ROUTE_PREFIX,
      uiConfig: {
        docExpansion: 'list',
        deepLinking: true,
        displayRequestDuration: true,
        // Keeps a pasted token across reloads — the difference between docs you
        // can actually exercise and docs you only read.
        persistAuthorization: true,
        tryItOutEnabled: true,
        filter: true,
        defaultModelsExpandDepth: 2,
        defaultModelRendering: 'model',
        syntaxHighlight: { activate: true, theme: 'nord' },
      },
      // Sends credentials on "Try it out" so cookie-mode flows work in the UI.
      initOAuth: {},
      // swagger-ui sets its own CSP for its routes, replacing the strict API one.
      // ⚑ That policy includes `upgrade-insecure-requests`, which over plain HTTP
      // rewrites every stylesheet and script to https:// and fails them all with
      // ERR_SSL_PROTOCOL_ERROR — invisible on localhost (a trustworthy origin is
      // exempt) and total breakage on a LAN address. Strip it unless we really are
      // on HTTPS; the same gate as helmet's copy in the security plugin.
      staticCSP: true,
      transformStaticCSP: (header) =>
        env.HTTPS_ENABLED
          ? header
          : header
              .replace(/\s*upgrade-insecure-requests\s*;?/gi, '')
              .replace(/;\s*;/g, ';')
              .trim(),
      theme: { title: `${env.APP_NAME} — Auth API` },
    });

    app.log.info(
      { docs: `http://localhost:${env.PORT}${env.SWAGGER_ROUTE_PREFIX}` },
      'swagger ui mounted',
    );
  },
  { name: 'swagger' },
);
