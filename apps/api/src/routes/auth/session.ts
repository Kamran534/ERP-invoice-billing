/**
 * Session lifecycle: register, login, refresh, logout, devices, password.
 *
 * The contracts, status codes, rate limits and security requirements here are
 * final — they are what the OpenAPI document publishes and what clients build
 * against. The handler bodies are the Phase 1 work (AUTH-MODULE-PLAN.md §18) and
 * currently answer `501 NOT_IMPLEMENTED` with a pointer to the spec section, so
 * nothing silently half-authenticates anyone.
 */

import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { errors } from '@auth/core';
import { route } from '../../lib/schema.js';
import { TAGS } from '../../plugins/swagger.js';
import {
  authOutcome,
  changePasswordBody,
  deviceSession,
  forgotPasswordBody,
  loginBody,
  okResponse,
  publicUser,
  refreshBody,
  refreshResponse,
  registerBody,
  registerResponse,
  resetPasswordBody,
  uuidField,
} from '../../schemas/auth.js';
import { errorSchema } from '../../lib/schema.js';

/**
 * Either transport satisfies these routes: cookies + CSRF header, or a bearer
 * token. OpenAPI reads the array as OR and each object's keys as AND.
 */
const cookieSecurity: Array<Record<string, string[]>> = [
  { cookieAuth: [], csrfToken: [] },
  { bearerAuth: [] },
];

export async function sessionRoutes(app: FastifyInstance): Promise<void> {
  // ── Registration ─────────────────────────────────────────────────────────
  app.post(
    '/auth/register',
    {
      config: { rateLimit: { max: 5, timeWindow: '1 hour' } },
      schema: route({
        summary: 'Create an account',
        description:
          'Creates a pending account and emails a verification link. No session is issued until ' +
          'the address is verified.\n\n' +
          '⚑ **Enumeration-safe:** if the address is already registered, the response is identical ' +
          'to a successful signup and a "someone tried to register with your email" notice goes to ' +
          'the existing owner. Never treat a 202 as proof the account is new.',
        tags: [TAGS.auth],
        operationId: 'register',
        rateLimit: '5 per hour per IP',
        body: registerBody,
        response: { 202: registerResponse, 422: errorSchema },
      }),
    },
    async () => {
      throw errors.notImplemented('§5.1 (Phase 1)');
    },
  );

  // ── Login ────────────────────────────────────────────────────────────────
  app.post(
    '/auth/login',
    {
      config: { rateLimit: { max: 20, timeWindow: '5 minutes' } },
      schema: route({
        summary: 'Log in with a password',
        description:
          'Returns one of three outcomes — branch on `status`:\n\n' +
          '* `authenticated` — session issued (tokens in cookies, or in the body in bearer mode).\n' +
          '* `mfa_required` — **no session yet**. Call `/auth/mfa/verify` with the `mfaToken`.\n' +
          '* `mfa_enrollment_required` — policy requires 2FA and none is enrolled; the returned ' +
          'session is quarantined to the enrollment endpoints only.\n\n' +
          '⚑ A wrong password and a non-existent account return the same body **and take the same ' +
          'time** — a dummy Argon2 verification runs on the unknown-user path. Do not build UI that ' +
          'assumes otherwise.\n\n' +
          'After too many failures the account locks and this returns `423 ACCOUNT_LOCKED` with ' +
          '`lockedUntil`.',
        tags: [TAGS.auth],
        operationId: 'login',
        rateLimit: '20 per 5 min per IP, 10 per 15 min per email',
        body: loginBody,
        response: { 200: authOutcome, 401: errorSchema, 403: errorSchema, 423: errorSchema },
      }),
    },
    async () => {
      throw errors.notImplemented('§5.3 (Phase 1)');
    },
  );

  // ── Refresh ──────────────────────────────────────────────────────────────
  app.post(
    '/auth/token/refresh',
    {
      config: { rateLimit: { max: 120, timeWindow: '5 minutes' } },
      schema: route({
        summary: 'Rotate the refresh token and mint an access token',
        description:
          'Consumes the presented refresh token and returns a **new** one. The old token is dead ' +
          'the instant this succeeds.\n\n' +
          '### Client requirements (not optional)\n' +
          '1. **Single-flight.** Exactly one refresh may be in flight per client, across all tabs. ' +
          'Parallel refreshes rotate the chain concurrently; the loser gets `409` and a genuinely ' +
          'replayed token is treated as theft, killing the entire session.\n' +
          '2. On `409 REFRESH_IN_PROGRESS` — wait ~200 ms, retry **once**, then treat as signed out.\n' +
          '3. On `401` — the session is gone. Go to login. Do not retry, do not loop.\n\n' +
          'Permissions are re-read from the database on every rotation, so a role change or ' +
          'suspension takes effect within one access-token lifetime (§5.5.3 step 17).\n\n' +
          '⚑ Presenting an already-used token is treated as **token theft**: the whole session ' +
          'family is revoked, the user is emailed, and an operator is paged. The response is a bare ' +
          '`401` that never explains why.',
        tags: [TAGS.auth],
        operationId: 'refreshToken',
        rateLimit: '120 per 5 min per IP',
        body: refreshBody,
        response: { 200: refreshResponse, 401: errorSchema, 409: errorSchema },
      }),
    },
    async () => {
      throw errors.notImplemented('§5.5 (Phase 1)');
    },
  );

  // ── Logout ───────────────────────────────────────────────────────────────
  app.post(
    '/auth/logout',
    {
      schema: route({
        summary: 'Log out of this device',
        description:
          'Revokes the current session and its refresh chain, and clears the cookies. ' +
          'Idempotent — returns 204 even for an already-dead session, so clients need no error path ' +
          'and nothing is leaked about session state.\n\n' +
          'The access token stays cryptographically valid until it expires (≤10 min). Enable ' +
          '`revocationCheck: cache` for instant invalidation (§5.5.9).',
        tags: [TAGS.auth],
        operationId: 'logout',
        security: cookieSecurity,
        response: { 204: null },
      }),
    },
    async () => {
      throw errors.notImplemented('§5.6 (Phase 1)');
    },
  );

  app.post(
    '/auth/logout-all',
    {
      schema: route({
        summary: 'Log out everywhere',
        description:
          'Revokes every session for the user, including trusted devices. Requires step-up ' +
          're-authentication (§5.4.7) — a stolen live session must not be able to lock the real ' +
          'owner out of their own account.',
        tags: [TAGS.auth],
        operationId: 'logoutAll',
        security: cookieSecurity,
        response: {
          200: z.object({ revokedSessions: z.number() }),
          403: errorSchema,
        },
      }),
    },
    async () => {
      throw errors.notImplemented('§5.6 (Phase 1)');
    },
  );

  // ── Current user ─────────────────────────────────────────────────────────
  app.get(
    '/auth/me',
    {
      schema: route({
        summary: 'Current user, org context and permissions',
        description:
          'The resolved identity for the presented access token. `permissions` is the effective ' +
          'set for the active org — authorize your UI from this, but never trust it as an ' +
          'enforcement boundary; the server re-checks every call.',
        tags: [TAGS.auth],
        operationId: 'getMe',
        security: cookieSecurity,
        response: {
          200: z.object({
            user: publicUser,
            org: z.object({ id: uuidField, name: z.string(), role: z.string() }).nullable(),
            permissions: z.array(z.string()),
            amr: z.array(z.string()),
            mfaSatisfiedAt: z.string().nullable().meta({
              description: 'Drives step-up: if this is older than 15 minutes, sensitive calls will 403.',
            }),
          }),
          401: errorSchema,
        },
      }),
    },
    async () => {
      throw errors.notImplemented('§5.3 / §10 (Phase 1)');
    },
  );

  // ── Devices ──────────────────────────────────────────────────────────────
  app.get(
    '/auth/sessions',
    {
      schema: route({
        summary: 'List signed-in devices',
        tags: [TAGS.auth],
        operationId: 'listSessions',
        security: cookieSecurity,
        response: { 200: z.object({ sessions: z.array(deviceSession) }), 401: errorSchema },
      }),
    },
    async () => {
      throw errors.notImplemented('§5.6 (Phase 1)');
    },
  );

  app.delete(
    '/auth/sessions/:id',
    {
      schema: route({
        summary: 'Sign out one device',
        description: 'Revokes another session by id. Revoking your own is equivalent to `/auth/logout`.',
        tags: [TAGS.auth],
        operationId: 'revokeSession',
        security: cookieSecurity,
        params: z.object({ id: uuidField }),
        response: { 204: null, 401: errorSchema, 404: errorSchema },
      }),
    },
    async () => {
      throw errors.notImplemented('§5.6 (Phase 1)');
    },
  );

  // ── Password ─────────────────────────────────────────────────────────────
  app.post(
    '/auth/password/forgot',
    {
      config: { rateLimit: { max: 10, timeWindow: '1 hour' } },
      schema: route({
        summary: 'Request a password-reset link',
        description:
          '⚑ Always returns `202`, with the same body and the same latency, whether or not the ' +
          'address exists. Rate-limited hard because this endpoint sends mail on demand.\n\n' +
          'The emailed link is built from the server-configured origin — never from the request ' +
          '`Host` header, which would otherwise be a password-reset poisoning vector (§5.7).',
        tags: [TAGS.account],
        operationId: 'forgotPassword',
        rateLimit: '10 per hour per IP, 3 per hour per address',
        body: forgotPasswordBody,
        response: { 202: okResponse },
      }),
    },
    async () => {
      throw errors.notImplemented('§5.7 (Phase 1)');
    },
  );

  app.post(
    '/auth/password/reset',
    {
      config: { rateLimit: { max: 20, timeWindow: '1 hour' } },
      schema: route({
        summary: 'Complete a password reset',
        description:
          'Single-use token, 60-minute TTL. On success **every** session for the user is revoked and ' +
          'all other pending reset tokens are invalidated, then a notification email is sent as an ' +
          'out-of-band tamper signal.',
        tags: [TAGS.account],
        operationId: 'resetPassword',
        rateLimit: '20 per hour per IP',
        body: resetPasswordBody,
        response: { 200: okResponse, 410: errorSchema, 422: errorSchema },
      }),
    },
    async () => {
      throw errors.notImplemented('§5.7 (Phase 1)');
    },
  );

  app.post(
    '/auth/password/change',
    {
      schema: route({
        summary: 'Change your password',
        description:
          'Requires the current password even though you are already signed in — that is what stops ' +
          'a drive-by XSS or CSRF foothold from becoming a permanent takeover. All *other* sessions ' +
          'are revoked on success.',
        tags: [TAGS.account],
        operationId: 'changePassword',
        security: cookieSecurity,
        body: changePasswordBody,
        response: { 200: okResponse, 401: errorSchema, 403: errorSchema, 422: errorSchema },
      }),
    },
    async () => {
      throw errors.notImplemented('§5.8 (Phase 1)');
    },
  );
}
