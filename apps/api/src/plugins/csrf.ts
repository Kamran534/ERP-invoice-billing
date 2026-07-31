/**
 * CSRF, and the guard that turns an access token into a caller (§8.3, §5.4.6).
 *
 * Both live here because they are two halves of the same question — "is this
 * request allowed to act as this user?" — and because the ordering between them
 * matters: CSRF is checked first, on every write, before anything reads a session.
 */

import fp from 'fastify-plugin';
import { AuthError, errors, permits, type AccessClaims } from '@auth/core';
import { timingSafeEquals } from '@auth/crypto';
import { readAccessToken, readCookie } from '../lib/cookies.js';

declare module 'fastify' {
  interface FastifyInstance {
    /** preHandler: 401s unless a valid access token is present. */
    requireAuth: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    /**
     * preHandler: `requireAuth`, plus a refusal for a session quarantined by the
     * 2FA enrollment policy. Use on everything except the enrollment endpoints.
     */
    requireFullAuth: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    /**
     * preHandler factory: `requireFullAuth`, plus the named permission from the
     * token's `perms` claim (§10.1–§10.2).
     */
    requirePermission: (
      permission: string,
    ) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
  interface FastifyRequest {
    /** Present once `requireAuth` has run. */
    auth?: AccessClaims & { iat: number; exp: number; jti: string };
  }
}

import type { FastifyReply, FastifyRequest } from 'fastify';

/** Methods that cannot change state, so they need no CSRF token. */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Routes that must work before a CSRF cookie exists. Logging in is the obvious
 * one: the client has no cookie to echo yet.
 *
 * ⚑ These are safe to exempt only because none of them acts on an *existing*
 * session using ambient credentials — that is the property that makes a route
 * CSRF-able, not whether it happens to be under /auth.
 */
const CSRF_EXEMPT = new Set([
  '/auth/register',
  '/auth/login',
  '/auth/verify-email',
  '/auth/resend-verification',
  '/auth/forgot-password',
  '/auth/reset-password',
  '/auth/otp/request',
  '/auth/otp/verify',
  '/auth/mfa/verify',
]);

export const csrfPlugin = fp(
  async (app) => {
    const { config } = app.auth;

    // ── Double-submit ──────────────────────────────────────────────────────
    app.addHook('onRequest', async (request) => {
      if (config.cookies.mode === 'bearer') return;
      if (SAFE_METHODS.has(request.method)) return;

      const path = request.url.split('?')[0] ?? '';
      if (CSRF_EXEMPT.has(path)) return;

      // ⚑ An explicit `Authorization: Bearer` is not ambient authority, so there is
      // nothing for CSRF to defend.
      //
      // CSRF exists because a browser attaches cookies to cross-site requests
      // whether or not the page meant it. It does not attach an `Authorization`
      // header: setting one cross-origin requires a preflight the target has to
      // permit, and the attacker would need the token itself — at which point CSRF
      // is beside the point.
      //
      // This matters in `both` mode, where a caller authenticating by bearer still
      // has session cookies sitting in the same browser. Without this, Swagger UI's
      // Authorize button gets `CSRF_FAILED` on every write: the token is doing the
      // work, and the cookies are only along for the ride.
      //
      // ⚑ Safe only because `readAccessToken` agrees: when a Bearer header is
      // present in a mode that permits it, that is the credential used — it never
      // silently falls back to the cookie if the header is malformed. If those two
      // ever disagree, this becomes a bypass.
      const authorization = request.headers.authorization;
      if (config.cookies.mode !== 'cookie' && authorization?.startsWith('Bearer ')) return;

      const { access, refresh, csrf } = config.cookies.names;
      const cookie = readCookie(request, csrf);

      // ⚑ A request carrying no session cookie at all is skipped, not refused.
      //
      // This is not the "omit the cookie to bypass the check" hole it resembles.
      // A cross-site attacker cannot *remove* the victim's cookies — the browser
      // attaches whatever it holds — so a request with none provably cannot act
      // on an ambient credential, and there is nothing to protect. Refusing it
      // instead breaks the two calls a client must always be able to make with
      // nothing in hand: logging out, and finding out it is logged out.
      //
      // The refresh cookie is checked too, so a request that somehow carries it
      // without the CSRF cookie is still refused rather than waved through.
      const hasSessionCookie =
        cookie !== null ||
        readCookie(request, access) !== null ||
        readCookie(request, refresh) !== null;
      if (!hasSessionCookie) return;

      const header = request.headers['x-csrf-token'];
      if (typeof header !== 'string' || !cookie) {
        throw new AuthError('CSRF_FAILED', 'Missing CSRF token');
      }

      // Constant-time, and length-checked first. `===` on a secret is a habit
      // worth not having even where the timing signal is weak.
      const a = Buffer.from(cookie, 'utf8');
      const b = Buffer.from(header, 'utf8');
      if (a.length !== b.length || !timingSafeEquals(a, b)) {
        throw new AuthError('CSRF_FAILED', 'CSRF token mismatch');
      }
    });

    // ── The guard ──────────────────────────────────────────────────────────
    app.decorate('requireAuth', async (request: FastifyRequest) => {
      const token = readAccessToken(request, config);
      if (!token) throw new AuthError('TOKEN_INVALID', 'Authentication required');

      try {
        request.auth = await app.tokens.verifyAccess(token);
      } catch {
        // ⚑ One answer for expired, tampered, wrong-audience and signed-by-a-key-
        // we-no-longer-have. The client's move is identical in every case — try a
        // refresh, then log in — and the distinctions only help someone probing.
        throw new AuthError('TOKEN_INVALID', 'Invalid or expired token');
      }
    });

    /**
     * ⚑ An HTTP guard is the outer layer, never the only one. Internal callers
     * bypass it entirely, so the service layer re-checks with `permits()` — see
     * §10.2.
     */
    app.decorate(
      'requirePermission',
      (permission: string) => async (request: FastifyRequest, reply: FastifyReply) => {
        await app.requireFullAuth(request, reply);

        const perms = request.auth?.perms ?? [];
        // ⚑ Default deny. No org context means no permissions, which is the correct
        // answer for a user who has not created or joined one yet — not a 500.
        if (!permits(perms, permission)) throw errors.permissionDenied(permission);
      },
    );

    app.decorate('requireFullAuth', async (request: FastifyRequest, reply: FastifyReply) => {
      await app.requireAuth(request, reply);

      // §5.4.6: a quarantined session is real, but reaches only the enrollment
      // endpoints, /auth/me and logout. Those routes use `requireAuth`; every
      // other route uses this and gets the refusal.
      const user = await app.auth.repos.users.findById(request.auth!.sub);
      if (user?.mfaRequiredAt) {
        const factors = await app.auth.repos.mfa.listConfirmedFactors(user.id);
        if (factors.length === 0) {
          throw new AuthError(
            'MFA_ENROLLMENT_REQUIRED',
            'Set up two-factor authentication to continue',
          );
        }
      }
    });
  },
  { name: 'csrf', dependencies: ['auth'] },
);
