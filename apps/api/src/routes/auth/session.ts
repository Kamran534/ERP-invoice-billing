/**
 * Session lifecycle: register, login, refresh, logout, devices, password.
 *
 * The contracts, status codes, rate limits and security requirements here are
 * final — they are what the OpenAPI document publishes and what clients build
 * against.
 *
 * The handlers are thin on purpose. Every decision lives in a `@auth/core`
 * use-case; what belongs here is transport — which cookie, which status code,
 * what shape goes on the wire. If a rule appears in this file, it is in the wrong
 * file. The three password routes (§5.7, §5.8) still answer `501`.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  AuthError,
  errors,
  listSessions,
  login,
  logout,
  logoutAll,
  register,
  resendVerification,
  revokeSession,
  rotateRefreshToken,
  verifyEmail,
  type IssuedSession,
  type User,
} from '@auth/core';
import { route } from '../../lib/schema.js';
import { TAGS } from '../../plugins/swagger.js';
import {
  authOutcome,
  changePasswordBody,
  deviceSession,
  emailField,
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
import {
  clearSessionCookies,
  readRefreshToken,
  setSessionCookies,
} from '../../lib/cookies.js';
import {
  presentDeviceSession,
  presentSession,
  presentUser,
  requestContext,
} from '../../lib/present.js';

/**
 * Either transport satisfies these routes: cookies + CSRF header, or a bearer
 * token. OpenAPI reads the array as OR and each object's keys as AND.
 */
const cookieSecurity: Array<Record<string, string[]>> = [
  { cookieAuth: [], csrfToken: [] },
  { bearerAuth: [] },
];

export async function sessionRoutes(app: FastifyInstance): Promise<void> {
  const { auth, authDeps } = app;

  /**
   * Turns an issued session into a reply: cookies set, body shaped for the
   * transport. Every path that authenticates someone goes through here, so a new
   * flow cannot forget the CSRF cookie or set the refresh cookie at the wrong
   * `Path`.
   */
  async function respondWithSession(
    reply: Parameters<typeof setSessionCookies>[0],
    issued: IssuedSession,
    user: User,
  ) {
    setSessionCookies(reply, auth.config, {
      accessToken: issued.accessToken,
      refreshToken: issued.refreshToken,
      expiresIn: issued.expiresIn,
      // A fresh, unguessable value per session. It is not a secret in the usual
      // sense — an attacker just must not be able to *read* it cross-origin.
      csrfToken: authDeps.newSecret('csrf'),
    });

    const factors = await auth.repos.mfa.listConfirmedFactors(user.id);
    return presentSession(auth.config, issued, presentUser(user, factors.length > 0));
  }

  /**
   * Step-up (§5.4.7): a sensitive action needs a second factor proven recently,
   * not merely a live session.
   *
   * ⚑ Partial. A user with confirmed factors must have satisfied one inside
   * `stepUpMaxAge`; a password-only user currently passes, because re-authenticating
   * by password needs the `/auth/reauth` endpoint that lands with §5.8. Enforcing
   * strictly today would make `logout-all` unreachable for everyone rather than
   * safer for anyone.
   */
  async function assertStepUp(session: { userId: string; mfaSatisfiedAt: Date | null }) {
    const factors = await auth.repos.mfa.listConfirmedFactors(session.userId);
    if (factors.length === 0) return;

    const satisfiedAt = session.mfaSatisfiedAt?.getTime() ?? 0;
    if (Date.now() - satisfiedAt > auth.config.tokens.stepUpMaxAge) {
      throw errors.reauthRequired(['totp', 'webauthn', 'email_otp']);
    }
  }

  /** The session behind the presented access token, or 401. */
  async function currentSession(request: FastifyRequest) {
    const claims = request.auth!;
    const session = await auth.repos.sessions.findById(claims.sid);
    if (!session || session.revokedAt) {
      throw new AuthError('SESSION_REVOKED', 'This session has been signed out');
    }
    return session;
  }

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
    async (request, reply) => {
      const body = request.body as { email: string; password: string; name?: string };
      const result = await register(auth, authDeps, { ...body, ...requestContext(request) });

      // 202, not 201: nothing usable has been created from the caller's point of
      // view, and a 201 would differ observably between "new" and "taken".
      return reply.code(202).send({
        status: result.status,
        message: 'If that address can be registered, a verification link is on its way.',
      });
    },
  );

  // ── Email verification ──────────────────────────────────────────────────
  app.post(
    '/auth/verify-email',
    {
      config: { rateLimit: { max: 20, timeWindow: '1 hour' } },
      schema: route({
        summary: 'Confirm an email address',
        description:
          'Consumes the token from the verification link and activates the account.\n\n' +
          'The token is single-use: a second call with the same token returns `410`, and so does a ' +
          'token that never existed or has expired. The three cases are deliberately ' +
          'indistinguishable — your UI should offer a resend for all of them.\n\n' +
          '⚑ No session is issued. Verifying proves control of a mailbox, not of a password; ' +
          'the client sends the user to log in.',
        tags: [TAGS.auth],
        operationId: 'verifyEmail',
        rateLimit: '20 per hour per IP',
        body: z.object({ token: z.string().min(20) }),
        response: { 200: okResponse, 410: errorSchema },
      }),
    },
    async (request) => {
      const { token } = request.body as { token: string };
      await verifyEmail(auth, authDeps, { token, ...requestContext(request) });
      return { ok: true as const };
    },
  );

  app.post(
    '/auth/resend-verification',
    {
      config: { rateLimit: { max: 5, timeWindow: '1 hour' } },
      schema: route({
        summary: 'Send the verification link again',
        description:
          'Always answers `202`, whether or not the address has an account and whether or not it ' +
          'is already verified — this endpoint sends mail on demand, so an honest answer would ' +
          'make it both an enumeration oracle and a way to have us mail a stranger repeatedly.\n\n' +
          'Sending a new link invalidates any previous one.',
        tags: [TAGS.auth],
        operationId: 'resendVerification',
        rateLimit: '5 per hour per IP',
        body: z.object({ email: emailField }),
        response: { 202: registerResponse },
      }),
    },
    async (request, reply) => {
      const { email } = request.body as { email: string };
      const result = await resendVerification(auth, authDeps, {
        email,
        ...requestContext(request),
      });
      return reply.code(202).send({
        status: result.status,
        message: 'If that address needs verifying, a new link is on its way.',
      });
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
    async (request, reply) => {
      const body = request.body as { email: string; password: string; rememberDevice?: boolean };
      const result = await login(auth, authDeps, {
        email: body.email,
        password: body.password,
        trustedDeviceToken: request.cookies[auth.config.cookies.names.trustedDevice] ?? null,
        ...requestContext(request),
      });

      if (result.status === 'mfa_required') {
        // ⚑ 200, and no cookies. The first factor passed; nothing is
        // authenticated. Setting a cookie here would make the second factor
        // optional for anyone who ignores the response body.
        return reply.code(200).send({
          status: 'mfa_required',
          mfaToken: result.mfaToken,
          availableMethods: result.availableMethods,
        });
      }

      const session = await respondWithSession(reply, result.session, result.user);

      if (result.mfaEnrollmentRequired) {
        return reply.code(200).send({
          status: 'mfa_enrollment_required',
          session,
          enrollBy: result.mfaGraceEndsAt?.toISOString() ?? null,
        });
      }
      return reply.code(200).send({ status: 'authenticated', session });
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
    async (request, reply) => {
      const presented = readRefreshToken(
        request,
        auth.config,
        request.body as { refreshToken?: string } | undefined,
      );
      if (!presented) throw errors.invalidRefreshToken();

      let rotated;
      try {
        rotated = await rotateRefreshToken(auth, authDeps, {
          presentedSecret: presented,
          ...requestContext(request),
        });
      } catch (error) {
        // ⚑ Clear the cookies on a dead session, but never on a 409. A client
        // that loses the multi-tab race must keep its cookies — it is about to
        // retry and pick up the winner's rotation.
        if (error instanceof AuthError && error.status === 401) {
          clearSessionCookies(reply, auth.config);
        }
        throw error;
      }

      setSessionCookies(reply, auth.config, {
        accessToken: rotated.accessToken,
        refreshToken: rotated.refreshToken,
        expiresIn: rotated.expiresIn,
        csrfToken: authDeps.newSecret('csrf'),
      });

      const bearer = auth.config.cookies.mode !== 'cookie';
      return reply.code(200).send({
        ...(bearer
          ? { accessToken: rotated.accessToken, refreshToken: rotated.refreshToken }
          : {}),
        expiresIn: rotated.expiresIn,
      });
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
    async (request, reply) => {
      // ⚑ No `requireAuth`. Logout must succeed for an expired or already-revoked
      // session, or a client whose token just lapsed can never clear its cookies
      // — and the 401 would tell an unauthenticated caller nothing useful anyway.
      const token = request.cookies[auth.config.cookies.names.access];
      const claims = token ? await app.tokens.verifyAccess(token).catch(() => null) : null;

      if (claims) {
        await logout(auth, { sessionId: claims.sid, ...requestContext(request) });
      }

      clearSessionCookies(reply, auth.config);
      return reply.code(204).send();
    },
  );

  app.post(
    '/auth/logout-all',
    {
      preHandler: app.requireAuth,
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
    async (request, reply) => {
      const session = await currentSession(request);
      await assertStepUp(session);

      const { revokedSessions } = await logoutAll(auth, {
        userId: session.userId,
        ...requestContext(request),
      });

      // The caller's own session is included, so its cookies go too.
      clearSessionCookies(reply, auth.config);
      return reply.code(200).send({ revokedSessions });
    },
  );

  // ── Current user ─────────────────────────────────────────────────────────
  app.get(
    '/auth/me',
    {
      // ⚑ `requireAuth`, not `requireFullAuth`. A session quarantined by the 2FA
      // policy must still be able to read itself — this is the endpoint the
      // enrollment screen calls to find out that it is quarantined (§5.4.6).
      preHandler: app.requireAuth,
      schema: route({
        summary: 'Current user, org context and permissions',
        description:
          'Who you are, read live from the database — not from the token.\n\n' +
          '`permissions` is the effective set for your organization. Authorize your UI from it, ' +
          'but never treat it as an enforcement boundary; the server re-checks every call.\n\n' +
          '⚑ **`staleToken: true`** means your access token was issued before your current ' +
          'organization or role, so the API will still refuse what this response says you can do. ' +
          'It happens right after creating an organization or accepting an invitation. Call ' +
          '`POST /auth/token/refresh`, or use the token those endpoints hand back.',
        tags: [TAGS.auth],
        operationId: 'getMe',
        security: cookieSecurity,
        response: {
          200: z.object({
            user: publicUser,
            org: z.object({ id: uuidField, name: z.string(), role: z.string() }).nullable(),
            permissions: z.array(z.string()),
            staleToken: z.boolean().meta({
              description:
                'Your token predates your current org or role. Refresh before acting on the ' +
                'permissions above.',
            }),
            amr: z.array(z.string()),
            mfaSatisfiedAt: z.string().nullable().meta({
              description: 'Drives step-up: if this is older than 15 minutes, sensitive calls will 403.',
            }),
          }),
          401: errorSchema,
        },
      }),
    },
    async (request) => {
      const session = await currentSession(request);
      const user = await auth.repos.users.findById(session.userId);
      if (!user) throw new AuthError('ACCOUNT_INACTIVE', 'Account is not active');

      const factors = await auth.repos.mfa.listConfirmedFactors(user.id);

      // ⚑ Live from the database, not from the token — and `staleToken` when they
      // disagree.
      //
      // An earlier version read `claims.org` and `claims.perms`, reasoning that
      // /auth/me should describe the credential in hand. It is defensible and it
      // is baffling in practice: create an organization, call /auth/me, and be
      // told you belong to nothing — because the token was minted before the
      // organization existed and JWTs do not learn.
      //
      // So this answers "who am I" with the truth, and flags the one case where
      // the API will refuse what that truth implies. A client seeing `staleToken`
      // refreshes; a client ignoring it gets a `403` it can recover from. Both are
      // better than a correct answer nobody can interpret.
      const claims = request.auth!;
      const membership = await auth.repos.memberships.findActiveForUser(user.id);
      const permissions = membership
        ? await auth.repos.roles.permissionsFor(membership.role.id)
        : [];

      return {
        user: presentUser(user, factors.length > 0),
        org: membership
          ? { id: membership.org.id, name: membership.org.name, role: membership.role.key }
          : null,
        permissions,
        staleToken: (claims.org ?? null) !== (membership?.org.id ?? null),
        amr: session.amr,
        mfaSatisfiedAt: session.mfaSatisfiedAt?.toISOString() ?? null,
      };
    },
  );

  // ── Devices ──────────────────────────────────────────────────────────────
  app.get(
    '/auth/sessions',
    {
      preHandler: app.requireFullAuth,
      schema: route({
        summary: 'List signed-in devices',
        tags: [TAGS.auth],
        operationId: 'listSessions',
        security: cookieSecurity,
        response: { 200: z.object({ sessions: z.array(deviceSession) }), 401: errorSchema },
      }),
    },
    async (request) => {
      const session = await currentSession(request);
      const views = await listSessions(auth, session.userId, session.id);
      return { sessions: views.map(presentDeviceSession) };
    },
  );

  app.delete(
    '/auth/sessions/:id',
    {
      preHandler: app.requireFullAuth,
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
    async (request, reply) => {
      const session = await currentSession(request);
      const { id } = request.params as { id: string };

      await revokeSession(auth, {
        userId: session.userId,
        sessionId: id,
        ...requestContext(request),
      });

      // Revoking your own session is equivalent to logging out, so the cookies
      // must go with it — otherwise the client keeps a refresh token for a
      // session the server has already killed.
      if (id === session.id) clearSessionCookies(reply, auth.config);
      return reply.code(204).send();
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
