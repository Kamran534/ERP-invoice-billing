/**
 * OTP login (§5.11) and two-factor authentication (§5.4).
 *
 * Both share one engine: generate → deliver → attempt-capped verify. The only
 * difference is `purpose`, which is why OTP-as-login (Phase 3) makes email 2FA
 * (Phase 4) nearly free.
 *
 * Handlers are Phase 3/4 work and answer 501 for now; the contracts are final.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  AuthError,
  confirmTotpEnrollment,
  errors,
  getMfaState,
  listTrustedDevices,
  regenerateRecoveryCodes,
  removeFactor,
  revokeTrustedDevice,
  startTotpEnrollment,
  verifyMfaChallenge,
} from '@auth/core';
import { route, errorSchema } from '../../lib/schema.js';
import { TAGS } from '../../plugins/swagger.js';
import {
  authOutcome,
  mfaStateResponse,
  mfaVerifyBody,
  okResponse,
  otpRequestBody,
  otpRequestResponse,
  otpVerifyBody,
  totpConfirmBody,
  totpSetupResponse,
  trustedDeviceSummary,
  uuidField,
} from '../../schemas/auth.js';
import { setSessionCookies } from '../../lib/cookies.js';
import { presentSession, presentUser, requestContext } from '../../lib/present.js';

const cookieSecurity: Array<Record<string, string[]>> = [
  { cookieAuth: [], csrfToken: [] },
  { bearerAuth: [] },
];
/** The challenge token is the only credential these accept — no session. */
const challengeSecurity: Array<Record<string, string[]>> = [{ mfaChallenge: [] }];

export async function otpRoutes(app: FastifyInstance): Promise<void> {
  const { auth, authDeps } = app;

  /**
   * The session behind the presented access token.
   *
   * These routes use `requireAuth` rather than `requireFullAuth`: a session
   * quarantined by the 2FA policy has to reach the enrollment endpoints, which is
   * the whole point of the quarantine (§5.4.6).
   */
  async function currentSession(request: FastifyRequest) {
    const session = await auth.repos.sessions.findById(request.auth!.sid);
    if (!session || session.revokedAt) {
      throw new AuthError('SESSION_REVOKED', 'This session has been signed out');
    }
    return session;
  }

  /**
   * §5.4.7 — a sensitive action needs a factor proven recently, not just a live
   * session.
   *
   * ⚑ A trusted device never satisfies this. `login` records `amr: ['pwd','device']`
   * and leaves `mfaSatisfiedAt` null precisely so that a stolen laptop can read the
   * account but cannot change what protects it (§5.4.5).
   *
   * ⚑ Still partial: a user with no confirmed factor passes, because password
   * re-authentication needs `/auth/reauth`, which lands with §5.8. Refusing them
   * today would make enrollment itself unreachable.
   */
  async function assertStepUp(session: { userId: string; mfaSatisfiedAt: Date | null }) {
    const factors = await auth.repos.mfa.listConfirmedFactors(session.userId);
    if (factors.length === 0) return;

    const satisfiedAt = session.mfaSatisfiedAt?.getTime() ?? 0;
    if (Date.now() - satisfiedAt > auth.config.tokens.stepUpMaxAge) {
      throw errors.reauthRequired(['totp', 'webauthn', 'email_otp']);
    }
  }

  // ── OTP as a primary factor ──────────────────────────────────────────────
  app.post(
    '/auth/otp/request',
    {
      config: { rateLimit: { max: 10, timeWindow: '1 hour' } },
      schema: route({
        summary: 'Send a one-time sign-in code',
        description:
          'Emails (or texts) a 6-digit code and returns a `challengeId` to pass to ' +
          '`/auth/otp/verify`.\n\n' +
          '⚑ **Enumeration-safe by construction.** A `challengeId` is returned even when no account ' +
          'exists — the response body, status and latency are identical, and no message is sent. ' +
          'A client cannot use this endpoint to test whether an address is registered.\n\n' +
          '**Client rules**\n' +
          '* Drive your resend countdown from `resendAfter`, never from a local timer.\n' +
          '* Requesting again invalidates the previous code: exactly one code is live per address, ' +
          'so "the last code I received" is unambiguous.\n' +
          '* The code must be redeemed from the same browser and network that requested it — this ' +
          'is what defeats "attacker calls you and asks you to read out the code".',
        tags: [TAGS.otp],
        operationId: 'requestOtp',
        rateLimit: '10 per hour per IP; 3 per hour per destination; 1 per 60s',
        body: otpRequestBody,
        response: { 202: otpRequestResponse, 429: errorSchema },
      }),
    },
    async () => {
      throw errors.notImplemented('§5.11.1 (Phase 3)');
    },
  );

  app.post(
    '/auth/otp/verify',
    {
      config: { rateLimit: { max: 30, timeWindow: '5 minutes' } },
      schema: route({
        summary: 'Redeem a one-time code',
        description:
          'Same three-way `status` contract as `/auth/login` — a user with 2FA enabled gets ' +
          '`mfa_required`, because an email code is one factor no matter which endpoint issued it.\n\n' +
          'Failure returns `401 INVALID_CODE` with `attemptsRemaining`. After 5 wrong attempts the ' +
          '**challenge is destroyed**, not merely the attempt: further tries return ' +
          '`429 CHALLENGE_EXHAUSTED` and a new code must be requested. Show that state instead of ' +
          'leaving a dead code box on screen.\n\n' +
          'Redeeming a code sent to an unverified address also verifies that address — receiving the ' +
          'code proves control of the mailbox.',
        tags: [TAGS.otp],
        operationId: 'verifyOtp',
        rateLimit: '30 per 5 min per IP; 5 attempts per challenge (hard)',
        body: otpVerifyBody,
        response: { 200: authOutcome, 401: errorSchema, 410: errorSchema, 429: errorSchema },
      }),
    },
    async () => {
      throw errors.notImplemented('§5.11.2 (Phase 3)');
    },
  );

  // ── OTP as a second factor ───────────────────────────────────────────────
  app.post(
    '/auth/mfa/otp/send',
    {
      config: { rateLimit: { max: 20, timeWindow: '1 hour' } },
      schema: route({
        summary: 'Send a code as the second factor',
        description:
          'For a pending 2FA challenge, when the user picks "email me a code" instead of their ' +
          'authenticator app. Authorized by the `mfaToken`, not by a session.\n\n' +
          '⚑ Rejected with `VALIDATION_FAILED` when the first factor was already an email OTP — the ' +
          'same channel cannot count twice.',
        tags: [TAGS.otp],
        operationId: 'sendMfaOtp',
        rateLimit: '20 per hour per IP; 3 per challenge',
        security: challengeSecurity,
        body: z.object({ mfaToken: z.string(), channel: z.enum(['email', 'sms']).default('email') }),
        response: { 202: otpRequestResponse, 400: errorSchema, 401: errorSchema },
      }),
    },
    async () => {
      throw errors.notImplemented('§5.11 (Phase 3)');
    },
  );

  app.post(
    '/auth/mfa/verify',
    {
      config: { rateLimit: { max: 30, timeWindow: '5 minutes' } },
      schema: route({
        summary: 'Complete two-factor authentication',
        description:
          'Exchanges a valid `mfaToken` + second factor for a real session.\n\n' +
          '* **TOTP** — ±1 timestep of drift is accepted, but a code cannot be replayed inside its ' +
          'own validity window.\n' +
          '* **Recovery code** — single use. Using one emails the user and prompts regeneration.\n' +
          '* 5 attempts per challenge, then the challenge dies and login must restart.\n\n' +
          '`rememberDevice: true` sets a trusted-device cookie, if the server enables it. That trust ' +
          'never satisfies step-up, and dies on any credential change (§5.4.5).',
        tags: [TAGS.otp],
        operationId: 'verifyMfa',
        rateLimit: '30 per 5 min per IP; 5 attempts per challenge (hard)',
        security: challengeSecurity,
        body: mfaVerifyBody,
        response: { 200: authOutcome, 401: errorSchema, 429: errorSchema },
      }),
    },
    async (request, reply) => {
      const body = request.body as {
        mfaToken: string;
        method: 'totp' | 'email_otp' | 'sms_otp' | 'recovery';
        code: string;
        rememberDevice?: boolean;
      };

      // Email and SMS as a *second* factor go through the OTP engine (§5.11),
      // which is a later phase. Saying so beats a generic validation error.
      if (body.method !== 'totp' && body.method !== 'recovery') {
        throw errors.notImplemented('§5.11 (Phase 3)');
      }

      const result = await verifyMfaChallenge(auth, authDeps, {
        mfaToken: body.mfaToken,
        method: body.method,
        code: body.code,
        rememberDevice: body.rememberDevice ?? false,
        ...requestContext(request),
      });

      setSessionCookies(reply, auth.config, {
        accessToken: result.session.accessToken,
        refreshToken: result.session.refreshToken,
        expiresIn: result.session.expiresIn,
        csrfToken: authDeps.newSecret('csrf'),
      });

      if (result.trustedDeviceToken) {
        const { names, sameSite, secure, domain } = auth.config.cookies;
        reply.setCookie(names.trustedDevice, result.trustedDeviceToken, {
          httpOnly: true,
          secure,
          sameSite,
          ...(domain ? { domain } : {}),
          path: '/',
          // ⚑ Matches the row's absolute expiry. A cookie that outlived the record
          // would send a token the server has already forgotten, on every login.
          maxAge: Math.floor(auth.config.mfa.trustedDevices.ttl / 1_000),
        });
      }

      const factors = await auth.repos.mfa.listConfirmedFactors(result.user.id);
      return reply.code(200).send({
        status: 'authenticated',
        session: presentSession(
          auth.config,
          result.session,
          presentUser(result.user, factors.length > 0),
        ),
      });
    },
  );

  // ── Enrollment ───────────────────────────────────────────────────────────
  app.get(
    '/auth/mfa',
    {
      preHandler: app.requireAuth,
      schema: route({
        summary: 'Current 2FA state',
        description:
          'What the account-security screen renders from: enforcement policy, whether this user is ' +
          'required to enroll, the confirmed factors, and how many recovery codes remain (warn the ' +
          'user at ≤2).',
        tags: [TAGS.otp],
        operationId: 'getMfaState',
        security: cookieSecurity,
        response: { 200: mfaStateResponse, 401: errorSchema },
      }),
    },
    async (request) => {
      const session = await currentSession(request);
      const state = await getMfaState(auth, session.userId);
      return {
        ...state,
        factors: state.factors.map((factor) => ({
          ...factor,
          lastUsedAt: factor.lastUsedAt?.toISOString() ?? null,
          createdAt: factor.createdAt.toISOString(),
        })),
      };
    },
  );

  app.post(
    '/auth/mfa/totp/setup',
    {
      preHandler: app.requireAuth,
      schema: route({
        summary: 'Begin authenticator-app enrollment',
        description:
          'Returns the secret, an `otpauth://` provisioning URI for the QR code, and (after ' +
          'confirmation) the recovery codes. The secret is shown **once** and is not retrievable ' +
          'again.\n\n' +
          '⚑ The factor is inactive until `/auth/mfa/totp/confirm` succeeds — an unconfirmed factor ' +
          'never satisfies a challenge, and is purged after 15 minutes. Requires step-up.',
        tags: [TAGS.otp],
        operationId: 'setupTotp',
        security: cookieSecurity,
        response: { 200: totpSetupResponse, 401: errorSchema, 403: errorSchema },
      }),
    },
    async (request) => {
      const session = await currentSession(request);
      await assertStepUp(session);

      const enrollment = await startTotpEnrollment(auth, {
        userId: session.userId,
        ...requestContext(request),
      });

      // ⚑ `recoveryCodes` is empty here and populated by /confirm. Handing them out
      // now would leave a working bypass behind an enrolment the user abandoned.
      return { ...enrollment, recoveryCodes: [] };
    },
  );

  app.post(
    '/auth/mfa/totp/confirm',
    {
      preHandler: app.requireAuth,
      config: { rateLimit: { max: 20, timeWindow: '5 minutes' } },
      schema: route({
        summary: 'Activate the authenticator factor',
        description:
          'Proves the user can generate a valid code before 2FA is switched on — otherwise a ' +
          'mis-scanned QR locks them out of their own account. Returns the recovery codes.',
        tags: [TAGS.otp],
        operationId: 'confirmTotp',
        security: cookieSecurity,
        body: totpConfirmBody,
        response: {
          200: z.object({ ok: z.literal(true), recoveryCodes: z.array(z.string()) }),
          401: errorSchema,
        },
      }),
    },
    async (request) => {
      const session = await currentSession(request);
      const body = request.body as { factorId: string; code: string };

      const { recoveryCodes } = await confirmTotpEnrollment(auth, authDeps, {
        userId: session.userId,
        factorId: body.factorId,
        code: body.code,
        // Kept alive while every other session is revoked — signing the user out of
        // the tab they just enrolled from would be a strange reward.
        currentSessionId: session.id,
        ...requestContext(request),
      });

      return { ok: true as const, recoveryCodes };
    },
  );

  app.delete(
    '/auth/mfa/factors/:id',
    {
      preHandler: app.requireAuth,
      schema: route({
        summary: 'Remove a second factor',
        description:
          'Requires step-up with a **currently active** factor — not a trusted device. Revokes all ' +
          'trusted devices. Returns `403 MFA_REQUIRED_BY_POLICY` when org policy mandates 2FA and ' +
          'this is the last factor.',
        tags: [TAGS.otp],
        operationId: 'removeMfaFactor',
        security: cookieSecurity,
        params: z.object({ id: uuidField }),
        response: { 204: null, 401: errorSchema, 403: errorSchema, 404: errorSchema },
      }),
    },
    async (request, reply) => {
      const session = await currentSession(request);
      await assertStepUp(session);

      const { id } = request.params as { id: string };
      await removeFactor(auth, {
        userId: session.userId,
        factorId: id,
        ...requestContext(request),
      });
      return reply.code(204).send();
    },
  );

  app.post(
    '/auth/mfa/recovery-codes',
    {
      preHandler: app.requireAuth,
      config: { rateLimit: { max: 5, timeWindow: '1 hour' } },
      schema: route({
        summary: 'Regenerate recovery codes',
        description:
          'Issues a fresh set and atomically invalidates every previous code. Requires step-up. ' +
          'Shown once.',
        tags: [TAGS.otp],
        operationId: 'regenerateRecoveryCodes',
        security: cookieSecurity,
        response: {
          200: z.object({ recoveryCodes: z.array(z.string()) }),
          401: errorSchema,
          403: errorSchema,
        },
      }),
    },
    async (request) => {
      const session = await currentSession(request);
      await assertStepUp(session);

      const recoveryCodes = await regenerateRecoveryCodes(auth, authDeps, {
        userId: session.userId,
        ...requestContext(request),
      });
      return { recoveryCodes };
    },
  );

  // ── Trusted devices ──────────────────────────────────────────────────────
  app.get(
    '/auth/trusted-devices',
    {
      preHandler: app.requireAuth,
      schema: route({
        summary: 'List remembered devices',
        description:
          'Devices currently allowed to skip 2FA. Present this list prominently — a "remember me" ' +
          'feature the user cannot see or revoke is a 2FA bypass with a friendly name.',
        tags: [TAGS.otp],
        operationId: 'listTrustedDevices',
        security: cookieSecurity,
        response: { 200: z.object({ devices: z.array(trustedDeviceSummary) }), 401: errorSchema },
      }),
    },
    async (request) => {
      const session = await currentSession(request);
      const devices = await listTrustedDevices(auth, session.userId);
      return {
        devices: devices.map((device) => ({
          ...device,
          lastUsedAt: device.lastUsedAt?.toISOString() ?? null,
          expiresAt: device.expiresAt.toISOString(),
        })),
      };
    },
  );

  app.delete(
    '/auth/trusted-devices/:id',
    {
      preHandler: app.requireAuth,
      schema: route({
        summary: 'Forget a remembered device',
        tags: [TAGS.otp],
        operationId: 'revokeTrustedDevice',
        security: cookieSecurity,
        params: z.object({ id: uuidField }),
        response: { 204: null, 401: errorSchema, 404: errorSchema },
      }),
    },
    async (request, reply) => {
      const session = await currentSession(request);
      const { id } = request.params as { id: string };
      await revokeTrustedDevice(auth, {
        userId: session.userId,
        deviceId: id,
        ...requestContext(request),
      });
      return reply.code(204).send();
    },
  );

  app.delete(
    '/auth/trusted-devices',
    {
      preHandler: app.requireAuth,
      schema: route({
        summary: 'Forget all remembered devices',
        description: 'Requires step-up. Every device must complete 2FA again on next sign-in.',
        tags: [TAGS.otp],
        operationId: 'revokeAllTrustedDevices',
        security: cookieSecurity,
        response: { 200: okResponse, 401: errorSchema, 403: errorSchema },
      }),
    },
    async (request) => {
      const session = await currentSession(request);
      await assertStepUp(session);

      await auth.repos.trustedDevices.revokeAllForUser(session.userId);
      return { ok: true as const };
    },
  );
}
