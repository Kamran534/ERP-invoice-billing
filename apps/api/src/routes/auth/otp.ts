/**
 * OTP login (§5.11) and two-factor authentication (§5.4).
 *
 * Both share one engine: generate → deliver → attempt-capped verify. The only
 * difference is `purpose`, which is why OTP-as-login (Phase 3) makes email 2FA
 * (Phase 4) nearly free.
 *
 * Handlers are Phase 3/4 work and answer 501 for now; the contracts are final.
 */

import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { errors } from '@auth/core';
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

const cookieSecurity: Array<Record<string, string[]>> = [
  { cookieAuth: [], csrfToken: [] },
  { bearerAuth: [] },
];
/** The challenge token is the only credential these accept — no session. */
const challengeSecurity: Array<Record<string, string[]>> = [{ mfaChallenge: [] }];

export async function otpRoutes(app: FastifyInstance): Promise<void> {
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
      throw errors.notImplemented('§5.4.3 (Phase 4)');
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
    async () => {
      throw errors.notImplemented('§5.4.3 (Phase 4)');
    },
  );

  // ── Enrollment ───────────────────────────────────────────────────────────
  app.get(
    '/auth/mfa',
    {
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
    async () => {
      throw errors.notImplemented('§5.4 (Phase 4)');
    },
  );

  app.post(
    '/auth/mfa/totp/setup',
    {
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
    async () => {
      throw errors.notImplemented('§5.4.1 (Phase 4)');
    },
  );

  app.post(
    '/auth/mfa/totp/confirm',
    {
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
    async () => {
      throw errors.notImplemented('§5.4.1 (Phase 4)');
    },
  );

  app.delete(
    '/auth/mfa/factors/:id',
    {
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
    async () => {
      throw errors.notImplemented('§5.4.8 (Phase 4)');
    },
  );

  app.post(
    '/auth/mfa/recovery-codes',
    {
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
    async () => {
      throw errors.notImplemented('§5.4.4 (Phase 4)');
    },
  );

  // ── Trusted devices ──────────────────────────────────────────────────────
  app.get(
    '/auth/trusted-devices',
    {
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
    async () => {
      throw errors.notImplemented('§5.4.5 (Phase 4)');
    },
  );

  app.delete(
    '/auth/trusted-devices/:id',
    {
      schema: route({
        summary: 'Forget a remembered device',
        tags: [TAGS.otp],
        operationId: 'revokeTrustedDevice',
        security: cookieSecurity,
        params: z.object({ id: uuidField }),
        response: { 204: null, 401: errorSchema, 404: errorSchema },
      }),
    },
    async () => {
      throw errors.notImplemented('§5.4.5 (Phase 4)');
    },
  );

  app.delete(
    '/auth/trusted-devices',
    {
      schema: route({
        summary: 'Forget all remembered devices',
        description: 'Requires step-up. Every device must complete 2FA again on next sign-in.',
        tags: [TAGS.otp],
        operationId: 'revokeAllTrustedDevices',
        security: cookieSecurity,
        response: { 200: okResponse, 401: errorSchema, 403: errorSchema },
      }),
    },
    async () => {
      throw errors.notImplemented('§5.4.5 (Phase 4)');
    },
  );
}
