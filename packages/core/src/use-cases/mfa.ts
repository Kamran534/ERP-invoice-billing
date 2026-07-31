/**
 * Two-factor authentication (AUTH-MODULE-PLAN.md §5.4).
 *
 * The whole lifecycle: enrol a TOTP factor, confirm it, complete a challenge with
 * it, fall back to a recovery code, and remember a device so the challenge is not
 * asked every time.
 *
 * Three properties are doing most of the work, and each is easy to lose:
 *
 *  1. **An unconfirmed factor never satisfies anything.** A half-finished
 *     enrolment that counted would be a permanent unverified bypass.
 *  2. **A code cannot be used twice**, even inside the drift window that makes
 *     TOTP usable at all. The window is ±30s; without a replay guard that is how
 *     long a shoulder-surfed code stays live.
 *  3. **The challenge dies, not just the attempt.** Five wrong guesses destroy the
 *     challenge, so an attacker with a stolen first factor cannot grind a
 *     six-digit code.
 */

import { AuthError, errors } from '../errors.js';
import { audit, emit, type AuthContext, type RequestContext } from '../context.js';
import type { Amr, MfaFactor, User, UserId } from '../ports.js';
import type { CryptoDeps } from './deps.js';
import { issueSession, type IssuedSession } from './session.js';

/** Unconfirmed factors older than this are swept away (§5.4.1). */
const ENROLLMENT_WINDOW_MS = 15 * 60_000;

/**
 * ⚑ Both or neither. A deployment that wired the TOTP provider but not the key
 * store would enrol factors whose secrets it cannot read back — and would then
 * either crash on every login or, worse, treat the factor as absent and let people
 * in with one factor.
 */
function requireTotp(ctx: AuthContext): {
  totp: NonNullable<AuthContext['totp']>;
  secrets: NonNullable<AuthContext['secrets']>;
} {
  if (!ctx.totp || !ctx.secrets) {
    throw new AuthError('SERVICE_UNAVAILABLE', 'Two-factor authentication is not configured');
  }
  return { totp: ctx.totp, secrets: ctx.secrets };
}

// ── Enrolment ───────────────────────────────────────────────────────────────

export interface StartTotpEnrollmentInput extends RequestContext {
  userId: UserId;
  label?: string | null;
}

export interface TotpEnrollment {
  factorId: string;
  /** ⚑ Returned exactly once. It is never readable again through any endpoint. */
  secret: string;
  provisioningUri: string;
}

export async function startTotpEnrollment(
  ctx: AuthContext,
  input: StartTotpEnrollmentInput,
): Promise<TotpEnrollment> {
  const { totp, secrets } = requireTotp(ctx);
  const user = await ctx.repos.users.findById(input.userId);
  if (!user) throw new AuthError('NOT_FOUND', 'User not found');

  // Clear out abandoned attempts first, so restarting enrolment does not
  // accumulate rows and the 15-minute purge stays meaningful.
  await ctx.repos.mfa.purgeUnconfirmed(
    user.id,
    new Date(ctx.clock.now().getTime() - ENROLLMENT_WINDOW_MS),
  );

  const secret = totp.generateSecret();
  const factor = await ctx.repos.mfa.addFactor({
    userId: user.id,
    type: 'totp',
    label: input.label ?? null,
    // ⚑ AEAD with the purpose bound as associated data, so this ciphertext cannot
    // be replayed into a context that decrypts signing keys.
    secretEnc: secrets.encrypt(secret.base32, 'totp-secret'),
  });

  await audit(ctx, {
    event: 'mfa.enrollment_started',
    actorType: 'user',
    actorUserId: user.id,
    targetType: 'mfa_factor',
    targetId: factor.id,
    ip: input.ip,
    userAgent: input.userAgent,
  });

  return {
    factorId: factor.id,
    secret: secret.base32,
    provisioningUri: totp.provisioningUri(secret, user.email ?? user.id, ctx.config.appName),
  };
}

export interface ConfirmTotpEnrollmentInput extends RequestContext {
  userId: UserId;
  factorId: string;
  code: string;
  /** The caller's session, kept alive when the others are revoked. */
  currentSessionId?: string | null;
}

export interface ConfirmedEnrollment {
  /** ⚑ Shown once, then only hashes remain. */
  recoveryCodes: string[];
}

export async function confirmTotpEnrollment(
  ctx: AuthContext,
  deps: CryptoDeps,
  input: ConfirmTotpEnrollmentInput,
): Promise<ConfirmedEnrollment> {
  const { totp, secrets } = requireTotp(ctx);
  const now = ctx.clock.now();

  const factor = await ctx.repos.mfa.findFactor(input.factorId);
  // ⚑ Ownership before existence, as everywhere else: a distinct answer for
  // "someone else's factor" would let a caller probe for factor ids.
  if (!factor || factor.userId !== input.userId || factor.type !== 'totp') {
    throw new AuthError('NOT_FOUND', 'Factor not found');
  }
  if (factor.confirmedAt) {
    throw new AuthError('CONFLICT', 'This factor is already confirmed');
  }
  if (!factor.secretEnc) {
    throw new AuthError('NOT_FOUND', 'Factor not found');
  }

  const verification = totp.verify(
    { base32: secrets.decrypt(factor.secretEnc, 'totp-secret') },
    input.code,
    now,
  );
  if (!verification.valid) {
    await audit(ctx, {
      event: 'mfa.enrollment_failed',
      actorType: 'user',
      actorUserId: input.userId,
      targetType: 'mfa_factor',
      targetId: factor.id,
      outcome: 'failure',
      ip: input.ip,
    });
    throw new AuthError('INVALID_CODE', 'That code is not right — check your authenticator');
  }

  await ctx.repos.mfa.confirmFactor(factor.id, now);
  if (verification.timestep !== null) {
    // The confirming code must not also work as the first login code.
    await ctx.repos.mfa.advanceTimestep(factor.id, now, verification.timestep);
  }

  const recoveryCodes = await regenerateRecoveryCodes(ctx, deps, {
    userId: input.userId,
    ip: input.ip,
    userAgent: input.userAgent,
    notify: false,
  });

  // ⚑ Turning on 2FA revokes every other session. Whoever was signed in before is
  // exactly who the new factor is meant to exclude.
  const sessions = await ctx.repos.sessions.listActive(input.userId);
  for (const session of sessions) {
    if (session.id === input.currentSessionId) continue;
    await ctx.repos.refreshTokens.revokeChain(session.id, 'mfa_change');
  }
  await ctx.repos.sessions.revokeAllForUser(
    input.userId,
    'mfa_change',
    input.currentSessionId ?? undefined,
  );

  await notifyFactorChange(ctx, input.userId, 'enabled');
  await audit(ctx, {
    event: 'mfa.enabled',
    actorType: 'user',
    actorUserId: input.userId,
    targetType: 'mfa_factor',
    targetId: factor.id,
    ip: input.ip,
    userAgent: input.userAgent,
  });
  await emit(ctx, 'mfa.enabled', { userId: input.userId, factorId: factor.id });

  return { recoveryCodes };
}

// ── Completing a challenge ──────────────────────────────────────────────────

export interface VerifyMfaInput extends RequestContext {
  mfaToken: string;
  method: 'totp' | 'recovery';
  code: string;
  /** Opt-in per login, and only honoured when the deployment allows it. */
  rememberDevice?: boolean;
}

export interface VerifiedMfa {
  user: User;
  session: IssuedSession;
  /** Set only when a device was remembered — the caller puts it in a cookie. */
  trustedDeviceToken: string | null;
}

export async function verifyMfaChallenge(
  ctx: AuthContext,
  deps: CryptoDeps,
  input: VerifyMfaInput,
): Promise<VerifiedMfa> {
  const now = ctx.clock.now();

  // ⚑ Attempt accounting first, and atomically. Reading the challenge, checking
  // the code and then incrementing would let parallel guesses share one attempt.
  const challenge = await ctx.repos.oneTimeTokens.claimAttempt(
    deps.sha256(input.mfaToken),
    'mfa_challenge',
  );
  // One answer for unknown, expired, already-used and out-of-attempts. The client
  // restarts the login in every case, so the distinctions only help an attacker.
  if (!challenge?.userId) {
    throw errors.challengeExhausted();
  }

  // ⚑ Bound to the client that started the login (§5.4.2). A challenge token read
  // out of a URL, a log, or a shoulder-surfed screen is useless elsewhere.
  const expectedBinding = deps.hex(deps.clientBinding(input));
  if (challenge.payload['binding'] !== expectedBinding) {
    await audit(ctx, {
      event: 'mfa.binding_mismatch',
      actorType: 'system',
      actorUserId: challenge.userId,
      outcome: 'failure',
      ip: input.ip,
      userAgent: input.userAgent,
    });
    throw errors.challengeExhausted();
  }

  const user = await ctx.repos.users.findById(challenge.userId);
  if (!user || user.status !== 'active') {
    throw new AuthError('ACCOUNT_INACTIVE', 'Account is not active');
  }

  const priorAmr = Array.isArray(challenge.payload['amr'])
    ? (challenge.payload['amr'] as Amr[])
    : (['pwd'] as Amr[]);

  const outcome =
    input.method === 'recovery'
      ? await verifyRecoveryCode(ctx, deps, user, input.code)
      : await verifyTotpCode(ctx, user, input.code, now);

  if (!outcome.ok) {
    await audit(ctx, {
      event: 'auth.mfa_failed',
      actorType: 'user',
      actorUserId: user.id,
      outcome: 'failure',
      ip: input.ip,
      userAgent: input.userAgent,
      metadata: { method: input.method, attemptsRemaining: challenge.attemptsRemaining },
    });
    throw errors.invalidCode(challenge.attemptsRemaining);
  }

  // Only now. A challenge consumed before the code was checked would give one
  // guess per challenge; consumed after, it gives `maxAttempts` and then dies.
  await ctx.repos.oneTimeTokens.markConsumed(challenge.id);

  const amr: Amr[] = [...priorAmr, outcome.amr];
  const session = await issueSession(ctx, deps, {
    user,
    amr,
    mfaSatisfiedAt: now,
    ip: input.ip,
    userAgent: input.userAgent,
  });

  const trustedDeviceToken = await maybeRememberDevice(ctx, deps, user, input, now);

  await audit(ctx, {
    event: 'auth.mfa_succeeded',
    actorType: 'user',
    actorUserId: user.id,
    sessionId: session.session.id,
    ip: input.ip,
    userAgent: input.userAgent,
    metadata: { method: input.method, remembered: trustedDeviceToken !== null },
  });
  await emit(ctx, 'user.logged_in', {
    userId: user.id,
    sessionId: session.session.id,
    method: input.method,
  });

  return { user, session, trustedDeviceToken };
}

async function verifyTotpCode(
  ctx: AuthContext,
  user: User,
  code: string,
  now: Date,
): Promise<{ ok: boolean; amr: Amr }> {
  const { totp, secrets } = requireTotp(ctx);
  const factors = await ctx.repos.mfa.listConfirmedFactors(user.id);

  for (const factor of factors) {
    if (factor.type !== 'totp' || !factor.secretEnc) continue;

    const verification = totp.verify(
      { base32: secrets.decrypt(factor.secretEnc, 'totp-secret') },
      code,
      now,
    );
    if (!verification.valid || verification.timestep === null) continue;

    // ⚑ The code verified; that is not enough. Drift tolerance means a code stays
    // valid for ~90 seconds, so without this the same code works repeatedly inside
    // its own window — which is exactly the window an attacker who watched someone
    // type it is operating in.
    const advanced = await ctx.repos.mfa.advanceTimestep(factor.id, now, verification.timestep);
    if (!advanced) return { ok: false, amr: 'totp' };

    await ctx.repos.mfa.touchFactor(factor.id, now);
    return { ok: true, amr: 'totp' };
  }

  return { ok: false, amr: 'totp' };
}

async function verifyRecoveryCode(
  ctx: AuthContext,
  deps: CryptoDeps,
  user: User,
  code: string,
): Promise<{ ok: boolean; amr: Amr }> {
  // Normalised, because these are typed off paper or a screenshot and the dashes
  // are decoration.
  const normalised = code.replace(/[\s-]/g, '').toUpperCase();
  const consumed = await ctx.repos.mfa.consumeRecoveryCode(user.id, deps.sha256(normalised));
  if (!consumed) return { ok: false, amr: 'otp' };

  const remaining = await ctx.repos.mfa.countUnusedRecoveryCodes(user.id);
  await notifyRecoveryCodeUsed(ctx, user, remaining);

  // ⚑ `otp`, not `totp`. A recovery code is a bearer secret, not a device — and
  // step-up (§5.4.7) is entitled to know the difference.
  return { ok: true, amr: 'otp' };
}

/** §5.4.5 — mint a device token, if the deployment and the user both asked. */
async function maybeRememberDevice(
  ctx: AuthContext,
  deps: CryptoDeps,
  user: User,
  input: VerifyMfaInput,
  now: Date,
): Promise<string | null> {
  const { enabled, ttl, max } = ctx.config.mfa.trustedDevices;
  if (!enabled || !input.rememberDevice) return null;

  // LRU by expiry: the cap is what stops a user accumulating an unbounded set of
  // things that skip their second factor.
  const existing = await ctx.repos.trustedDevices.listForUser(user.id);
  if (existing.length >= max) {
    const sorted = [...existing].sort(
      (a, b) => (a.lastUsedAt?.getTime() ?? 0) - (b.lastUsedAt?.getTime() ?? 0),
    );
    for (const stale of sorted.slice(0, existing.length - max + 1)) {
      await ctx.repos.trustedDevices.revoke(stale.id);
    }
  }

  const token = deps.newSecret('td');
  await ctx.repos.trustedDevices.create({
    userId: user.id,
    hash: deps.sha256(token),
    label: input.userAgent?.slice(0, 100) ?? null,
    // ⚑ Absolute, from the 2FA that earned it. No sliding renewal, or "30 days"
    // becomes "forever, for anyone who signs in monthly".
    expiresAt: new Date(now.getTime() + ttl),
    mfaSatisfiedAt: now,
  });

  await audit(ctx, {
    event: 'mfa.device_trusted',
    actorType: 'user',
    actorUserId: user.id,
    ip: input.ip,
    userAgent: input.userAgent,
  });

  return token;
}

// ── Management ──────────────────────────────────────────────────────────────

export interface MfaState {
  enforced: 'optional' | 'admins' | 'all';
  required: boolean;
  enrolled: boolean;
  factors: Array<{
    id: string;
    type: MfaFactor['type'];
    label: string | null;
    confirmed: boolean;
    lastUsedAt: Date | null;
    createdAt: Date;
  }>;
  recoveryCodesRemaining: number;
}

export async function getMfaState(ctx: AuthContext, userId: UserId): Promise<MfaState> {
  const user = await ctx.repos.users.findById(userId);
  const factors = await ctx.repos.mfa.listAllFactors(userId);

  return {
    enforced: ctx.config.mfa.enforce,
    required: ctx.config.mfa.enforce === 'all' || user?.mfaRequiredAt != null,
    enrolled: factors.some((factor) => factor.confirmedAt !== null),
    factors: factors.map((factor) => ({
      id: factor.id,
      type: factor.type,
      label: factor.label,
      confirmed: factor.confirmedAt !== null,
      lastUsedAt: factor.lastUsedAt,
      createdAt: factor.createdAt,
    })),
    recoveryCodesRemaining: await ctx.repos.mfa.countUnusedRecoveryCodes(userId),
  };
}

export interface RemoveFactorInput extends RequestContext {
  userId: UserId;
  factorId: string;
}

/**
 * §5.4.8. The caller is responsible for the step-up check; what belongs here is
 * the policy refusal and the containment.
 */
export async function removeFactor(ctx: AuthContext, input: RemoveFactorInput): Promise<void> {
  const factor = await ctx.repos.mfa.findFactor(input.factorId);
  if (!factor || factor.userId !== input.userId) {
    throw new AuthError('NOT_FOUND', 'Factor not found');
  }

  const confirmed = await ctx.repos.mfa.listConfirmedFactors(input.userId);
  const isLastConfirmed =
    factor.confirmedAt !== null && confirmed.filter((f) => f.id !== factor.id).length === 0;

  const user = await ctx.repos.users.findById(input.userId);
  const mandatory = ctx.config.mfa.enforce === 'all' || user?.mfaRequiredAt != null;

  // ⚑ Refused outright rather than quietly quarantining. Removing the last factor
  // under a policy that mandates one is a request to disable a control, and the
  // honest answer is no.
  if (isLastConfirmed && mandatory) {
    throw new AuthError(
      'MFA_REQUIRED_BY_POLICY',
      'Two-factor authentication is required for this account',
    );
  }

  await ctx.repos.mfa.removeFactor(factor.id);

  // Trust was earned by a factor that no longer exists.
  await ctx.repos.trustedDevices.revokeAllForUser(input.userId);

  if (isLastConfirmed) {
    await notifyFactorChange(ctx, input.userId, 'disabled');
    await emit(ctx, 'mfa.disabled', { userId: input.userId });
  }

  await audit(ctx, {
    event: isLastConfirmed ? 'mfa.disabled' : 'mfa.factor_removed',
    actorType: 'user',
    actorUserId: input.userId,
    targetType: 'mfa_factor',
    targetId: factor.id,
    ip: input.ip,
    userAgent: input.userAgent,
  });
}

export interface RegenerateRecoveryCodesInput extends RequestContext {
  userId: UserId;
  /** Suppressed during enrolment, where the "2FA enabled" mail already went out. */
  notify?: boolean;
}

export async function regenerateRecoveryCodes(
  ctx: AuthContext,
  deps: CryptoDeps,
  input: RegenerateRecoveryCodesInput,
): Promise<string[]> {
  const count = ctx.config.mfa.recoveryCodeCount;
  const codes = Array.from({ length: count }, () => formatRecoveryCode(ctx));

  // ⚑ Replaces the whole set in one operation. Adding to the existing set would
  // leave codes alive that the user believes they have just invalidated.
  await ctx.repos.mfa.replaceRecoveryCodes(
    input.userId,
    codes.map((code) => deps.sha256(code.replace(/-/g, ''))),
  );

  if (input.notify !== false) {
    const user = await ctx.repos.users.findById(input.userId);
    if (user?.email) {
      await ctx.mailer.send({
        to: user.email,
        subject: `Your recovery codes were regenerated — ${ctx.config.appName}`,
        text:
          `New recovery codes were generated for your account, and every previous code ` +
          `has stopped working.\n\nIf this wasn't you, sign in and review your security settings now.`,
        html:
          `<p>New recovery codes were generated for your account, and every previous code ` +
          `has stopped working.</p><p>If this wasn't you, sign in and review your security settings now.</p>`,
      });
    }
  }

  await audit(ctx, {
    event: 'mfa.recovery_codes_regenerated',
    actorType: 'user',
    actorUserId: input.userId,
    ip: input.ip,
    userAgent: input.userAgent,
    metadata: { count },
  });

  return codes;
}

/**
 * Readable groups, no ambiguous characters. These get typed off paper by someone
 * who has already lost their phone and is not enjoying it.
 */
const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function formatRecoveryCode(ctx: AuthContext): string {
  const bytes = ctx.random.bytes(20);
  const chars = Array.from(bytes, (byte) => RECOVERY_ALPHABET[byte % RECOVERY_ALPHABET.length]!);
  return [
    chars.slice(0, 5).join(''),
    chars.slice(5, 10).join(''),
    chars.slice(10, 15).join(''),
    chars.slice(15, 20).join(''),
  ].join('-');
}

// ── Trusted devices ─────────────────────────────────────────────────────────

export async function listTrustedDevices(
  ctx: AuthContext,
  userId: UserId,
): Promise<Array<{ id: string; label: string | null; lastUsedAt: Date | null; expiresAt: Date }>> {
  return ctx.repos.trustedDevices.listForUser(userId);
}

export interface RevokeTrustedDeviceInput extends RequestContext {
  userId: UserId;
  deviceId: string;
}

export async function revokeTrustedDevice(
  ctx: AuthContext,
  input: RevokeTrustedDeviceInput,
): Promise<void> {
  const devices = await ctx.repos.trustedDevices.listForUser(input.userId);
  // Ownership before existence, as with sessions.
  if (!devices.some((device) => device.id === input.deviceId)) {
    throw new AuthError('NOT_FOUND', 'Device not found');
  }

  await ctx.repos.trustedDevices.revoke(input.deviceId);
  await audit(ctx, {
    event: 'mfa.device_revoked',
    actorType: 'user',
    actorUserId: input.userId,
    targetType: 'trusted_device',
    targetId: input.deviceId,
    ip: input.ip,
    userAgent: input.userAgent,
  });
}

// ── Notifications ───────────────────────────────────────────────────────────

/**
 * ⚑ Out-of-band, always. If an attacker has enough access to change someone's
 * second factor, the account owner learns about it somewhere the attacker is not.
 */
async function notifyFactorChange(
  ctx: AuthContext,
  userId: UserId,
  change: 'enabled' | 'disabled',
): Promise<void> {
  const user = await ctx.repos.users.findById(userId);
  if (!user?.email) return;

  const verb = change === 'enabled' ? 'switched on' : 'turned off';
  await ctx.mailer.send({
    to: user.email,
    subject: `Two-factor authentication was ${verb} — ${ctx.config.appName}`,
    text:
      `Two-factor authentication on your account was ${verb}.\n\n` +
      `If this wasn't you, change your password immediately and contact support.`,
    html:
      `<p>Two-factor authentication on your account was ${verb}.</p>` +
      `<p>If this wasn't you, change your password immediately and contact support.</p>`,
  });
}

async function notifyRecoveryCodeUsed(
  ctx: AuthContext,
  user: User,
  remaining: number,
): Promise<void> {
  if (!user.email) return;

  // ⚑ Warn at two. Someone who runs out has no second factor and no way back in
  // except a human support flow, which is expensive for everyone.
  const warning =
    remaining <= 2
      ? ` You have ${remaining} left — generate a new set from your security settings now.`
      : ` You have ${remaining} left.`;

  await ctx.mailer.send({
    to: user.email,
    subject: `A recovery code was used to sign in — ${ctx.config.appName}`,
    text: `A recovery code was used to sign in to your account.${warning}\n\nIf this wasn't you, change your password immediately.`,
    html: `<p>A recovery code was used to sign in to your account.${warning}</p><p>If this wasn't you, change your password immediately.</p>`,
  });
}
