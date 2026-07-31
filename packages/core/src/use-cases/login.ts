/**
 * Password login (AUTH-MODULE-PLAN.md §5.3), including the branch into 2FA
 * (§5.4.2) and the enrollment quarantine (§5.4.6).
 *
 * Two invariants shape everything here:
 *
 *  1. **"No such user" and "wrong password" are indistinguishable** — same code,
 *     same body, and same *cost*. The dummy verifies below are not defensive
 *     padding; without them the unknown-user path returns in microseconds while
 *     the real one spends ~60ms in Argon2, and that difference is measurable
 *     across the internet.
 *  2. **`mfa_required` is a success, not a failure.** It returns 200 with a
 *     challenge token and no session — the first factor passed, the login has
 *     not finished. Modelling it as an error would push the HTTP layer into
 *     setting cookies from a catch block.
 */

import { AuthError, errors } from '../errors.js';
import { audit, emit, type AuthContext, type RequestContext } from '../context.js';
import type { Amr, MfaFactor, User } from '../ports.js';
import type { CryptoDeps } from './deps.js';
import { issueSession, type IssuedSession } from './session.js';

/** What the challenge screen may offer. Wider than `MfaFactorType`: recovery codes are not a factor. */
export type MfaMethod = 'totp' | 'webauthn' | 'email_otp' | 'sms_otp' | 'recovery';

export interface LoginInput extends RequestContext {
  email: string;
  password: string;
  /** Raw value of the trusted-device cookie, if the client sent one (§5.4.5). */
  trustedDeviceToken?: string | null;
}

export type LoginResult =
  | {
      status: 'authenticated';
      user: User;
      session: IssuedSession;
      /**
       * Policy demands a second factor and the user has none. The session is real
       * but quarantined — the HTTP guard limits it to /auth/me, the enrollment
       * endpoints and logout (§5.4.6).
       */
      mfaEnrollmentRequired: boolean;
      /** When the quarantine stops being advisory. Null when not quarantined. */
      mfaGraceEndsAt: Date | null;
    }
  | {
      status: 'mfa_required';
      mfaToken: string;
      availableMethods: MfaMethod[];
      expiresIn: number;
    };

export async function login(
  ctx: AuthContext,
  deps: CryptoDeps,
  input: LoginInput,
): Promise<LoginResult> {
  const now = ctx.clock.now();
  const user = await ctx.repos.users.findByEmail(input.email.trim());

  // ⚑ One branch for "no account" and for "account with no password" (passkey- or
  // SSO-only). Both must cost a full Argon2 verify, or the absence of a password
  // becomes as detectable as the absence of an account.
  if (!user || !user.passwordHash) {
    await ctx.hasher.verifyDummy(input.password);
    await recordFailure(ctx, input, user?.id ?? null, user ? 'no_password' : 'unknown_user');
    throw errors.invalidCredentials();
  }

  // Locked first, and deliberately without the dummy verify. The response is a
  // distinct 423 either way so there is no timing signal left to protect, and
  // refusing early keeps a lockout from being a way to keep the Argon2 semaphore
  // (§8.5) permanently saturated.
  if (user.lockedUntil && user.lockedUntil.getTime() > now.getTime()) {
    await recordFailure(ctx, input, user.id, 'locked');
    throw errors.accountLocked(user.lockedUntil);
  }

  if (user.status === 'deleted') {
    // A deleted account answers exactly like an address that never existed —
    // including the cost.
    await ctx.hasher.verifyDummy(input.password);
    await recordFailure(ctx, input, user.id, 'deleted');
    throw errors.invalidCredentials();
  }

  if (user.status === 'suspended') {
    await recordFailure(ctx, input, user.id, 'suspended');
    throw new AuthError('ACCOUNT_SUSPENDED', 'This account has been suspended');
  }

  const ok = await ctx.hasher.verify(input.password, user.passwordHash);
  if (!ok) {
    const { lockFor, maxFailures } = {
      maxFailures: ctx.config.lockout.maxFailures,
      lockFor: ctx.config.lockout.lockFor,
    };
    // Atomic increment-and-lock in one statement, so N parallel guesses cannot
    // each read the same pre-increment count and slip past the threshold together.
    const state = await ctx.repos.users.registerFailedLogin(user.id, maxFailures, lockFor);

    await recordFailure(ctx, input, user.id, 'bad_password', {
      failedLoginCount: state.failedLoginCount,
    });

    if (state.lockedUntil && state.lockedUntil.getTime() > now.getTime()) {
      await emit(ctx, 'user.locked', { userId: user.id, until: state.lockedUntil });
      throw errors.accountLocked(state.lockedUntil);
    }
    throw errors.invalidCredentials();
  }

  await ctx.repos.users.clearFailedLogins(user.id);
  await maybeRehash(ctx, user, input.password);

  // ⚑ After the password check, never before. Answering EMAIL_NOT_VERIFIED to an
  // unauthenticated caller would turn this endpoint into an oracle for "this
  // address is registered but not yet verified" — which is precisely the set of
  // addresses worth attacking, since the account is half-built.
  if (
    ctx.config.email.requireVerification &&
    !ctx.config.email.allowUnverifiedLogin &&
    !user.emailVerifiedAt
  ) {
    await recordFailure(ctx, input, user.id, 'email_unverified');
    throw new AuthError('EMAIL_NOT_VERIFIED', 'Confirm your email address before signing in');
  }

  const factors = ctx.config.mfa.enabled
    ? await ctx.repos.mfa.listConfirmedFactors(user.id)
    : [];

  if (factors.length > 0) {
    const trusted = await resolveTrustedDevice(ctx, deps, user, input.trustedDeviceToken);
    if (trusted) {
      await ctx.repos.trustedDevices.touch(trusted.id, now);
      // ⚑ `mfaSatisfiedAt` stays null. Trust skips the challenge screen; it does
      // not count as having presented a factor, so step-up (§5.4.7) still asks —
      // a stolen laptop must not be able to change the password (§5.4.5).
      return finishLogin(ctx, deps, user, input, {
        amr: ['pwd', 'device'],
        mfaSatisfiedAt: null,
        method: 'trusted_device',
      });
    }

    const challenge = await issueMfaChallenge(ctx, deps, user, factors, input);
    await audit(ctx, {
      event: 'auth.mfa_challenged',
      actorType: 'user',
      actorUserId: user.id,
      ip: input.ip,
      userAgent: input.userAgent,
      metadata: { availableMethods: challenge.availableMethods },
    });
    return { status: 'mfa_required', ...challenge };
  }

  if (mfaRequiredByPolicy(ctx, user)) {
    return quarantine(ctx, deps, user, input);
  }

  return finishLogin(ctx, deps, user, input, {
    amr: ['pwd'],
    mfaSatisfiedAt: null,
    method: 'password',
  });
}

// ── steps ───────────────────────────────────────────────────────────────────

/**
 * §5.3 step 5 — the one moment we hold the plaintext and can upgrade a legacy or
 * under-parameterised hash.
 *
 * ⚑ Does not touch `passwordUpdatedAt`. That field is a credential-change marker:
 * refresh (§5.5.3 step 10) kills every session created before it. A rehash is the
 * same password stored differently, and bumping it would sign the user out of
 * every other device for doing nothing.
 */
async function maybeRehash(ctx: AuthContext, user: User, plain: string): Promise<void> {
  if (!user.passwordHash) return;
  if (user.passwordAlgo === 'argon2id' && !ctx.hasher.needsRehash(user.passwordHash)) return;

  try {
    const rehashed = await ctx.hasher.hash(plain);
    await ctx.repos.users.update(user.id, {
      passwordHash: rehashed.hash,
      passwordAlgo: 'argon2id',
    });
  } catch (error) {
    // The credential was already verified — a failed upgrade is an operational
    // problem, not a reason to refuse a correct password.
    ctx.logger.warn({ err: error, userId: user.id }, 'password rehash failed');
  }
}

async function finishLogin(
  ctx: AuthContext,
  deps: CryptoDeps,
  user: User,
  input: LoginInput,
  opts: { amr: Amr[]; mfaSatisfiedAt: Date | null; method: string },
): Promise<Extract<LoginResult, { status: 'authenticated' }>> {
  const session = await issueSession(ctx, deps, {
    user,
    amr: opts.amr,
    mfaSatisfiedAt: opts.mfaSatisfiedAt,
    ip: input.ip,
    userAgent: input.userAgent,
  });

  await audit(ctx, {
    event: 'auth.login_succeeded',
    actorType: 'user',
    actorUserId: user.id,
    sessionId: session.session.id,
    ip: input.ip,
    userAgent: input.userAgent,
    metadata: { method: opts.method },
  });
  await emit(ctx, 'user.logged_in', {
    userId: user.id,
    sessionId: session.session.id,
    method: opts.method,
  });

  return {
    status: 'authenticated',
    user,
    session,
    mfaEnrollmentRequired: false,
    mfaGraceEndsAt: null,
  };
}

/**
 * §5.4.6 — policy requires a second factor and there is none confirmed.
 *
 * ⚑ This succeeds on purpose. The obvious implementation refuses the login, which
 * locks the user out of the enrollment screen that would satisfy the policy. The
 * session is real but marked; the route guard is what narrows it.
 */
async function quarantine(
  ctx: AuthContext,
  deps: CryptoDeps,
  user: User,
  input: LoginInput,
): Promise<Extract<LoginResult, { status: 'authenticated' }>> {
  const now = ctx.clock.now();
  const markedAt = user.mfaRequiredAt ?? now;

  if (!user.mfaRequiredAt) {
    await ctx.repos.users.update(user.id, { mfaRequiredAt: markedAt });
  }

  const result = await finishLogin(ctx, deps, user, input, {
    amr: ['pwd'],
    mfaSatisfiedAt: null,
    method: 'password',
  });

  await audit(ctx, {
    event: 'auth.mfa_enrollment_required',
    actorType: 'system',
    actorUserId: user.id,
    sessionId: result.session.session.id,
    ip: input.ip,
  });

  return {
    ...result,
    mfaEnrollmentRequired: true,
    // The grace period runs from when the requirement was first applied, not from
    // this login — otherwise never logging in indefinitely postpones the deadline.
    mfaGraceEndsAt: new Date(markedAt.getTime() + ctx.config.mfa.gracePeriod),
  };
}

/** §5.4.6 — is a second factor mandatory for this user? */
function mfaRequiredByPolicy(ctx: AuthContext, user: User): boolean {
  if (!ctx.config.mfa.enabled) return false;
  if (ctx.config.mfa.enforce === 'all') return true;
  // `'admins'` needs the role table, which arrives with RBAC (§10). Until then the
  // per-user marker is the enforcement signal: promoting someone to a privileged
  // role sets `mfaRequiredAt`, and this reads it back.
  return user.mfaRequiredAt !== null;
}

/**
 * §5.4.2 — the challenge token. Stored as a one-time token so consumption is a
 * single atomic UPDATE, and carrying nothing that would be worth stealing: no
 * `sid`, no permissions, no audience. It authorizes exactly one endpoint.
 */
async function issueMfaChallenge(
  ctx: AuthContext,
  deps: CryptoDeps,
  user: User,
  factors: MfaFactor[],
  input: LoginInput,
): Promise<{ mfaToken: string; availableMethods: MfaMethod[]; expiresIn: number }> {
  const ttl = ctx.config.tokens.mfaChallengeTtl;
  const secret = deps.newSecret('mfa');
  const availableMethods = await offerableMethods(ctx, user, factors);

  await ctx.repos.oneTimeTokens.issue({
    userId: user.id,
    purpose: 'mfa_challenge',
    hash: deps.sha256(secret),
    payload: {
      amr: ['pwd'],
      availableMethods,
      // ⚑ Bound to the client that started the login. A challenge token read out of
      // a URL, a log or a shoulder-surfed screen is useless from anywhere else.
      binding: deps.hex(deps.clientBinding(input)),
    },
    expiresAt: new Date(ctx.clock.now().getTime() + ttl),
    requestedIp: input.ip,
  });

  return { mfaToken: secret, availableMethods, expiresIn: Math.floor(ttl / 1000) };
}

/**
 * What the challenge screen should offer.
 *
 * ⚑ Email OTP is listed whenever it is configured, which means a user with TOTP
 * enrolled can still fall back to their mailbox — so the *effective* strength of
 * their second factor is the weaker of the two. That is a deployment decision, not
 * an accident: drop `'email_otp'` from `mfa.methods` to make enrolled factors
 * binding, at the cost of a support ticket every time someone loses their phone.
 */
async function offerableMethods(
  ctx: AuthContext,
  user: User,
  factors: MfaFactor[],
): Promise<MfaMethod[]> {
  const configured = new Set<string>(ctx.config.mfa.methods);
  const methods = new Set<MfaMethod>();

  for (const factor of factors) {
    if (factor.type === 'totp' && configured.has('totp')) methods.add('totp');
    if (factor.type === 'webauthn' && configured.has('webauthn')) methods.add('webauthn');
    if (factor.type === 'sms' && configured.has('sms_otp') && user.phoneVerifiedAt) {
      methods.add('sms_otp');
    }
  }

  if (configured.has('email_otp') && user.email && user.emailVerifiedAt) {
    methods.add('email_otp');
  }

  if ((await ctx.repos.mfa.countUnusedRecoveryCodes(user.id)) > 0) {
    methods.add('recovery');
  }

  return [...methods];
}

/** §5.4.5 — a trusted-device cookie that may skip the challenge. */
async function resolveTrustedDevice(
  ctx: AuthContext,
  deps: CryptoDeps,
  user: User,
  token: string | null | undefined,
): Promise<{ id: string } | null> {
  if (!token || !ctx.config.mfa.trustedDevices.enabled) return null;

  const device = await ctx.repos.trustedDevices.findValidByHash(deps.sha256(token));
  // ⚑ Trust is scoped to (user, device), not to the device alone. Without this
  // check a cookie minted for one account would skip 2FA on every account that
  // shares the browser.
  if (!device || device.userId !== user.id) return null;

  return { id: device.id };
}

async function recordFailure(
  ctx: AuthContext,
  input: LoginInput,
  userId: string | null,
  reason: string,
  metadata: Record<string, unknown> = {},
): Promise<void> {
  await audit(ctx, {
    event: 'auth.login_failed',
    actorType: userId ? 'user' : 'system',
    actorUserId: userId,
    outcome: 'failure',
    ip: input.ip,
    userAgent: input.userAgent,
    // ⚑ The reason is recorded, never returned. Operators need to tell a locked
    // account from a wrong password; the caller must not be able to.
    metadata: { reason, ...metadata },
  });
}
