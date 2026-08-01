/**
 * Registration and email verification (AUTH-MODULE-PLAN.md §5.1, §5.2).
 *
 * The whole flow is shaped by one rule: **the response must not reveal whether the
 * address already has an account** — not in the body, not in the status, and not in
 * how long it took. Everything below that looks redundant is there for the timing.
 */

import { AuthError } from '../errors.js';
import { audit, emit, type AuthContext, type RequestContext } from '../context.js';
import type { User } from '../ports.js';
import type { CryptoDeps } from './deps.js';

export interface RegisterInput extends RequestContext {
  email: string;
  password: string;
  name?: string | null;
}

export interface RegisterResult {
  status: 'verification_sent';
}

export async function register(
  ctx: AuthContext,
  deps: CryptoDeps,
  input: RegisterInput,
): Promise<RegisterResult> {
  const email = input.email.trim();
  await assertPasswordAcceptable(ctx, input.password);

  // ⚑ Hash before looking the user up, and hash on both branches. Hashing is by
  // far the most expensive step, so doing it only when the address is free would
  // make "already registered" reliably faster to detect than "available".
  const hashed = await ctx.hasher.hash(input.password);

  const existing = await ctx.repos.users.findByEmail(email);
  if (existing) {
    await audit(ctx, {
      event: 'user.registered',
      actorType: 'system',
      outcome: 'failure',
      ip: input.ip,
      userAgent: input.userAgent,
      metadata: { reason: 'email_taken' },
    });

    /**
     * ⚑ The deployment's choice, made explicit at boot rather than here.
     *
     * `false` (the default) is §5.1's enumeration resistance: identical body,
     * identical status, identical *timing* — which is why the password was hashed
     * above before this lookup ran. The person who learns anything is the account
     * holder, by email; the caller learns nothing.
     *
     * `true` tells the caller directly. It costs the guarantee — `/auth/register`
     * becomes an oracle for "does this address have an account" — and buys the
     * usability: someone who forgot they signed up is otherwise told to watch an
     * inbox for a link that never comes.
     */
    if (ctx.config.registration.revealExistingAccount) {
      throw new AuthError(
        'CONFLICT',
        'An account already exists for this email address',
        { details: { field: 'email' } },
      );
    }

    // Tell the real owner that someone tried, and tell the caller nothing.
    await ctx.mailer.send({
      to: email,
      subject: `Someone tried to register with your email — ${ctx.config.appName}`,
      text:
        `Someone entered this address when signing up to ${ctx.config.appName}, but an ` +
        `account already exists.

If that was you, sign in instead — or reset your ` +
        `password if you have forgotten it. If it wasn't, you can ignore this message.`,
      html:
        `<p>Someone entered this address when signing up to ${ctx.config.appName}, but an ` +
        `account already exists.</p><p>If that was you, sign in instead — or reset your ` +
        `password if you have forgotten it. If it wasn't, you can ignore this message.</p>`,
    });

    return { status: 'verification_sent' };
  }

  const user = await ctx.repos.users.create({
    email,
    name: input.name ?? null,
    passwordHash: hashed.hash,
    passwordAlgo: 'argon2id',
    status: 'pending',
  });

  await sendVerificationEmail(ctx, deps, user, input);

  await audit(ctx, {
    event: 'user.registered',
    actorType: 'user',
    actorUserId: user.id,
    ip: input.ip,
    userAgent: input.userAgent,
  });
  await emit(ctx, 'user.registered', { userId: user.id });

  return { status: 'verification_sent' };
}

/**
 * Password policy (§8.1). Length and a breach check, deliberately no composition
 * rules — NIST 800-63B, and because "must contain a symbol" reliably produces
 * `Password1!` rather than anything stronger.
 */
export async function assertPasswordAcceptable(
  ctx: AuthContext,
  password: string,
): Promise<void> {
  const { minLength, maxLength, checkBreached } = ctx.config.password;

  if (password.length < minLength) {
    throw new AuthError('WEAK_PASSWORD', `Password must be at least ${minLength} characters`, {
      details: { minLength },
    });
  }
  // An upper bound is not about strength: it stops a megabyte of input becoming a
  // memory-hard hash big enough to take the process down.
  if (password.length > maxLength) {
    throw new AuthError('WEAK_PASSWORD', `Password must be at most ${maxLength} characters`, {
      details: { maxLength },
    });
  }

  if (checkBreached && ctx.breachChecker) {
    let breached = false;
    try {
      breached = await ctx.breachChecker.isBreached(password);
    } catch (error) {
      // Fail open, but loudly. A third-party outage must not stop people signing
      // up; a silent one must not quietly disable the control either.
      ctx.logger.warn({ err: error }, 'breach check unavailable — allowing password');
    }
    if (breached) {
      throw new AuthError(
        'PASSWORD_BREACHED',
        'This password has appeared in a known data breach — choose another',
      );
    }
  }
}

async function sendVerificationEmail(
  ctx: AuthContext,
  deps: CryptoDeps,
  user: User,
  request: RequestContext,
): Promise<void> {
  const secret = deps.newSecret();
  const ttlMs = 24 * 3_600_000;

  await ctx.repos.oneTimeTokens.issue({
    userId: user.id,
    purpose: 'email_verify',
    hash: deps.sha256(secret),
    expiresAt: new Date(ctx.clock.now().getTime() + ttlMs),
    requestedIp: request.ip,
  });

  // ⚑ Built from configured origin, never from a request header. A Host-header
  // controlled link is how password-reset poisoning works (§5.7).
  const url = `${ctx.config.urls.appOrigin}${ctx.config.urls.verifyPath}?token=${secret}`;

  await ctx.mailer.send({
    to: user.email ?? '',
    subject: `Confirm your email address — ${ctx.config.appName}`,
    text: `Confirm this address to finish setting up your account:\n\n${url}\n\nThis link expires in 24 hours.`,
    html: `<p>Confirm this address to finish setting up your account.</p><p><a href="${url}">Confirm email</a></p><p>This link expires in 24 hours.</p>`,
  });

  await audit(ctx, {
    event: 'email.verification_sent',
    actorType: 'system',
    actorUserId: user.id,
    ip: request.ip,
  });
}

export interface VerifyEmailInput extends RequestContext {
  token: string;
}

export async function verifyEmail(
  ctx: AuthContext,
  deps: CryptoDeps,
  input: VerifyEmailInput,
): Promise<{ userId: string }> {
  const consumed = await ctx.repos.oneTimeTokens.consume(
    deps.sha256(input.token),
    'email_verify',
  );

  // One code for "never existed", "already used" and "expired". The client offers a
  // resend either way, so distinguishing them buys nothing and leaks a little.
  if (!consumed?.userId) {
    throw new AuthError('CODE_EXPIRED', 'This link is no longer valid — request a new one');
  }

  const user = await ctx.repos.users.findById(consumed.userId);
  if (!user) throw new AuthError('CODE_EXPIRED', 'This link is no longer valid');

  const now = ctx.clock.now();
  await ctx.repos.users.update(user.id, {
    emailVerifiedAt: now,
    // Only a pending account is promoted. A suspended one stays suspended, or
    // verification would become a way to undo moderation.
    ...(user.status === 'pending' ? { status: 'active' as const } : {}),
  });

  await audit(ctx, {
    event: 'email.verified',
    actorType: 'user',
    actorUserId: user.id,
    ip: input.ip,
    userAgent: input.userAgent,
  });
  await emit(ctx, 'user.verified', { userId: user.id });

  return { userId: user.id };
}

export interface ResendVerificationInput extends RequestContext {
  email: string;
}

/**
 * ⚑ Always reports success. This endpoint sends mail on demand, so it is both an
 * enumeration oracle and a spam amplifier if it answers honestly; the per-account
 * rate limit (§8.2) is what keeps the mail volume sane.
 */
export async function resendVerification(
  ctx: AuthContext,
  deps: CryptoDeps,
  input: ResendVerificationInput,
): Promise<{ status: 'verification_sent' }> {
  const user = await ctx.repos.users.findByEmail(input.email.trim());

  if (user && !user.emailVerifiedAt) {
    // Invalidate outstanding links so only the newest one works.
    await ctx.repos.oneTimeTokens.revokeAllForUser(user.id, 'email_verify');
    await sendVerificationEmail(ctx, deps, user, input);
  }

  return { status: 'verification_sent' };
}
