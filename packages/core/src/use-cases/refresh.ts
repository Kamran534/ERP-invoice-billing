/**
 * Refresh-token rotation (AUTH-MODULE-PLAN.md §5.5.3).
 *
 * Implements the numbered sequence from the plan. Every rejection below is a
 * deliberate `401` with a distinct code so a client can tell "retry" from "give
 * up", except reuse — which returns a bare `401` that explains nothing, because
 * telling an attacker the alarm exists tells them which token tripped it.
 */

import { AuthError, errors } from '../errors.js';
import { audit, emit, type AuthContext, type RequestContext } from '../context.js';
import type { AccessClaims, RefreshTokenRow, Session, User } from '../ports.js';
import type { CryptoDeps } from './deps.js';
import { resolveAccess } from './orgs.js';

export interface RotateRefreshInput extends RequestContext {
  /** The opaque secret the client presented. Never logged, never stored. */
  presentedSecret: string;
}

export interface RotateRefreshResult {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  session: Session;
}

/**
 * Rotation uses only `sha256` and `newSecret`, but takes the whole `CryptoDeps`
 * so the module has one vocabulary rather than a per-use-case dialect that drifts.
 */
export type RefreshDeps = CryptoDeps;

export async function rotateRefreshToken(
  ctx: AuthContext,
  deps: RefreshDeps,
  input: RotateRefreshInput,
): Promise<RotateRefreshResult> {
  const now = ctx.clock.now();
  const presentedHash = deps.sha256(input.presentedSecret);

  // ── 1–6: claim the token, and classify anything that is not a clean claim ──
  const claim = await ctx.repos.refreshTokens.claim(presentedHash);

  switch (claim.outcome) {
    case 'unknown':
      await audit(ctx, {
        event: 'auth.refresh_unknown',
        actorType: 'system',
        outcome: 'failure',
        ip: input.ip,
        userAgent: input.userAgent,
      });
      throw new AuthError('INVALID_REFRESH_TOKEN', 'Invalid refresh token');

    case 'revoked':
      throw new AuthError('SESSION_REVOKED', 'This session has been signed out');

    case 'expired':
      throw new AuthError('REFRESH_EXPIRED', 'Refresh token has expired');

    case 'concurrent':
      // ⚑ Not theft. Another request claimed the same live token microseconds
      // ago — the multi-tab race §5.5.5 describes. The client waits and retries
      // once, picking up the winner's successor.
      await audit(ctx, {
        event: 'auth.refresh_concurrent',
        actorType: 'system',
        sessionId: claim.token.sessionId,
        ip: input.ip,
        userAgent: input.userAgent,
      });
      throw new AuthError('REFRESH_IN_PROGRESS', 'A refresh is already in progress');

    case 'reuse':
      return handleReuse(ctx, deps, input, claim.token, now);

    case 'ok':
      break;
  }

  const claimed = claim.token;

  // ── 7–11: the session and the user must still be entitled to a token ──────
  const session = await ctx.repos.sessions.findById(claimed.sessionId);
  if (!session || session.revokedAt) {
    throw new AuthError('SESSION_REVOKED', 'This session has been signed out');
  }

  if (session.absoluteExpiresAt.getTime() <= now.getTime()) {
    // ⚑ Never extended, for any reason. This is what makes a stolen session that
    // is used continuously still die.
    await ctx.repos.sessions.revoke(session.id, 'absolute_timeout');
    throw new AuthError('SESSION_EXPIRED', 'Session has reached its maximum lifetime');
  }

  if (session.idleExpiresAt.getTime() <= now.getTime()) {
    await ctx.repos.sessions.revoke(session.id, 'idle_timeout');
    throw new AuthError('SESSION_IDLE_TIMEOUT', 'Session expired through inactivity');
  }

  const user = await ctx.repos.users.findById(session.userId);
  if (!user || user.status !== 'active') {
    await ctx.repos.sessions.revoke(session.id, user ? 'suspended' : 'deleted');
    throw new AuthError('ACCOUNT_INACTIVE', 'Account is not active');
  }

  // A password change after this session began means the session predates the
  // current credential. Whoever holds it may be who the change was defending against.
  if (user.passwordUpdatedAt && user.passwordUpdatedAt.getTime() > session.createdAt.getTime()) {
    await ctx.repos.sessions.revoke(session.id, 'password_change');
    throw new AuthError('CREDENTIALS_CHANGED', 'Credentials changed — sign in again');
  }

  // ── 14–16: issue the successor and slide the idle window ─────────────────
  const secret = deps.newSecret();
  const idleExpiresAt = new Date(
    Math.min(
      now.getTime() + ctx.config.tokens.refresh.idleTtl,
      session.absoluteExpiresAt.getTime(),
    ),
  );

  const successor = await ctx.repos.refreshTokens.issue(
    session.id,
    deps.sha256(secret),
    idleExpiresAt,
  );
  await ctx.repos.refreshTokens.link(claimed.id, successor.id);
  await ctx.repos.sessions.touch(session.id, now, idleExpiresAt);

  // ── 17–18: permissions are re-read here, which is why access tokens can be
  // short and dumb: a role change or suspension lands within one token lifetime.
  // ⚑ Re-resolved on every rotation, not carried over from the previous token.
  // That is what makes a role change, a removed membership or a new permission
  // land within one access-token lifetime instead of at the next login (§10.8).
  const access_ = await resolveAccess(ctx, user.id);
  if (access_.orgId !== session.orgId) {
    await ctx.repos.sessions.setOrg(session.id, access_.orgId);
  }

  const claims: AccessClaims = {
    sub: user.id,
    sid: session.id,
    org: access_.orgId,
    roles: access_.roles,
    perms: access_.perms,
    amr: session.amr,
  };
  const access = await ctx.tokens.mintAccess(claims);

  await audit(ctx, {
    event: 'auth.refresh_rotated',
    actorType: 'user',
    actorUserId: user.id,
    sessionId: session.id,
    ip: input.ip,
    userAgent: input.userAgent,
  });

  return {
    accessToken: access.token,
    refreshToken: secret,
    expiresIn: access.expiresIn,
    session: { ...session, lastSeenAt: now, idleExpiresAt, orgId: access_.orgId },
  };
}

/**
 * A used token presented again means two parties hold it (§5.5.4).
 *
 * There are exactly two exceptions, in order of how narrow they are.
 *
 * The first is the token still being in flight: `claim` reports `reuse` whenever
 * the row was already used when it looked, and that includes a sibling request
 * that simply arrived a few milliseconds after the winner committed. The database
 * cannot tell those apart from a replay — both are "used_at is set" — so the
 * decision is made here, on how recently, and it is a policy rather than a fact.
 *
 * The second is the *immediate predecessor* being re-presented within
 * `reuseGraceMs`, and only while its successor is itself still unused. Anything
 * looser and a thief's replay is forgiven too.
 */
async function handleReuse(
  ctx: AuthContext,
  deps: RefreshDeps,
  input: RotateRefreshInput,
  token: RefreshTokenRow,
  now: Date,
): Promise<RotateRefreshResult> {
  const { inFlightWindowMs } = ctx.config.tokens.refresh;
  if (
    // `> 0` matters: without it a window of zero still forgives a replay in the
    // same millisecond, which is exactly what "off" is supposed to forbid.
    inFlightWindowMs > 0 &&
    token.usedAt !== null &&
    now.getTime() - token.usedAt.getTime() <= inFlightWindowMs
  ) {
    // ⚑ Not theft: another request claimed this same token moments ago. Reporting
    // the losers of a multi-tab race as theft destroys the session of a user who
    // did nothing but open a second tab, and it happens far more often than theft.
    await audit(ctx, {
      event: 'auth.refresh_concurrent',
      actorType: 'system',
      sessionId: token.sessionId,
      ip: input.ip,
      userAgent: input.userAgent,
      metadata: { inFlight: true, claimedMsAgo: now.getTime() - token.usedAt.getTime() },
    });
    throw new AuthError('REFRESH_IN_PROGRESS', 'A refresh is already in progress');
  }

  const graceMs = ctx.config.tokens.refresh.reuseGraceMs;
  const withinGrace =
    graceMs > 0 && token.usedAt !== null && now.getTime() - token.usedAt.getTime() <= graceMs;

  if (withinGrace && token.replacedById) {
    const successor = await ctx.repos.refreshTokens.findBySessionAndSuccessor(token.replacedById);
    // ⚑ Only if the successor is still unused. Once the chain has moved on, a
    // re-presented predecessor is indistinguishable from a replay.
    if (successor && !successor.usedAt && !successor.revokedAt) {
      await audit(ctx, {
        event: 'auth.refresh_concurrent',
        actorType: 'system',
        sessionId: token.sessionId,
        ip: input.ip,
        userAgent: input.userAgent,
        metadata: { grace: true },
      });
      throw new AuthError('REFRESH_IN_PROGRESS', 'A refresh is already in progress');
    }
  }

  // Contain first, explain never.
  await ctx.repos.refreshTokens.revokeChain(token.sessionId, 'reuse_detected');
  await ctx.repos.sessions.revoke(token.sessionId, 'reuse_detected');

  const session = await ctx.repos.sessions.findById(token.sessionId);
  const user = session ? await ctx.repos.users.findById(session.userId) : null;

  if (ctx.config.tokens.refresh.reuseRevokesAllSessions && user) {
    await ctx.repos.sessions.revokeAllForUser(user.id, 'reuse_detected');
  }

  await audit(ctx, {
    event: 'auth.refresh_reuse_detected',
    actorType: 'system',
    actorUserId: user?.id ?? null,
    sessionId: token.sessionId,
    ip: input.ip,
    userAgent: input.userAgent,
    outcome: 'failure',
    metadata: { severity: 'high' },
  });

  await emit(ctx, 'security.refresh_reuse_detected', {
    userId: user?.id ?? null,
    sessionId: token.sessionId,
    ip: input.ip,
  });

  if (user?.email) {
    // Out-of-band signal. Sending is fail-soft, so a mail outage cannot stop the
    // containment above from having happened.
    await ctx.mailer.send({
      to: user.email,
      subject: `We signed out a device on your account — ${ctx.config.appName}`,
      text:
        `On ${now.toUTCString()} a sign-in credential for your account was reused from more than ` +
        `one place, so we signed that session out as a precaution.\n\n` +
        `If you don't recognise this, change your password and review your active devices.`,
      html: `<p>On ${now.toUTCString()} a sign-in credential for your account was reused from more than one place, so we signed that session out as a precaution.</p><p>If you don't recognise this, change your password and review your active devices.</p>`,
    });
  }

  // ⚑ A bare 401. Never reveal that reuse was detected, which token tripped it, or
  // that an alarm exists at all.
  throw errors.invalidRefreshToken();
}
