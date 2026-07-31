/**
 * Session issuance and teardown (AUTH-MODULE-PLAN.md §5.5.2, §5.6).
 *
 * `issueSession` is the single place a session comes into existence. Password
 * login, OTP verification and MFA verification all funnel through it, so the
 * absolute cap, the idle window and the first refresh token are established
 * identically no matter which door the user came through — and there is one place
 * to change if that policy ever moves.
 */

import { AuthError } from '../errors.js';
import { audit, emit, type AuthContext, type RequestContext } from '../context.js';
import type { Amr, OrgId, Session, SessionId, User, UserId } from '../ports.js';
import type { CryptoDeps } from './deps.js';
import { resolveAccess } from './orgs.js';

export interface IssuedSession {
  session: Session;
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface IssueSessionInput extends RequestContext {
  user: User;
  /** The factors actually used. Drives step-up and the one-factor-twice rule. */
  amr: Amr[];
  mfaSatisfiedAt?: Date | null;
  orgId?: OrgId | null;
}

export async function issueSession(
  ctx: AuthContext,
  deps: CryptoDeps,
  input: IssueSessionInput,
): Promise<IssuedSession> {
  const now = ctx.clock.now();
  const { refresh } = ctx.config.tokens;

  // Both windows are set from the same instant. The absolute one is never touched
  // again for the life of the session (§5.5.3 step 8).
  const absoluteExpiresAt = new Date(now.getTime() + refresh.absoluteTtl);
  const idleExpiresAt = new Date(
    Math.min(now.getTime() + refresh.idleTtl, absoluteExpiresAt.getTime()),
  );

  const session = await ctx.repos.sessions.create({
    id: ctx.random.uuid(),
    userId: input.user.id,
    orgId: input.orgId ?? null,
    idleExpiresAt,
    absoluteExpiresAt,
    amr: input.amr,
    mfaSatisfiedAt: input.mfaSatisfiedAt ?? null,
    impersonatedBy: null,
  });

  const secret = deps.newSecret('rt');
  await ctx.repos.refreshTokens.issue(session.id, deps.sha256(secret), idleExpiresAt);

  // §10.8 — which tenant, and what they may do in it. A user who belongs to
  // nothing gets a real session with `org: null`; the client's move is to offer to
  // create one, not to treat them as unauthenticated.
  const access_ = await resolveAccess(ctx, input.user.id);
  if (access_.orgId && access_.orgId !== session.orgId) {
    await ctx.repos.sessions.setOrg(session.id, access_.orgId);
  }

  const access = await ctx.tokens.mintAccess({
    sub: input.user.id,
    sid: session.id,
    org: access_.orgId,
    roles: access_.roles,
    perms: access_.perms,
    amr: input.amr,
  });

  await ctx.repos.users.update(input.user.id, { lastLoginAt: now });

  return {
    session: { ...session, orgId: access_.orgId },
    accessToken: access.token,
    refreshToken: secret,
    expiresIn: access.expiresIn,
  };
}

export interface LogoutInput extends RequestContext {
  sessionId: SessionId;
}

/**
 * ⚑ Idempotent, and silent about whether the session existed. A client that
 * retries a logout, or sends one for a session already killed by reuse detection,
 * must get the same answer as the happy path — there is nothing useful to report
 * and something to leak.
 */
export async function logout(ctx: AuthContext, input: LogoutInput): Promise<void> {
  const session = await ctx.repos.sessions.findById(input.sessionId);
  if (!session) return;

  await ctx.repos.refreshTokens.revokeChain(session.id, 'logout');
  await ctx.repos.sessions.revoke(session.id, 'logout');

  await audit(ctx, {
    event: 'auth.logout',
    actorType: 'user',
    actorUserId: session.userId,
    sessionId: session.id,
    ip: input.ip,
    userAgent: input.userAgent,
  });
  await emit(ctx, 'user.logged_out', { userId: session.userId, sessionId: session.id });
}

export interface LogoutAllInput extends RequestContext {
  userId: UserId;
  /** Usually the caller's own session, so "sign out everywhere else" works. */
  exceptSessionId?: SessionId;
}

/**
 * Also revokes trusted devices: signing out everywhere but leaving a device that
 * skips 2FA would make the action a good deal less final than it reads (§5.4.5).
 */
export async function logoutAll(
  ctx: AuthContext,
  input: LogoutAllInput,
): Promise<{ revokedSessions: number }> {
  const sessions = await ctx.repos.sessions.listActive(input.userId);
  for (const session of sessions) {
    if (session.id === input.exceptSessionId) continue;
    await ctx.repos.refreshTokens.revokeChain(session.id, 'logout_all');
  }

  const revokedSessions = await ctx.repos.sessions.revokeAllForUser(
    input.userId,
    'logout_all',
    input.exceptSessionId,
  );
  await ctx.repos.trustedDevices.revokeAllForUser(input.userId);

  await audit(ctx, {
    event: 'auth.logout_all',
    actorType: 'user',
    actorUserId: input.userId,
    ip: input.ip,
    userAgent: input.userAgent,
    metadata: { revokedSessions },
  });

  return { revokedSessions };
}

export interface DeviceSessionView {
  id: SessionId;
  current: boolean;
  amr: Amr[];
  createdAt: Date;
  lastSeenAt: Date;
  absoluteExpiresAt: Date;
}

export async function listSessions(
  ctx: AuthContext,
  userId: UserId,
  currentSessionId: SessionId | null,
): Promise<DeviceSessionView[]> {
  const sessions = await ctx.repos.sessions.listActive(userId);
  return sessions.map((session) => ({
    id: session.id,
    current: session.id === currentSessionId,
    amr: session.amr,
    createdAt: session.createdAt,
    lastSeenAt: session.lastSeenAt,
    absoluteExpiresAt: session.absoluteExpiresAt,
  }));
}

export interface RevokeSessionInput extends RequestContext {
  userId: UserId;
  sessionId: SessionId;
}

export async function revokeSession(ctx: AuthContext, input: RevokeSessionInput): Promise<void> {
  const session = await ctx.repos.sessions.findById(input.sessionId);

  // ⚑ Ownership is checked before existence is admitted. Returning 404 for
  // "someone else's session" and 200 for "yours" would let a caller enumerate
  // session ids belonging to other people.
  if (!session || session.userId !== input.userId) {
    throw new AuthError('NOT_FOUND', 'Session not found');
  }

  await ctx.repos.refreshTokens.revokeChain(session.id, 'admin');
  await ctx.repos.sessions.revoke(session.id, 'admin');

  await audit(ctx, {
    event: 'session.revoked_by_admin',
    actorType: 'user',
    actorUserId: input.userId,
    sessionId: session.id,
    ip: input.ip,
    userAgent: input.userAgent,
  });
}
