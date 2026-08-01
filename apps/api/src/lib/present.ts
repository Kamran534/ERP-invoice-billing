/**
 * Domain objects → the wire shapes in `schemas/auth.ts`.
 *
 * One place, because the alternative is each handler building `publicUser` by
 * hand and one of them eventually including a field the schema does not publish —
 * which Fastify's serializer would silently strip, or worse, wouldn't.
 */

import type { FastifyRequest } from 'fastify';
import type { AuthConfig, DeviceSessionView, IssuedSession, User } from '@auth/core';

export interface PublicUser {
  id: string;
  email: string | null;
  emailVerified: boolean;
  /** §10.12 — an employee's login name; null for accounts that signed up by email. */
  username: string | null;
  name: string | null;
  status: 'pending' | 'active' | 'suspended';
  mfaEnrolled: boolean;
  createdAt: string;
}

export function presentUser(user: User, mfaEnrolled: boolean): PublicUser {
  return {
    id: user.id,
    email: user.email,
    emailVerified: user.emailVerifiedAt !== null,
    username: user.username,
    // `deleted` is not in the published union, and a deleted user should never
    // reach a serializer anyway — the flows refuse them earlier.
    status: user.status === 'deleted' ? 'suspended' : user.status,
    name: user.name,
    mfaEnrolled,
    createdAt: user.createdAt.toISOString(),
  };
}

/**
 * ⚑ The tokens are omitted in cookie mode, not merely ignored. Returning them in
 * the body as well would put the refresh token everywhere a response body goes —
 * a log, a service worker cache, a browser devtools panel someone screenshots —
 * which is exactly what httpOnly cookies are for avoiding.
 */
export function presentSession(
  config: AuthConfig,
  issued: IssuedSession,
  user: PublicUser,
): { accessToken?: string; refreshToken?: string; expiresIn: number; user: PublicUser } {
  const bearer = config.cookies.mode !== 'cookie';
  return {
    ...(bearer ? { accessToken: issued.accessToken, refreshToken: issued.refreshToken } : {}),
    expiresIn: issued.expiresIn,
    user,
  };
}

export function presentDeviceSession(view: DeviceSessionView): {
  id: string;
  current: boolean;
  deviceLabel: string | null;
  ip: string | null;
  amr: string[];
  createdAt: string;
  lastSeenAt: string;
  absoluteExpiresAt: string;
} {
  return {
    id: view.id,
    current: view.current,
    // Both are recorded on the session row but not surfaced by the use-case's
    // view yet. The contract publishes them, so they are explicitly null rather
    // than absent — a client can render "unknown device" instead of crashing.
    deviceLabel: null,
    ip: null,
    amr: view.amr,
    createdAt: view.createdAt.toISOString(),
    lastSeenAt: view.lastSeenAt.toISOString(),
    absoluteExpiresAt: view.absoluteExpiresAt.toISOString(),
  };
}

/** What the use-cases record on audit rows and bind challenges to. */
export function requestContext(request: FastifyRequest): {
  ip: string | null;
  userAgent: string | null;
} {
  return {
    ip: request.ip ?? null,
    userAgent: request.headers['user-agent'] ?? null,
  };
}
