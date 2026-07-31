/**
 * Where the tokens live on the wire (AUTH-MODULE-PLAN.md §5.5.6).
 *
 * All cookie handling is here rather than in the handlers, because the flags are
 * the security property and they must not drift between the route that sets a
 * cookie and the route that clears it. A `Path` mismatch on clear leaves a live
 * refresh token in the browser after logout — which looks like it worked.
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import type { AuthConfig } from '@auth/core';

/** Options shared by every cookie we set. `secure` follows `HTTPS_ENABLED`. */
function base(config: AuthConfig) {
  return {
    secure: config.cookies.secure,
    sameSite: config.cookies.sameSite,
    ...(config.cookies.domain ? { domain: config.cookies.domain } : {}),
  } as const;
}

export interface SessionCookies {
  accessToken: string;
  /**
   * Omitted when only the access token is being replaced — an org switch (§10.9)
   * mints a new access token and deliberately does *not* rotate the refresh chain,
   * because the identity has not changed. Overwriting the refresh cookie there
   * would leave every tab that had not switched holding a spent token, which is
   * indistinguishable from theft.
   */
  refreshToken?: string;
  /** Seconds — mirrors the access token, so the cookie dies with the token. */
  expiresIn: number;
  csrfToken: string;
}

export function setSessionCookies(
  reply: FastifyReply,
  config: AuthConfig,
  tokens: SessionCookies,
): void {
  const { names, refreshPath } = config.cookies;
  const shared = base(config);

  reply.setCookie(names.access, tokens.accessToken, {
    ...shared,
    httpOnly: true,
    path: '/',
    maxAge: tokens.expiresIn,
  });

  // ⚑ Scoped to the refresh endpoint. The refresh token is the long-lived
  // credential, and a cookie scoped to `/` is attached to every API call — so an
  // ordinary request log, a proxy, or a mis-set CORS header on any route becomes
  // an exposure of the one token that can mint new sessions.
  if (tokens.refreshToken !== undefined) {
    reply.setCookie(names.refresh, tokens.refreshToken, {
      ...shared,
      httpOnly: true,
      path: refreshPath,
      maxAge: Math.floor(config.tokens.refresh.idleTtl / 1_000),
    });
  }

  // ⚑ Deliberately readable by JavaScript — that is the whole mechanism. The
  // client reads it and echoes it in a header, and an attacker on another origin
  // can cause the cookie to be *sent* but cannot *read* it to build the header.
  reply.setCookie(names.csrf, tokens.csrfToken, {
    ...shared,
    httpOnly: false,
    path: '/',
    maxAge: Math.floor(config.tokens.refresh.idleTtl / 1_000),
  });
}

/**
 * ⚑ Clearing must repeat the exact `path` and `domain` the cookie was set with.
 * A browser treats `(name, domain, path)` as the identity, so clearing
 * `__Host-rt` at `/` leaves the one at `/auth/token` alive — a logout that
 * returns 204 and signs nobody out.
 */
export function clearSessionCookies(reply: FastifyReply, config: AuthConfig): void {
  const { names, refreshPath } = config.cookies;
  const shared = base(config);

  reply.clearCookie(names.access, { ...shared, httpOnly: true, path: '/' });
  reply.clearCookie(names.refresh, { ...shared, httpOnly: true, path: refreshPath });
  reply.clearCookie(names.csrf, { ...shared, httpOnly: false, path: '/' });
}

export function readCookie(request: FastifyRequest, name: string): string | null {
  return request.cookies[name] ?? null;
}

/**
 * The access token, from whichever transport the deployment uses.
 *
 * Bearer wins when both are present. A caller that went to the trouble of setting
 * an `Authorization` header meant it; silently preferring an ambient cookie is how
 * one tab's session answers another tab's deliberate request.
 */
export function readAccessToken(request: FastifyRequest, config: AuthConfig): string | null {
  const { mode, names } = config.cookies;

  if (mode !== 'cookie') {
    const header = request.headers.authorization;
    // ⚑ Present means used, even when malformed — the early `return` is the point,
    // not an accident of style. The CSRF hook skips its check whenever it sees a
    // `Bearer ` header, on the grounds that an explicit credential is not ambient;
    // if this fell back to the cookie for an empty or broken header, that skip
    // would become a bypass. The two must decide identically.
    if (header?.startsWith('Bearer ')) return header.slice(7).trim() || null;
  }

  if (mode !== 'bearer') return readCookie(request, names.access);
  return null;
}

/**
 * The refresh token. In bearer mode it arrives in the body, because a native
 * client has no cookie jar; in cookie mode the body is ignored entirely so a
 * cross-origin form post cannot supply one.
 */
export function readRefreshToken(
  request: FastifyRequest,
  config: AuthConfig,
  body: { refreshToken?: string } | undefined,
): string | null {
  const { mode, names } = config.cookies;
  if (mode !== 'bearer') {
    const fromCookie = readCookie(request, names.refresh);
    if (fromCookie) return fromCookie;
  }
  if (mode !== 'cookie') return body?.refreshToken ?? null;
  return null;
}
