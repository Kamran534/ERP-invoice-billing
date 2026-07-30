/**
 * The error model is public API: clients branch on `code`, and the 401/403 split
 * decides whether a client retries or gives up (AUTH-MODULE-PLAN.md §1.7, §10.4).
 * These tests pin that contract.
 */

import { describe, it, expect } from 'vitest';
import { AUTH_ERROR_CODES, AuthError, errors, isAuthError, isClientSafe } from './errors.js';

describe('status mapping', () => {
  it('maps every code to a sane HTTP status', () => {
    for (const [code, status] of Object.entries(AUTH_ERROR_CODES)) {
      expect(status, `${code} has an out-of-range status`).toBeGreaterThanOrEqual(400);
      expect(status, `${code} has an out-of-range status`).toBeLessThan(600);
    }
  });

  it('keeps the 401/403 distinction that clients depend on', () => {
    // 401 = no valid credential → refresh, then re-login.
    expect(AUTH_ERROR_CODES.INVALID_CREDENTIALS).toBe(401);
    expect(AUTH_ERROR_CODES.INVALID_REFRESH_TOKEN).toBe(401);
    expect(AUTH_ERROR_CODES.SESSION_EXPIRED).toBe(401);
    expect(AUTH_ERROR_CODES.MFA_REQUIRED).toBe(401);

    // 403 = authenticated but not permitted → do not retry.
    expect(AUTH_ERROR_CODES.PERMISSION_DENIED).toBe(403);
    expect(AUTH_ERROR_CODES.REAUTH_REQUIRED).toBe(403);
    expect(AUTH_ERROR_CODES.MFA_ENROLLMENT_REQUIRED).toBe(403);
  });

  it('uses 409 for the benign refresh race, never 401', () => {
    // Conflating this with 401 is what makes clients log users out on a race
    // instead of retrying once (§5.5.5).
    expect(AUTH_ERROR_CODES.REFRESH_IN_PROGRESS).toBe(409);
  });

  it('uses 410 for consumed/expired one-time tokens so the UI can offer a resend', () => {
    expect(AUTH_ERROR_CODES.CODE_EXPIRED).toBe(410);
  });

  it('uses 423 for lockout, distinct from a wrong password', () => {
    expect(AUTH_ERROR_CODES.ACCOUNT_LOCKED).toBe(423);
    expect(AUTH_ERROR_CODES.ACCOUNT_LOCKED).not.toBe(AUTH_ERROR_CODES.INVALID_CREDENTIALS);
  });
});

describe('AuthError', () => {
  it('derives status from the code and is identifiable across module boundaries', () => {
    const error = new AuthError('PERMISSION_DENIED');
    expect(error.status).toBe(403);
    expect(error.name).toBe('AuthError');
    expect(isAuthError(error)).toBe(true);
    expect(isAuthError(new Error('nope'))).toBe(false);
    expect(isAuthError(null)).toBe(false);
  });

  it('allows an explicit status override', () => {
    expect(new AuthError('VALIDATION_FAILED', 'x', { status: 422 }).status).toBe(422);
  });

  it('falls back to the code as the message', () => {
    expect(new AuthError('NOT_FOUND').message).toBe('NOT_FOUND');
  });

  it('preserves the cause for logging without exposing it', () => {
    const cause = new Error('connection reset');
    const error = new AuthError('INTERNAL', 'Internal server error', { cause });
    expect(error.cause).toBe(cause);
    expect(JSON.stringify(error.toJSON())).not.toContain('connection reset');
  });

  it('serializes only code, message and details — never a stack', () => {
    const json = new AuthError('INVALID_CODE', 'Incorrect code', {
      details: { attemptsRemaining: 3 },
    }).toJSON();
    expect(json).toEqual({
      code: 'INVALID_CODE',
      message: 'Incorrect code',
      details: { attemptsRemaining: 3 },
    });
    expect(Object.keys(json)).not.toContain('stack');
  });

  it('omits details entirely when there are none', () => {
    expect(new AuthError('NOT_FOUND').toJSON()).not.toHaveProperty('details');
  });
});

describe('isClientSafe', () => {
  it('treats 4xx as safe to forward', () => {
    expect(isClientSafe(new AuthError('INVALID_CREDENTIALS'))).toBe(true);
    expect(isClientSafe(new AuthError('RATE_LIMITED'))).toBe(true);
  });

  it('hides genuine server errors', () => {
    // The message would leak schema names, paths and query fragments.
    expect(isClientSafe(new AuthError('INTERNAL'))).toBe(false);
  });

  it('exposes the two deliberate 5xx signals', () => {
    // A 501 status with an "Internal server error" body is a confusing lie, and
    // a 503 needs to reach the client for Retry-After to mean anything.
    expect(isClientSafe(errors.notImplemented('§5.3'))).toBe(true);
    expect(isClientSafe(new AuthError('SERVICE_UNAVAILABLE'))).toBe(true);
  });
});

describe('error factories', () => {
  it('invalidCredentials says nothing about which half was wrong', () => {
    const error = errors.invalidCredentials();
    expect(error.code).toBe('INVALID_CREDENTIALS');
    // Enumeration resistance starts with not writing "no such user" in the copy.
    expect(error.message.toLowerCase()).not.toMatch(/not found|no such|unknown user|exist/);
  });

  it('accountLocked reports lockedUntil and a positive Retry-After', () => {
    const until = new Date(Date.now() + 15 * 60_000);
    const error = errors.accountLocked(until);
    expect(error.status).toBe(423);
    expect(error.details?.['lockedUntil']).toBe(until.toISOString());
    expect(error.retryAfter).toBeGreaterThan(0);
    expect(error.retryAfter).toBeLessThanOrEqual(900);
  });

  it('accountLocked never emits a negative Retry-After for a past date', () => {
    // A negative Retry-After header is invalid and some proxies drop the response.
    expect(errors.accountLocked(new Date(Date.now() - 60_000)).retryAfter).toBeGreaterThanOrEqual(1);
  });

  it('mfaRequired carries the challenge token and method list, and nothing else', () => {
    const error = errors.mfaRequired('challenge-abc', ['totp', 'email_otp']);
    expect(error.status).toBe(401);
    expect(error.details).toEqual({
      mfaToken: 'challenge-abc',
      availableMethods: ['totp', 'email_otp'],
    });
    // No session, no access token — nothing is authenticated at this point.
    expect(JSON.stringify(error.details)).not.toMatch(/accessToken|refreshToken|sid/);
  });

  it('reauthRequired is the one 403 a client should act on', () => {
    const error = errors.reauthRequired(['password', 'totp']);
    expect(error.status).toBe(403);
    expect(error.code).toBe('REAUTH_REQUIRED');
    expect(error.details?.['reauthMethods']).toEqual(['password', 'totp']);
  });

  it('invalidCode reports attemptsRemaining so the UI can warn before lockout', () => {
    expect(errors.invalidCode(2).details?.['attemptsRemaining']).toBe(2);
  });

  it('challengeExhausted tells the user to request a new code, not to retry', () => {
    const error = errors.challengeExhausted();
    expect(error.status).toBe(429);
    expect(error.message).toMatch(/new code/i);
  });

  it('rateLimited sets Retry-After', () => {
    expect(errors.rateLimited(42).retryAfter).toBe(42);
  });

  it('permissionDenied names the missing permission only when given one', () => {
    expect(errors.permissionDenied('invoice:write').details?.['requiredPermission']).toBe(
      'invoice:write',
    );
    expect(errors.permissionDenied().details).toBeUndefined();
  });

  it('notImplemented points at the plan section that specifies it', () => {
    const error = errors.notImplemented('§5.5 (Phase 1)');
    expect(error.status).toBe(501);
    expect(error.message).toContain('AUTH-MODULE-PLAN.md');
    expect(error.details?.['plannedIn']).toBe('§5.5 (Phase 1)');
  });
});
