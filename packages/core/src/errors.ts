/**
 * Typed, stable error model (AUTH-MODULE-PLAN.md §1.7, §10.4).
 *
 * Rules:
 *  - `code` is the machine-readable contract. It is public API: never rename one
 *    without a version bump. Clients branch on it.
 *  - `message` is a developer-facing default. Human-facing copy lives in the
 *    host app's i18n bundle, keyed by `code`.
 *  - 401 = "no valid credential, try refreshing then re-login".
 *    403 = "authenticated but not allowed, do not retry" — except REAUTH_REQUIRED,
 *    the one 403 a client should act on by prompting for step-up.
 *  - `details` must never contain a secret. It is serialized to the client.
 */

export const AUTH_ERROR_CODES = {
  // ── credentials / login ──────────────────────────────────────────────────
  // Deliberately identical for "no such user" and "wrong password" (§5.3 ⚑).
  INVALID_CREDENTIALS: 401,
  ACCOUNT_LOCKED: 423,
  ACCOUNT_SUSPENDED: 403,
  ACCOUNT_INACTIVE: 401,
  EMAIL_NOT_VERIFIED: 403,

  // ── OTP (§5.11) ──────────────────────────────────────────────────────────
  INVALID_CODE: 401,
  CODE_EXPIRED: 410,
  CHALLENGE_EXHAUSTED: 429,
  CHALLENGE_NOT_FOUND: 404,
  RESEND_TOO_SOON: 429,

  // ── 2FA (§5.4) ───────────────────────────────────────────────────────────
  MFA_REQUIRED: 401,
  MFA_ENROLLMENT_REQUIRED: 403,
  MFA_REQUIRED_BY_POLICY: 403,
  MFA_FACTOR_NOT_CONFIRMED: 409,
  REAUTH_REQUIRED: 403,

  // ── sessions & refresh (§5.5) ────────────────────────────────────────────
  INVALID_REFRESH_TOKEN: 401,
  REFRESH_EXPIRED: 401,
  REFRESH_IN_PROGRESS: 409,
  SESSION_REVOKED: 401,
  SESSION_EXPIRED: 401,
  SESSION_IDLE_TIMEOUT: 401,
  CREDENTIALS_CHANGED: 401,
  TOKEN_INVALID: 401,
  CSRF_FAILED: 403,

  // ── passwords (§8.1) ─────────────────────────────────────────────────────
  WEAK_PASSWORD: 422,
  PASSWORD_BREACHED: 422,
  PASSWORD_REUSED: 422,

  // ── authorization (§10) ──────────────────────────────────────────────────
  PERMISSION_DENIED: 403,
  ORG_CONTEXT_REQUIRED: 400,

  // ── generic ──────────────────────────────────────────────────────────────
  VALIDATION_FAILED: 400,
  NOT_FOUND: 404,
  CONFLICT: 409,
  RATE_LIMITED: 429,
  PAYLOAD_TOO_LARGE: 413,
  NOT_IMPLEMENTED: 501,
  SERVICE_UNAVAILABLE: 503,
  INTERNAL: 500,
} as const;

export type AuthErrorCode = keyof typeof AUTH_ERROR_CODES;

export interface AuthErrorOptions {
  /** Safe, client-visible context. Never put secrets or PII here. */
  details?: Record<string, unknown>;
  /** Override the default status for this code. */
  status?: number;
  /** Seconds — sets Retry-After on 429/503. */
  retryAfter?: number;
  cause?: unknown;
}

export class AuthError extends Error {
  readonly code: AuthErrorCode;
  readonly status: number;
  readonly details?: Record<string, unknown>;
  readonly retryAfter?: number;

  constructor(code: AuthErrorCode, message?: string, options: AuthErrorOptions = {}) {
    super(message ?? code, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'AuthError';
    this.code = code;
    this.status = options.status ?? AUTH_ERROR_CODES[code];
    this.details = options.details;
    this.retryAfter = options.retryAfter;
    Error.captureStackTrace?.(this, AuthError);
  }

  /** Wire format. `traceId` is stamped by the HTTP layer, not here. */
  toJSON(): { code: AuthErrorCode; message: string; details?: Record<string, unknown> } {
    return {
      code: this.code,
      message: this.message,
      ...(this.details ? { details: this.details } : {}),
    };
  }
}

export function isAuthError(e: unknown): e is AuthError {
  return e instanceof AuthError;
}

/**
 * A handful of 5xx codes are deliberate, informative signals rather than leaked
 * internals: 501 says "this endpoint isn't built yet" and 503 says "retry".
 * Neither reveals anything about the server's internals, and masking them as
 * INTERNAL would produce the confusing combination of a 501 status with an
 * "Internal server error" body.
 */
const EXPOSED_SERVER_CODES: ReadonlySet<AuthErrorCode> = new Set([
  'NOT_IMPLEMENTED',
  'SERVICE_UNAVAILABLE',
]);

/** Any other 5xx must never forward its message to a client. */
export function isClientSafe(e: AuthError): boolean {
  return e.status < 500 || EXPOSED_SERVER_CODES.has(e.code);
}

// ── Named constructors for the codes with non-obvious payloads ─────────────

export const errors = {
  invalidCredentials: () => new AuthError('INVALID_CREDENTIALS', 'Invalid email or password'),

  accountLocked: (until: Date) =>
    new AuthError('ACCOUNT_LOCKED', 'Too many failed attempts', {
      details: { lockedUntil: until.toISOString() },
      retryAfter: Math.max(1, Math.ceil((until.getTime() - Date.now()) / 1000)),
    }),

  /** §5.4.2 — carries the methods the UI should offer. Never carries a session. */
  mfaRequired: (mfaToken: string, availableMethods: readonly string[]) =>
    new AuthError('MFA_REQUIRED', 'Second factor required', {
      details: { mfaToken, availableMethods },
    }),

  /** §5.4.7 — the one 403 a client should act on. */
  reauthRequired: (reauthMethods: readonly string[]) =>
    new AuthError('REAUTH_REQUIRED', 'Re-authentication required for this action', {
      details: { reauthMethods },
    }),

  invalidCode: (attemptsRemaining: number) =>
    new AuthError('INVALID_CODE', 'Incorrect code', { details: { attemptsRemaining } }),

  challengeExhausted: () =>
    new AuthError('CHALLENGE_EXHAUSTED', 'Too many incorrect attempts — request a new code'),

  rateLimited: (retryAfterSeconds: number) =>
    new AuthError('RATE_LIMITED', 'Too many requests', { retryAfter: retryAfterSeconds }),

  permissionDenied: (permission?: string) =>
    new AuthError('PERMISSION_DENIED', 'You do not have permission to do that', {
      ...(permission ? { details: { requiredPermission: permission } } : {}),
    }),

  /** Scaffold marker: the contract is real, the use-case lands in a later phase. */
  notImplemented: (plannedIn: string) =>
    new AuthError('NOT_IMPLEMENTED', `Not implemented yet — see docs/AUTH-MODULE-PLAN.md ${plannedIn}`, {
      details: { plannedIn },
    }),

  internal: (cause?: unknown) =>
    new AuthError('INTERNAL', 'Internal server error', { cause }),
} as const;
