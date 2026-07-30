/**
 * Ports — the module's entire coupling surface (AUTH-MODULE-PLAN.md §6).
 *
 * Nothing in this file imports a framework, a driver, or a logger. Implement
 * these and the module runs on any stack; that is the whole genericity contract.
 * Adapters live in packages/db, packages/crypto, packages/mail.
 */

export type UserId = string;
export type SessionId = string;
export type OrgId = string;
export type ChallengeId = string;
export type DeviceId = string;

export type UserStatus = 'pending' | 'active' | 'suspended' | 'deleted';
export type RevokeReason =
  | 'logout'
  | 'logout_all'
  | 'password_change'
  | 'email_change'
  | 'mfa_change'
  | 'reuse_detected'
  | 'idle_timeout'
  | 'absolute_timeout'
  | 'admin'
  | 'suspended'
  | 'deleted'
  | 'key_rotation';

/** Authentication methods present on a session — RFC 8176 style (§8.4). */
export type Amr = 'pwd' | 'otp' | 'totp' | 'webauthn' | 'device' | 'oauth' | 'impersonation';

export type OtpPurpose = 'login' | 'mfa' | 'step_up' | 'phone_verify';
export type OtpChannel = 'email' | 'sms';
export type OneTimeTokenPurpose =
  | 'email_verify'
  | 'password_reset'
  | 'magic_link'
  | 'email_change'
  | 'org_invite';

export interface User {
  id: UserId;
  email: string | null;
  emailVerifiedAt: Date | null;
  phone: string | null;
  phoneVerifiedAt: Date | null;
  passwordHash: string | null;
  passwordAlgo: string | null;
  passwordUpdatedAt: Date | null;
  status: UserStatus;
  name: string | null;
  mfaRequiredAt: Date | null;
  failedLoginCount: number;
  lockedUntil: Date | null;
  lastLoginAt: Date | null;
  createdAt: Date;
}

export interface Session {
  id: SessionId;
  userId: UserId;
  orgId: OrgId | null;
  createdAt: Date;
  lastSeenAt: Date;
  idleExpiresAt: Date;
  absoluteExpiresAt: Date;
  revokedAt: Date | null;
  revokedReason: RevokeReason | null;
  amr: Amr[];
  mfaSatisfiedAt: Date | null;
  impersonatedBy: UserId | null;
}

export interface RefreshTokenRow {
  id: string;
  sessionId: SessionId;
  issuedAt: Date;
  expiresAt: Date;
  usedAt: Date | null;
  replacedById: string | null;
  revokedAt: Date | null;
}

/**
 * The outcome of presenting a refresh token (§5.5.3 steps 2–6, 13).
 * `reuse` is the theft signal; `concurrent` is the benign race that must NOT be
 * treated as theft.
 */
export type RefreshClaim =
  | { outcome: 'ok'; token: RefreshTokenRow }
  | { outcome: 'unknown' }
  | { outcome: 'reuse'; token: RefreshTokenRow }
  | { outcome: 'revoked'; token: RefreshTokenRow }
  | { outcome: 'expired'; token: RefreshTokenRow }
  | { outcome: 'concurrent'; token: RefreshTokenRow };

export interface OtpChallenge {
  id: ChallengeId;
  userId: UserId | null;
  purpose: OtpPurpose;
  channel: OtpChannel;
  attempts: number;
  maxAttempts: number;
  resendCount: number;
  expiresAt: Date;
  consumedAt: Date | null;
  lastSentAt: Date;
}

// ── Persistence ports ───────────────────────────────────────────────────────

export interface UserRepo {
  findById(id: UserId): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  create(input: Partial<User> & { email: string }): Promise<User>;
  update(id: UserId, patch: Partial<User>): Promise<User>;
  /** Atomic: increments and locks in one statement so parallel guesses can't outrun it. */
  registerFailedLogin(
    id: UserId,
    lockAfter: number,
    lockForMs: number,
  ): Promise<{ failedLoginCount: number; lockedUntil: Date | null }>;
  clearFailedLogins(id: UserId): Promise<void>;
}

export interface SessionRepo {
  create(input: Omit<Session, 'createdAt' | 'lastSeenAt' | 'revokedAt' | 'revokedReason'>): Promise<Session>;
  findById(id: SessionId): Promise<Session | null>;
  listActive(userId: UserId): Promise<Session[]>;
  touch(id: SessionId, at: Date, idleExpiresAt: Date): Promise<void>;
  revoke(id: SessionId, reason: RevokeReason): Promise<void>;
  revokeAllForUser(userId: UserId, reason: RevokeReason, except?: SessionId): Promise<number>;
}

export interface RefreshTokenRepo {
  issue(sessionId: SessionId, hash: Uint8Array, expiresAt: Date): Promise<RefreshTokenRow>;
  /** ⚑ Must mark used and return the row in ONE atomic statement (§5.5.3 step 13). */
  claim(hash: Uint8Array, graceMs: number): Promise<RefreshClaim>;
  link(tokenId: string, replacedById: string): Promise<void>;
  /** Kills the whole family — the point of rotation (§5.5.4). */
  revokeChain(sessionId: SessionId, reason: RevokeReason): Promise<number>;
}

export interface OneTimeTokenRepo {
  issue(input: {
    userId: UserId | null;
    purpose: OneTimeTokenPurpose;
    hash: Uint8Array;
    payload?: Record<string, unknown>;
    expiresAt: Date;
    requestedIp?: string | null;
  }): Promise<void>;
  /** ⚑ Single atomic UPDATE ... WHERE consumed_at IS NULL RETURNING (§4.4). */
  consume(
    hash: Uint8Array,
    purpose: OneTimeTokenPurpose,
  ): Promise<{ userId: UserId | null; payload: Record<string, unknown> } | null>;
  revokeAllForUser(userId: UserId, purpose: OneTimeTokenPurpose): Promise<number>;
}

export interface OtpChallengeRepo {
  create(input: {
    userId: UserId | null;
    purpose: OtpPurpose;
    channel: OtpChannel;
    destinationHash: Uint8Array;
    codeHash: Uint8Array;
    maxAttempts: number;
    clientBinding: Uint8Array | null;
    expiresAt: Date;
  }): Promise<OtpChallenge>;
  /** ⚑ Atomic attempt accounting; null when consumed, expired, or capped (§5.11.2). */
  claimAttempt(id: ChallengeId): Promise<(OtpChallenge & { codeHash: Uint8Array; clientBinding: Uint8Array | null }) | null>;
  markConsumed(id: ChallengeId): Promise<void>;
  /** Enforces singleActiveChallenge — call before creating a new one. */
  invalidateActive(destinationHash: Uint8Array, purpose: OtpPurpose): Promise<number>;
  registerResend(id: ChallengeId, minIntervalMs: number, maxResends: number): Promise<'sent' | 'too_soon' | 'exhausted'>;
}

export interface TrustedDeviceRepo {
  create(input: { userId: UserId; hash: Uint8Array; label: string | null; expiresAt: Date; mfaSatisfiedAt: Date }): Promise<{ id: DeviceId }>;
  findValidByHash(hash: Uint8Array): Promise<{ id: DeviceId; userId: UserId } | null>;
  listForUser(userId: UserId): Promise<Array<{ id: DeviceId; label: string | null; lastUsedAt: Date | null; expiresAt: Date }>>;
  revoke(id: DeviceId): Promise<void>;
  revokeAllForUser(userId: UserId): Promise<number>;
}

export interface AuditEvent {
  event: string;
  actorType: 'user' | 'system' | 'api_key' | 'support';
  actorUserId?: UserId | null;
  orgId?: OrgId | null;
  targetType?: string | null;
  targetId?: string | null;
  sessionId?: SessionId | null;
  ip?: string | null;
  userAgent?: string | null;
  outcome?: 'success' | 'failure';
  metadata?: Record<string, unknown>;
}

export interface AuditRepo {
  append(event: AuditEvent): Promise<void>;
}

export interface UnitOfWork<Repos> {
  transaction<T>(fn: (repos: Repos) => Promise<T>, opts?: { isolation?: 'serializable' | 'repeatable read' }): Promise<T>;
}

// ── Service ports ───────────────────────────────────────────────────────────

export interface HashResult {
  hash: string;
  algo: string;
}

export interface PasswordHasher {
  hash(plain: string): Promise<HashResult>;
  verify(plain: string, hash: string): Promise<boolean>;
  /** True for legacy algorithms — triggers lazy rehash on successful login (§5.3 step 5). */
  needsRehash(hash: string): boolean;
}

export interface AccessClaims {
  sub: UserId;
  sid: SessionId;
  org?: OrgId | null;
  roles?: string[];
  perms?: string[];
  amr: Amr[];
}

export interface TokenService {
  mintAccess(claims: AccessClaims): Promise<{ token: string; expiresIn: number }>;
  verifyAccess(token: string): Promise<AccessClaims & { iat: number; exp: number; jti: string }>;
  jwks(): Promise<{ keys: unknown[] }>;
}

export interface RateLimitDecision {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

export interface RateLimiter {
  consume(key: string, limit: number, windowMs: number): Promise<RateLimitDecision>;
  reset(key: string): Promise<void>;
}

export interface RenderedMail {
  to: string;
  subject: string;
  html: string;
  text: string;
}

export interface Mailer {
  send(mail: RenderedMail): Promise<void>;
}

/** Optional — only wired when the SMS channel is enabled (§5.4, A12). */
export interface SmsSender {
  send(to: string, body: string): Promise<void>;
}

export interface Clock {
  now(): Date;
}

export interface RandomSource {
  bytes(n: number): Uint8Array;
  /** Time-sortable UUIDv7 — index locality on every insert. */
  uuid(): string;
  /** ⚑ CSPRNG + rejection sampling, never modulo (§5.11.1). */
  digits(length: number): string;
}

export interface Logger {
  debug(obj: unknown, msg?: string): void;
  info(obj: unknown, msg?: string): void;
  warn(obj: unknown, msg?: string): void;
  error(obj: unknown, msg?: string): void;
}

/** Domain events (§6). ⚑ Handlers must never be able to block or fail a login. */
export interface AuthDomainEvent {
  type: string;
  at: Date;
  payload: Record<string, unknown>;
}

export interface EventBus {
  publish(event: AuthDomainEvent): Promise<void>;
}

export interface BreachChecker {
  /** HIBP range API — k-anonymity, only the first 5 SHA-1 hex chars leave the process. */
  isBreached(plain: string): Promise<boolean>;
}
