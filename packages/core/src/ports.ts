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
  | 'org_invite'
  // The 2FA challenge (§5.4.2). Reuses this table because single-use atomic
  // consumption, a TTL and a payload are exactly what it needs, and purpose is a
  // text column so widening this union requires no migration.
  | 'mfa_challenge';

export interface User {
  id: UserId;
  email: string | null;
  emailVerifiedAt: Date | null;
  phone: string | null;
  phoneVerifiedAt: Date | null;
  passwordHash: string | null;
  /** Narrow, so a legacy hash cannot be recorded under an invented algorithm name. */
  passwordAlgo: 'argon2id' | 'bcrypt' | null;
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
  /**
   * Read the row, then claim it with a guarded `UPDATE ... WHERE used_at IS NULL`
   * (§5.5.3).
   *
   * ⚑ `concurrent` is a proof: the guard failed after a clean read, so someone
   * claimed the token in between. `reuse` is **not** a proof — it means only that
   * the row was already spent when we looked, which a sibling request arriving
   * milliseconds late produces just as readily as a thief. `token.usedAt` carries
   * the fact the use-case needs to tell them apart.
   *
   * Returns a classification only. Both the in-flight window and the grace window
   * live in the use-case, because whether to forgive a presentation is a decision,
   * not a database fact.
   */
  claim(hash: Uint8Array): Promise<RefreshClaim>;
  link(tokenId: string, replacedById: string): Promise<void>;
  /** Kills the whole family — the point of rotation (§5.5.4). */
  revokeChain(sessionId: SessionId, reason: RevokeReason): Promise<number>;
  findBySessionAndSuccessor(tokenId: string): Promise<RefreshTokenRow | null>;
}

// ── Second factors ──────────────────────────────────────────────────────────

export type MfaFactorType = 'totp' | 'webauthn' | 'sms';

export interface MfaFactor {
  id: string;
  userId: UserId;
  type: MfaFactorType;
  label: string | null;
  secretEnc: Uint8Array | null;
  confirmedAt: Date | null;
  lastUsedAt: Date | null;
  /** ⚑ Last accepted TOTP timestep. A code at or below this is a replay (§5.4.3). */
  lastUsedTimestep: number | null;
  createdAt: Date;
}

export interface MfaRepo {
  addFactor(input: {
    userId: UserId;
    type: MfaFactorType;
    label: string | null;
    secretEnc: Uint8Array | null;
  }): Promise<MfaFactor>;
  findFactor(id: string): Promise<MfaFactor | null>;
  /** Confirmed factors only — an unconfirmed one must never satisfy a challenge. */
  listConfirmedFactors(userId: UserId): Promise<MfaFactor[]>;
  listAllFactors(userId: UserId): Promise<MfaFactor[]>;
  confirmFactor(id: string, at: Date): Promise<void>;
  touchFactor(id: string, at: Date): Promise<void>;
  /**
   * ⚑ Records the timestep a code matched, atomically and only if it advances.
   * Returns false when the step is not newer — which is a replay, and the caller
   * must refuse even though the code verified.
   */
  advanceTimestep(id: string, at: Date, timestep: number): Promise<boolean>;
  removeFactor(id: string): Promise<void>;
  /** Purges unconfirmed factors older than the cutoff (§5.4.1). */
  purgeUnconfirmed(userId: UserId, olderThan: Date): Promise<number>;

  /** Replaces the whole set atomically — regenerating invalidates every old code. */
  replaceRecoveryCodes(userId: UserId, hashes: Uint8Array[]): Promise<void>;
  /** ⚑ Single atomic consume; a code must never be usable twice. */
  consumeRecoveryCode(userId: UserId, hash: Uint8Array): Promise<boolean>;
  countUnusedRecoveryCodes(userId: UserId): Promise<number>;
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
  /**
   * For tokens that are *presented against* rather than redeemed — the 2FA
   * challenge, where the token names the challenge and a separate code is guessed.
   *
   * ⚑ Increments and checks the cap in one statement, so parallel guesses cannot
   * each read the same pre-increment count. Returns null when the token is
   * unknown, consumed, expired, or out of attempts — the caller must not be able
   * to tell those apart. The row is *not* consumed; a correct code does that.
   */
  claimAttempt(
    hash: Uint8Array,
    purpose: OneTimeTokenPurpose,
  ): Promise<{
    id: string;
    userId: UserId | null;
    payload: Record<string, unknown>;
    attemptsRemaining: number;
  } | null>;
  markConsumed(id: string): Promise<void>;
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
  /** Records use. ⚑ Must not extend `expires_at` — the 30-day cap never slides (§5.4.5). */
  touch(id: DeviceId, at: Date): Promise<void>;
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
  /**
   * ⚑ Verify against a fixed internal hash and always return false. Called on the
   * no-such-user and no-password paths so they cost what a real verify costs
   * (§5.3 step 2). Returning `false` rather than `void` lets the caller write the
   * two branches identically.
   */
  verifyDummy(plain: string): Promise<false>;
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

/**
 * Authenticated encryption for the few secrets that must be recoverable rather
 * than hashed — a TOTP secret has to be readable to verify a code (§4.3).
 *
 * ⚑ `purpose` is bound as associated data, so a ciphertext cannot be moved from
 * one use to another. Implemented by `@auth/crypto`; named differently from its
 * `Aead` so importing both is unambiguous.
 */
export interface SecretBox {
  encrypt(plaintext: string, purpose: 'totp-secret' | 'signing-key'): Uint8Array;
  decrypt(payload: Uint8Array, purpose: 'totp-secret' | 'signing-key'): string;
}

export interface TotpSecret {
  /** Base32 — what the user types when they cannot scan the QR code. */
  base32: string;
}

export interface TotpVerification {
  valid: boolean;
  /**
   * ⚑ The absolute timestep the code matched, or null. The caller must record it:
   * without it the ±1-step drift tolerance is a 90-second replay window (§5.4.3).
   */
  timestep: number | null;
}

/** RFC 6238. Implemented by `@auth/crypto`'s `TotpService`. */
export interface TotpProvider {
  generateSecret(): TotpSecret;
  provisioningUri(secret: TotpSecret, account: string, issuer: string): string;
  verify(secret: TotpSecret, code: string, at?: Date): TotpVerification;
}

export interface BreachChecker {
  /** HIBP range API — k-anonymity, only the first 5 SHA-1 hex chars leave the process. */
  isBreached(plain: string): Promise<boolean>;
}
