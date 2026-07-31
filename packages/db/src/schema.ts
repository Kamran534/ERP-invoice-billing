/**
 * Auth schema — the tables specified in AUTH-MODULE-PLAN.md §4.
 *
 * Conventions:
 *  - `auth_` table prefix so the module owns its namespace and never collides
 *    with application tables.
 *  - UUIDv7 primary keys generated in the application (packages/crypto) — time
 *    sortable, so inserts stay at the right edge of the index.
 *  - timestamptz everywhere; the DB runs in UTC.
 *  - Secrets are hashed (bytea), never stored plaintext.
 *  - Partial indexes on the "alive" subset (`WHERE revoked_at IS NULL`) keep the
 *    hot indexes small as dead rows accumulate.
 */

import { sql } from 'drizzle-orm';
import {
  pgTable,
  uuid,
  text,
  timestamp,
  integer,
  bigint,
  boolean,
  jsonb,
  inet,
  index,
  uniqueIndex,
  primaryKey,
  type AnyPgColumn,
} from 'drizzle-orm/pg-core';
import { bytea, citext } from './types.js';

const now = sql`now()`;

// ── Tenancy ────────────────────────────────────────────────────────────────

export const orgs = pgTable(
  'auth_orgs',
  {
    id: uuid('id').primaryKey(),
    name: text('name').notNull(),
    slug: citext('slug').notNull(),
    status: text('status').notNull().default('active').$type<'active' | 'suspended'>(),
    /** e.g. { requireMfa: true, allowedDomains: [...] } — per-org policy overrides. */
    settings: jsonb('settings').notNull().default({}),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  },
  (t) => [uniqueIndex('uq_orgs_slug').on(t.slug)],
);

export const roles = pgTable(
  'auth_roles',
  {
    id: uuid('id').primaryKey(),
    /** null = system role, shared across every org. */
    orgId: uuid('org_id').references(() => orgs.id, { onDelete: 'cascade' }),
    key: text('key').notNull(),
    name: text('name').notNull(),
    isSystem: boolean('is_system').notNull().default(false),
  },
  (t) => [uniqueIndex('uq_roles_org_key').on(t.orgId, t.key)],
);

export const rolePermissions = pgTable(
  'auth_role_permissions',
  {
    roleId: uuid('role_id')
      .notNull()
      .references(() => roles.id, { onDelete: 'cascade' }),
    /** 'invoice:read' | 'invoice:*' | '*' — validated against the host app's registry. */
    permission: text('permission').notNull(),
  },
  (t) => [primaryKey({ columns: [t.roleId, t.permission] })],
);

// ── Identity ───────────────────────────────────────────────────────────────

export const users = pgTable(
  'auth_users',
  {
    id: uuid('id').primaryKey(),
    /** Nullable: passkey-only and SSO-only accounts have no address of their own. */
    email: citext('email'),
    emailVerifiedAt: timestamp('email_verified_at', { withTimezone: true }),
    /** E.164, only populated when the SMS OTP channel is enabled. */
    phone: text('phone'),
    phoneVerifiedAt: timestamp('phone_verified_at', { withTimezone: true }),
    /** Nullable: passwordless accounts. */
    passwordHash: text('password_hash'),
    passwordAlgo: text('password_algo').$type<'argon2id' | 'bcrypt'>(),
    passwordUpdatedAt: timestamp('password_updated_at', { withTimezone: true }),
    status: text('status')
      .notNull()
      .default('pending')
      .$type<'pending' | 'active' | 'suspended' | 'deleted'>(),
    name: text('name'),
    avatarUrl: text('avatar_url'),
    locale: text('locale'),
    timezone: text('timezone'),
    /** Host-app extension point — validated against an optional zod schema. */
    profile: jsonb('profile').notNull().default({}),
    /** Set when org policy forces 2FA on this user (§5.4.6 quarantine). */
    mfaRequiredAt: timestamp('mfa_required_at', { withTimezone: true }),
    failedLoginCount: integer('failed_login_count').notNull().default(0),
    lockedUntil: timestamp('locked_until', { withTimezone: true }),
    lastLoginAt: timestamp('last_login_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().default(now),
    deletedAt: timestamp('deleted_at', { withTimezone: true }),
  },
  (t) => [
    uniqueIndex('uq_users_email').on(t.email),
    uniqueIndex('uq_users_phone').on(t.phone),
    index('idx_users_status_live').on(t.status).where(sql`deleted_at IS NULL`),
  ],
);

export const memberships = pgTable(
  'auth_memberships',
  {
    id: uuid('id').primaryKey(),
    orgId: uuid('org_id')
      .notNull()
      .references(() => orgs.id, { onDelete: 'cascade' }),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    roleId: uuid('role_id')
      .notNull()
      .references(() => roles.id),
    status: text('status').notNull().default('active').$type<'invited' | 'active' | 'suspended'>(),
    invitedBy: uuid('invited_by').references((): AnyPgColumn => users.id),
    joinedAt: timestamp('joined_at', { withTimezone: true }),
  },
  (t) => [
    uniqueIndex('uq_memberships_org_user').on(t.orgId, t.userId),
    index('idx_memberships_user').on(t.userId),
  ],
);

export const identities = pgTable(
  'auth_identities',
  {
    id: uuid('id').primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    provider: text('provider').notNull(),
    providerUserId: text('provider_user_id').notNull(),
    email: citext('email'),
    /** ⚑ Only ever link on a provider-verified email (§5.10). */
    emailVerified: boolean('email_verified').notNull().default(false),
    profile: jsonb('profile').notNull().default({}),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
    lastLoginAt: timestamp('last_login_at', { withTimezone: true }),
    // NOTE: provider access/refresh tokens are deliberately not stored here.
  },
  (t) => [
    uniqueIndex('uq_identities_provider_subject').on(t.provider, t.providerUserId),
    index('idx_identities_user').on(t.userId),
  ],
);

export const passwordHistory = pgTable(
  'auth_password_history',
  {
    id: uuid('id').primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    passwordHash: text('password_hash').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  },
  (t) => [index('idx_password_history_user').on(t.userId, t.createdAt)],
);

// ── Sessions & refresh chain ───────────────────────────────────────────────

export const sessions = pgTable(
  'auth_sessions',
  {
    id: uuid('id').primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    /** Active tenant; changed by /auth/token/switch-org without forking the chain. */
    orgId: uuid('org_id').references(() => orgs.id),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
    lastSeenAt: timestamp('last_seen_at', { withTimezone: true }).notNull().default(now),
    /** Slides on every refresh. */
    idleExpiresAt: timestamp('idle_expires_at', { withTimezone: true }).notNull(),
    /** ⚑ Hard cap — never extended, for any reason (§5.5.3 step 8). */
    absoluteExpiresAt: timestamp('absolute_expires_at', { withTimezone: true }).notNull(),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    revokedReason: text('revoked_reason'),
    /** Auth methods actually used: ['pwd','otp'] etc. Drives §5.4.3 distinctness. */
    amr: text('amr').array().notNull().default(sql`'{}'::text[]`),
    mfaSatisfiedAt: timestamp('mfa_satisfied_at', { withTimezone: true }),
    ip: inet('ip'),
    userAgent: text('user_agent'),
    deviceLabel: text('device_label'),
    /** Support impersonation — always audited, never silent (§5.15). */
    impersonatedBy: uuid('impersonated_by').references((): AnyPgColumn => users.id),
  },
  (t) => [
    index('idx_sessions_user_live').on(t.userId).where(sql`revoked_at IS NULL`),
    index('idx_sessions_expiry').on(t.absoluteExpiresAt).where(sql`revoked_at IS NULL`),
  ],
);

export const refreshTokens = pgTable(
  'auth_refresh_tokens',
  {
    id: uuid('id').primaryKey(),
    sessionId: uuid('session_id')
      .notNull()
      .references(() => sessions.id, { onDelete: 'cascade' }),
    /** sha256(secret). The secret itself is never persisted anywhere. */
    tokenHash: bytea('token_hash').notNull(),
    issuedAt: timestamp('issued_at', { withTimezone: true }).notNull().default(now),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    /** ⚑ Non-null + presented again = reuse = presumed theft (§5.5.4). */
    usedAt: timestamp('used_at', { withTimezone: true }),
    replacedById: uuid('replaced_by_id').references((): AnyPgColumn => refreshTokens.id),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
  },
  (t) => [
    uniqueIndex('uq_refresh_token_hash').on(t.tokenHash),
    index('idx_refresh_session').on(t.sessionId),
    // The rotation invariant: at most one unused token per session.
    uniqueIndex('uq_refresh_active_per_session')
      .on(t.sessionId)
      .where(sql`used_at IS NULL AND revoked_at IS NULL`),
  ],
);

// ── Second factors ─────────────────────────────────────────────────────────

export const mfaFactors = pgTable(
  'auth_mfa_factors',
  {
    id: uuid('id').primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    type: text('type').notNull().$type<'totp' | 'webauthn' | 'sms'>(),
    label: text('label'),
    /** AEAD(TOTP secret, KEK) — never plaintext, never in a log. */
    secretEnc: bytea('secret_enc'),
    /** ⚑ Unconfirmed factors never satisfy a challenge and are purged (§5.4.1). */
    confirmedAt: timestamp('confirmed_at', { withTimezone: true }),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  },
  (t) => [index('idx_mfa_factors_user').on(t.userId).where(sql`confirmed_at IS NOT NULL`)],
);

export const webauthnCredentials = pgTable(
  'auth_webauthn_credentials',
  {
    id: uuid('id').primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    credentialId: bytea('credential_id').notNull(),
    publicKey: bytea('public_key').notNull(),
    /** ⚑ Must increase monotonically where the authenticator provides it (clone detection). */
    signCount: bigint('sign_count', { mode: 'number' }).notNull().default(0),
    transports: text('transports').array(),
    aaguid: uuid('aaguid'),
    backedUp: boolean('backed_up'),
    label: text('label'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
  },
  (t) => [
    uniqueIndex('uq_webauthn_credential_id').on(t.credentialId),
    index('idx_webauthn_user').on(t.userId),
  ],
);

export const recoveryCodes = pgTable(
  'auth_recovery_codes',
  {
    id: uuid('id').primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    codeHash: bytea('code_hash').notNull(),
    usedAt: timestamp('used_at', { withTimezone: true }),
  },
  (t) => [index('idx_recovery_codes_user').on(t.userId).where(sql`used_at IS NULL`)],
);

/**
 * One table serves OTP-as-login (§5.11) and OTP-as-second-factor (§5.4) — the
 * generate → deliver → attempt-capped-verify engine is identical.
 */
export const otpChallenges = pgTable(
  'auth_otp_challenges',
  {
    id: uuid('id').primaryKey(),
    /** null until the destination is resolved to an account. */
    userId: uuid('user_id').references(() => users.id, { onDelete: 'cascade' }),
    purpose: text('purpose').notNull().$type<'login' | 'mfa' | 'step_up' | 'phone_verify'>(),
    channel: text('channel').notNull().$type<'email' | 'sms'>(),
    /** ⚑ sha256(normalized destination) — no raw email or phone in this table. */
    destinationHash: bytea('destination_hash').notNull(),
    /** sha256(code || challenge id) — salted per challenge. */
    codeHash: bytea('code_hash').notNull(),
    attempts: integer('attempts').notNull().default(0),
    maxAttempts: integer('max_attempts').notNull().default(5),
    resendCount: integer('resend_count').notNull().default(0),
    /** sha256(ua || ip/24) — defeats the "read me your code" relay (§5.11.2). */
    clientBinding: bytea('client_binding'),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    consumedAt: timestamp('consumed_at', { withTimezone: true }),
    lastSentAt: timestamp('last_sent_at', { withTimezone: true }).notNull().default(now),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  },
  (t) => [
    index('idx_otp_destination_purpose')
      .on(t.destinationHash, t.purpose)
      .where(sql`consumed_at IS NULL`),
    index('idx_otp_expiry').on(t.expiresAt),
  ],
);

export const trustedDevices = pgTable(
  'auth_trusted_devices',
  {
    id: uuid('id').primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    tokenHash: bytea('token_hash').notNull(),
    label: text('label'),
    ip: inet('ip'),
    userAgent: text('user_agent'),
    /** The 2FA event that earned this trust. */
    mfaSatisfiedAt: timestamp('mfa_satisfied_at', { withTimezone: true }).notNull(),
    /** ⚑ Absolute — no sliding renewal (§5.4.5). */
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  },
  (t) => [
    uniqueIndex('uq_trusted_device_hash').on(t.tokenHash),
    index('idx_trusted_devices_user').on(t.userId).where(sql`revoked_at IS NULL`),
  ],
);

// ── One-time tokens (verify / reset / magic link / invite) ─────────────────

export const oneTimeTokens = pgTable(
  'auth_one_time_tokens',
  {
    id: uuid('id').primaryKey(),
    /** null for invitations addressed to an email with no account yet. */
    userId: uuid('user_id').references(() => users.id, { onDelete: 'cascade' }),
    purpose: text('purpose')
      .notNull()
      .$type<'email_verify' | 'password_reset' | 'magic_link' | 'email_change' | 'org_invite' | 'mfa_challenge'>(),
    tokenHash: bytea('token_hash').notNull(),
    /** e.g. { newEmail } for email_change, { orgId, roleId } for org_invite. */
    payload: jsonb('payload').notNull().default({}),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    /** ⚑ Set by a single atomic UPDATE ... WHERE consumed_at IS NULL (§4.4). */
    consumedAt: timestamp('consumed_at', { withTimezone: true }),
    requestedIp: inet('requested_ip'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  },
  (t) => [
    uniqueIndex('uq_ott_hash').on(t.tokenHash),
    index('idx_ott_user_purpose').on(t.userId, t.purpose).where(sql`consumed_at IS NULL`),
    index('idx_ott_expiry').on(t.expiresAt),
  ],
);

// ── Machine identity ───────────────────────────────────────────────────────

export const apiKeys = pgTable(
  'auth_api_keys',
  {
    id: uuid('id').primaryKey(),
    orgId: uuid('org_id').references(() => orgs.id, { onDelete: 'cascade' }),
    createdBy: uuid('created_by').references(() => users.id),
    name: text('name').notNull(),
    /** Shown in the UI and indexed for O(1) lookup: 'ak_live_7f3a'. */
    prefix: text('prefix').notNull(),
    keyHash: bytea('key_hash').notNull(),
    scopes: text('scopes').array().notNull().default(sql`'{}'::text[]`),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
    expiresAt: timestamp('expires_at', { withTimezone: true }),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  },
  (t) => [
    uniqueIndex('uq_api_keys_prefix').on(t.prefix),
    index('idx_api_keys_org').on(t.orgId).where(sql`revoked_at IS NULL`),
  ],
);

// ── Audit & forensics ──────────────────────────────────────────────────────

/**
 * Append-only. Grant the application role INSERT/SELECT only — no UPDATE, no
 * DELETE — so a compromised app credential cannot rewrite history (§4.7).
 * Partition monthly once volume justifies it.
 */
export const auditEvents = pgTable(
  'auth_audit_events',
  {
    id: uuid('id').primaryKey(),
    occurredAt: timestamp('occurred_at', { withTimezone: true }).notNull().default(now),
    orgId: uuid('org_id'),
    actorUserId: uuid('actor_user_id'),
    actorType: text('actor_type').notNull().default('user'),
    event: text('event').notNull(),
    targetType: text('target_type'),
    targetId: text('target_id'),
    sessionId: uuid('session_id'),
    ip: inet('ip'),
    userAgent: text('user_agent'),
    outcome: text('outcome').notNull().default('success').$type<'success' | 'failure'>(),
    metadata: jsonb('metadata').notNull().default({}),
  },
  (t) => [
    index('idx_audit_org_time').on(t.orgId, t.occurredAt.desc()),
    index('idx_audit_actor_time').on(t.actorUserId, t.occurredAt.desc()),
    index('idx_audit_event_time').on(t.event, t.occurredAt.desc()),
  ],
);

/** Short-lived: drives lockout and anomaly detection. Purged after 30 days. */
export const loginAttempts = pgTable(
  'auth_login_attempts',
  {
    id: uuid('id').primaryKey(),
    /** Hashed, so this table is not an email harvest if leaked. */
    emailHash: bytea('email_hash'),
    ip: inet('ip'),
    success: boolean('success').notNull(),
    reason: text('reason'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  },
  (t) => [
    index('idx_login_attempts_email_time').on(t.emailHash, t.createdAt),
    index('idx_login_attempts_ip_time').on(t.ip, t.createdAt),
  ],
);

// ── Signing keys (JWKS) ────────────────────────────────────────────────────

export const signingKeys = pgTable('auth_signing_keys', {
  kid: text('kid').primaryKey(),
  alg: text('alg').notNull(),
  publicJwk: jsonb('public_jwk').notNull(),
  /** AEAD(private key, KEK-from-env-or-KMS). */
  privateKeyEnc: bytea('private_key_enc').notNull(),
  /** next → active → retiring → retired (§8.6). */
  status: text('status').notNull().$type<'next' | 'active' | 'retiring' | 'retired'>(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  activatedAt: timestamp('activated_at', { withTimezone: true }),
  retiredAt: timestamp('retired_at', { withTimezone: true }),
});

export const schema = {
  orgs,
  roles,
  rolePermissions,
  users,
  memberships,
  identities,
  passwordHistory,
  sessions,
  refreshTokens,
  mfaFactors,
  webauthnCredentials,
  recoveryCodes,
  otpChallenges,
  trustedDevices,
  oneTimeTokens,
  apiKeys,
  auditEvents,
  loginAttempts,
  signingKeys,
};
