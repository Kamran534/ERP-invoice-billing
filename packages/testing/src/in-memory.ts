/**
 * In-memory implementations of every port (AUTH-MODULE-PLAN.md §3.1).
 *
 * These exist so the use-cases in `@auth/core` can be tested with no database, no
 * containers and no clock — which is the payoff for `core` importing nothing. The
 * Postgres adapters are verified separately against real Postgres; these are for
 * exercising *decisions*, not persistence.
 *
 * ⚑ They are honest about concurrency where it matters. `claim` reproduces the
 * read-then-guard ordering, so a test can drive the reuse-versus-race distinction
 * without a database.
 */

import { createHash } from 'node:crypto';
import type {
  AuditEvent,
  AuditRepo,
  Clock,
  CryptoDeps,
  EventBus,
  Logger,
  Mailer,
  Membership,
  MembershipRepo,
  MembershipView,
  MfaFactor,
  MfaRepo,
  Org,
  OrgRepo,
  OneTimeTokenPurpose,
  OneTimeTokenRepo,
  OtpChallenge,
  OtpChallengeRepo,
  PasswordHasher,
  RandomSource,
  RefreshClaim,
  RefreshTokenRepo,
  RefreshTokenRow,
  RenderedMail,
  Role,
  RoleRepo,
  RevokeReason,
  Session,
  SessionRepo,
  SecretBox,
  TokenService,
  TotpProvider,
  TotpSecret,
  TrustedDeviceRepo,
  User,
  UserId,
  UserRepo,
} from '@auth/core';

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

/**
 * ⚑ Every double takes the clock. Reading real time inside a double silently
 * defeats a fake clock: a token issued at the fake "now" looks long expired when
 * compared against wall-clock, and every time-based assertion then fails for a
 * reason that has nothing to do with the code under test.
 */
const realClock: Clock = { now: () => new Date() };

/** Controllable time. Every TTL in the system is arithmetic on this. */
export class FakeClock implements Clock {
  #now: Date;
  constructor(start: Date = new Date('2026-01-01T00:00:00.000Z')) {
    this.#now = start;
  }
  now(): Date {
    return new Date(this.#now);
  }
  advance(ms: number): void {
    this.#now = new Date(this.#now.getTime() + ms);
  }
  set(at: Date): void {
    this.#now = new Date(at);
  }
}

/**
 * Deterministic ids and secrets, so failures are reproducible.
 *
 * ⚑ Deterministic is not the same as constant. `bytes()` advances the counter on
 * every call; an earlier version read it without incrementing, so every call
 * returned the identical buffer — which made ten "random" recovery codes ten
 * copies of one code, and made a real duplicate-secret bug invisible to the tests
 * that were meant to catch it.
 */
export function createSequentialRandom(prefix = 'test'): RandomSource & { reset(): void } {
  let counter = 0;
  const next = () => `${prefix}-${(counter += 1).toString().padStart(6, '0')}`;
  return {
    bytes: (n: number) => {
      counter += 1;
      return new Uint8Array(Array.from({ length: n }, (_, i) => (counter * 31 + i * 7) % 256));
    },
    uuid: () => {
      const n = (counter += 1).toString(16).padStart(12, '0');
      return `0191f0aa-0000-7000-8000-${n}`;
    },
    digits: (length: number) => next().replace(/\D/g, '').slice(-length).padStart(length, '0'),
    reset: () => {
      counter = 0;
    },
  };
}

export function createInMemoryUserRepo(clock: Clock = realClock): UserRepo & { all(): User[] } {
  const byId = new Map<string, User>();
  let seq = 0;

  return {
    all: () => [...byId.values()],

    async findById(id) {
      return byId.get(id) ?? null;
    },

    async findByEmail(email) {
      // Case-insensitive, matching the citext column.
      const wanted = email.trim().toLowerCase();
      return [...byId.values()].find((u) => u.email?.toLowerCase() === wanted) ?? null;
    },

    async findByUsernameInOrg(orgId, username) {
      const wanted = username.trim().toLowerCase();
      // ⚑ Scoped, like the unique index. A double that matched on username alone
      // would let a test pass on behaviour the database refuses.
      return (
        [...byId.values()].find(
          (u) => u.orgScopeId === orgId && u.username?.toLowerCase() === wanted,
        ) ?? null
      );
    },

    async create(input) {
      const user: User = {
        id: input.id ?? `user-${(seq += 1)}`,
        email: input.email ?? null,
        emailVerifiedAt: input.emailVerifiedAt ?? null,
        username: input.username ?? null,
        orgScopeId: input.orgScopeId ?? null,
        phone: input.phone ?? null,
        phoneVerifiedAt: null,
        passwordHash: input.passwordHash ?? null,
        passwordAlgo: input.passwordAlgo ?? null,
        passwordUpdatedAt: input.passwordHash ? clock.now() : null,
        status: input.status ?? 'pending',
        name: input.name ?? null,
        mfaRequiredAt: null,
        failedLoginCount: 0,
        lockedUntil: null,
        lastLoginAt: null,
        createdAt: input.createdAt ?? clock.now(),
      };
      byId.set(user.id, user);
      return user;
    },

    async update(id, patch) {
      const existing = byId.get(id);
      if (!existing) throw new Error(`user ${id} not found`);
      const updated = { ...existing, ...patch };
      byId.set(id, updated);
      return updated;
    },

    async registerFailedLogin(id, lockAfter, lockForMs) {
      const user = byId.get(id);
      if (!user) return { failedLoginCount: 0, lockedUntil: null };
      const failedLoginCount = user.failedLoginCount + 1;
      const lockedUntil =
        failedLoginCount >= lockAfter ? new Date(clock.now().getTime() + lockForMs) : user.lockedUntil;
      byId.set(id, { ...user, failedLoginCount, lockedUntil });
      return { failedLoginCount, lockedUntil };
    },

    async clearFailedLogins(id) {
      const user = byId.get(id);
      if (user) byId.set(id, { ...user, failedLoginCount: 0, lockedUntil: null });
    },
  };
}

export function createInMemorySessionRepo(clock: Clock = realClock): SessionRepo & { all(): Session[] } {
  const byId = new Map<string, Session>();
  let seq = 0;

  return {
    all: () => [...byId.values()],

    async create(input) {
      const session: Session = {
        ...input,
        id: input.id || `session-${(seq += 1)}`,
        createdAt: clock.now(),
        lastSeenAt: clock.now(),
        revokedAt: null,
        revokedReason: null,
      };
      byId.set(session.id, session);
      return session;
    },

    async findById(id) {
      return byId.get(id) ?? null;
    },

    async listActive(userId) {
      return [...byId.values()].filter((s) => s.userId === userId && !s.revokedAt);
    },

    async touch(id, at, idleExpiresAt) {
      const session = byId.get(id);
      if (session) byId.set(id, { ...session, lastSeenAt: at, idleExpiresAt });
    },

    async setOrg(id, orgId) {
      const session = byId.get(id);
      if (session) byId.set(id, { ...session, orgId });
    },

    async revoke(id, reason) {
      const session = byId.get(id);
      // Idempotent, and the first reason wins — as in the SQL adapter.
      if (session && !session.revokedAt) {
        byId.set(id, { ...session, revokedAt: clock.now(), revokedReason: reason });
      }
    },

    async revokeAllForUser(userId, reason, except) {
      let count = 0;
      for (const session of byId.values()) {
        if (session.userId !== userId || session.revokedAt || session.id === except) continue;
        byId.set(session.id, { ...session, revokedAt: clock.now(), revokedReason: reason });
        count += 1;
      }
      return count;
    },
  };
}

/**
 * `all()` exposes the stored `hash` on purpose: it is how a test asserts that the
 * secret itself was never persisted, which is the whole reason the column holds a
 * digest.
 */
export function createInMemoryRefreshTokenRepo(clock: Clock = realClock): RefreshTokenRepo & {
  all(): Array<RefreshTokenRow & { hash: string }>;
} {
  const byId = new Map<string, RefreshTokenRow & { hash: string }>();
  let seq = 0;

  const find = (hash: Uint8Array) =>
    [...byId.values()].find((t) => t.hash === hex(hash)) ?? null;

  return {
    all: () => [...byId.values()],

    async issue(sessionId, hash, expiresAt) {
      const row: RefreshTokenRow & { hash: string } = {
        id: `rt-${(seq += 1)}`,
        sessionId,
        issuedAt: clock.now(),
        expiresAt,
        usedAt: null,
        replacedById: null,
        revokedAt: null,
        hash: hex(hash),
      };
      byId.set(row.id, row);
      return row;
    },

    /**
     * ⚑ Mirrors the adapter's read-then-guard ordering. Because this is
     * single-threaded, a genuine race cannot occur — a test that wants the
     * `concurrent` branch drives it through the repo directly.
     */
    async claim(hash): Promise<RefreshClaim> {
      const existing = find(hash);
      if (!existing) return { outcome: 'unknown' };
      if (existing.revokedAt) return { outcome: 'revoked', token: existing };
      if (existing.usedAt) return { outcome: 'reuse', token: existing };
      if (existing.expiresAt.getTime() <= clock.now().getTime()) return { outcome: 'expired', token: existing };

      const claimed = { ...existing, usedAt: clock.now() };
      byId.set(claimed.id, claimed);
      return { outcome: 'ok', token: claimed };
    },

    async link(tokenId, replacedById) {
      const token = byId.get(tokenId);
      if (token) byId.set(tokenId, { ...token, replacedById });
    },

    async revokeChain(sessionId) {
      let count = 0;
      for (const token of byId.values()) {
        if (token.sessionId !== sessionId || token.revokedAt) continue;
        byId.set(token.id, { ...token, revokedAt: clock.now() });
        count += 1;
      }
      return count;
    },

    async findBySessionAndSuccessor(tokenId) {
      return byId.get(tokenId) ?? null;
    },
  };
}

export function createInMemoryOneTimeTokenRepo(clock: Clock = realClock): OneTimeTokenRepo {
  const rows: Array<{
    id: string;
    userId: UserId | null;
    purpose: OneTimeTokenPurpose;
    hash: string;
    payload: Record<string, unknown>;
    attempts: number;
    maxAttempts: number;
    expiresAt: Date;
    consumedAt: Date | null;
  }> = [];
  let seq = 0;

  return {
    async issue(input) {
      rows.push({
        id: `ott-${(seq += 1)}`,
        userId: input.userId,
        purpose: input.purpose,
        hash: hex(input.hash),
        payload: input.payload ?? {},
        attempts: 0,
        maxAttempts: 5,
        expiresAt: input.expiresAt,
        consumedAt: null,
      });
    },

    /** Mirrors the SQL: increments, checks the cap, and does NOT consume. */
    async claimAttempt(hash, purpose) {
      const row = rows.find(
        (r) =>
          r.hash === hex(hash) &&
          r.purpose === purpose &&
          !r.consumedAt &&
          r.expiresAt.getTime() > clock.now().getTime() &&
          r.attempts < r.maxAttempts,
      );
      if (!row) return null;
      row.attempts += 1;
      return {
        id: row.id,
        userId: row.userId,
        payload: row.payload,
        attemptsRemaining: row.maxAttempts - row.attempts,
      };
    },

    async markConsumed(id) {
      const row = rows.find((r) => r.id === id && !r.consumedAt);
      if (row) row.consumedAt = clock.now();
    },

    async consume(hash, purpose) {
      const row = rows.find(
        (r) =>
          r.hash === hex(hash) &&
          r.purpose === purpose &&
          !r.consumedAt &&
          r.expiresAt.getTime() > clock.now().getTime(),
      );
      if (!row) return null;
      row.consumedAt = clock.now();
      return { userId: row.userId, payload: row.payload };
    },

    async revokeAllForUser(userId, purpose) {
      let count = 0;
      for (const row of rows) {
        if (row.userId === userId && row.purpose === purpose && !row.consumedAt) {
          row.consumedAt = clock.now();
          count += 1;
        }
      }
      return count;
    },
  };
}

export function createInMemoryOtpChallengeRepo(clock: Clock = realClock): OtpChallengeRepo {
  const rows = new Map<
    string,
    OtpChallenge & { destinationHash: string; codeHash: Uint8Array; clientBinding: Uint8Array | null }
  >();
  let seq = 0;

  return {
    async create(input) {
      const row = {
        id: `otp-${(seq += 1)}`,
        userId: input.userId,
        purpose: input.purpose,
        channel: input.channel,
        attempts: 0,
        maxAttempts: input.maxAttempts,
        resendCount: 0,
        expiresAt: input.expiresAt,
        consumedAt: null,
        lastSentAt: clock.now(),
        destinationHash: hex(input.destinationHash),
        codeHash: input.codeHash,
        clientBinding: input.clientBinding,
      };
      rows.set(row.id, row);
      return row;
    },

    async claimAttempt(id) {
      const row = rows.get(id);
      if (
        !row ||
        row.consumedAt ||
        row.expiresAt.getTime() <= clock.now().getTime() ||
        row.attempts >= row.maxAttempts
      ) {
        return null;
      }
      row.attempts += 1;
      return { ...row, codeHash: row.codeHash, clientBinding: row.clientBinding };
    },

    async markConsumed(id) {
      const row = rows.get(id);
      if (row) row.consumedAt = clock.now();
    },

    async invalidateActive(destinationHash, purpose) {
      let count = 0;
      for (const row of rows.values()) {
        if (row.destinationHash === hex(destinationHash) && row.purpose === purpose && !row.consumedAt) {
          row.consumedAt = clock.now();
          count += 1;
        }
      }
      return count;
    },

    async registerResend(id, minIntervalMs, maxResends) {
      const row = rows.get(id);
      if (!row || row.consumedAt || row.expiresAt.getTime() <= clock.now().getTime()) return 'exhausted';
      if (row.resendCount >= maxResends) return 'exhausted';
      if (clock.now().getTime() - row.lastSentAt.getTime() < minIntervalMs) return 'too_soon';
      row.resendCount += 1;
      row.lastSentAt = clock.now();
      return 'sent';
    },
  };
}

export function createInMemoryMfaRepo(clock: Clock = realClock): MfaRepo {
  const factors = new Map<string, MfaFactor>();
  const codes: Array<{ userId: UserId; hash: string; usedAt: Date | null }> = [];
  let seq = 0;

  return {
    async addFactor(input) {
      const factor: MfaFactor = {
        id: `factor-${(seq += 1)}`,
        userId: input.userId,
        type: input.type,
        label: input.label,
        secretEnc: input.secretEnc,
        confirmedAt: null,
        lastUsedAt: null,
        lastUsedTimestep: null,
        createdAt: clock.now(),
      };
      factors.set(factor.id, factor);
      return factor;
    },
    async findFactor(id) {
      return factors.get(id) ?? null;
    },
    async listConfirmedFactors(userId) {
      return [...factors.values()].filter((f) => f.userId === userId && f.confirmedAt);
    },
    async listAllFactors(userId) {
      return [...factors.values()].filter((f) => f.userId === userId);
    },
    /** Mirrors the guarded UPDATE: only ever moves forward. */
    async advanceTimestep(id, at, timestep) {
      const factor = factors.get(id);
      if (!factor) return false;
      if (factor.lastUsedTimestep !== null && factor.lastUsedTimestep >= timestep) return false;
      factors.set(id, { ...factor, lastUsedTimestep: timestep, lastUsedAt: at });
      return true;
    },
    async confirmFactor(id, at) {
      const factor = factors.get(id);
      if (factor) factors.set(id, { ...factor, confirmedAt: at });
    },
    async touchFactor(id, at) {
      const factor = factors.get(id);
      if (factor) factors.set(id, { ...factor, lastUsedAt: at });
    },
    async removeFactor(id) {
      factors.delete(id);
    },
    async purgeUnconfirmed(userId, olderThan) {
      let count = 0;
      for (const factor of [...factors.values()]) {
        if (factor.userId === userId && !factor.confirmedAt && factor.createdAt < olderThan) {
          factors.delete(factor.id);
          count += 1;
        }
      }
      return count;
    },
    async replaceRecoveryCodes(userId, hashes) {
      for (let i = codes.length - 1; i >= 0; i -= 1) {
        if (codes[i]!.userId === userId) codes.splice(i, 1);
      }
      for (const hash of hashes) codes.push({ userId, hash: hex(hash), usedAt: null });
    },
    async consumeRecoveryCode(userId, hash) {
      const code = codes.find((c) => c.userId === userId && c.hash === hex(hash) && !c.usedAt);
      if (!code) return false;
      code.usedAt = clock.now();
      return true;
    },
    async countUnusedRecoveryCodes(userId) {
      return codes.filter((c) => c.userId === userId && !c.usedAt).length;
    },
  };
}

export function createInMemoryTrustedDeviceRepo(clock: Clock = realClock): TrustedDeviceRepo {
  const rows = new Map<
    string,
    { id: string; userId: UserId; hash: string; label: string | null; expiresAt: Date; revokedAt: Date | null; lastUsedAt: Date | null }
  >();
  let seq = 0;

  return {
    async create(input) {
      const id = `device-${(seq += 1)}`;
      rows.set(id, {
        id,
        userId: input.userId,
        hash: hex(input.hash),
        label: input.label,
        expiresAt: input.expiresAt,
        revokedAt: null,
        lastUsedAt: null,
      });
      return { id };
    },
    async findValidByHash(hash) {
      const row = [...rows.values()].find(
        (r) => r.hash === hex(hash) && !r.revokedAt && r.expiresAt.getTime() > clock.now().getTime(),
      );
      return row ? { id: row.id, userId: row.userId } : null;
    },
    async listForUser(userId) {
      return [...rows.values()]
        .filter((r) => r.userId === userId && !r.revokedAt)
        .map((r) => ({ id: r.id, label: r.label, lastUsedAt: r.lastUsedAt, expiresAt: r.expiresAt }));
    },
    async touch(id, at) {
      const row = rows.get(id);
      // Mirrors the SQL adapter: `expiresAt` is deliberately untouched.
      if (row) row.lastUsedAt = at;
    },
    async revoke(id) {
      const row = rows.get(id);
      if (row) row.revokedAt = clock.now();
    },
    async revokeAllForUser(userId) {
      let count = 0;
      for (const row of rows.values()) {
        if (row.userId === userId && !row.revokedAt) {
          row.revokedAt = clock.now();
          count += 1;
        }
      }
      return count;
    },
  };
}

/**
 * Organizations, memberships and roles.
 *
 * ⚑ `createWithOwner` is all-or-nothing here too. The doubles exist to let a
 * use-case test drive real decisions, and "what happens when the membership
 * insert fails" is a decision — a double that leaves a half-built org would let a
 * test pass on behaviour Postgres would never produce.
 */
export function createInMemoryOrgRepos(
  clock: Clock = realClock,
  /**
   * ⚑ The user store, when employee creation is exercised (§10.12). Passed in
   * rather than kept locally because the real `createEmployee` writes a user row
   * and a membership row in one transaction, and a double that invented its own
   * user store would let `findByUsernameInOrg` disagree with what was created.
   */
  userRepo?: UserRepo,
): {
  orgs: OrgRepo;
  memberships: MembershipRepo;
  roles: RoleRepo;
} {
  const orgRows = new Map<string, Org>();
  const roleRows = new Map<string, Role>();
  const rolePerms = new Map<string, string[]>();
  const membershipRows = new Map<string, Membership>();
  const emails = new Map<string, string | null>();
  let seq = 0;

  const viewOf = (m: Membership): MembershipView | null => {
    const org = orgRows.get(m.orgId);
    const role = roleRows.get(m.roleId);
    if (!org || !role) return null;
    return { membershipId: m.id, org, role, status: m.status, joinedAt: m.joinedAt };
  };

  return {
    orgs: {
      async createWithOwner(input) {
        if (input.onlyIfFirst && orgRows.size > 0) return { conflict: 'not_first' };
        if ([...orgRows.values()].some((o) => o.slug === input.slug)) {
          return { conflict: 'slug_taken' };
        }

        const org: Org = {
          id: `org-${(seq += 1)}`,
          name: input.name,
          slug: input.slug,
          status: 'active',
          legalName: null,
          taxId: null,
          email: null,
          phone: null,
          website: null,
          logoUrl: null,
          address: null,
          timezone: null,
          locale: null,
          currency: null,
          ...(input.profile ?? {}),
          createdAt: clock.now(),
        };
        orgRows.set(org.id, org);

        const byKey = new Map<string, string>();
        for (const role of input.roles) {
          const row: Role = {
            id: `role-${(seq += 1)}`,
            orgId: org.id,
            key: role.key,
            name: role.name,
            isSystem: true,
          };
          roleRows.set(row.id, row);
          rolePerms.set(row.id, [...role.permissions]);
          byKey.set(role.key, row.id);
        }

        const ownerRoleId = byKey.get(input.ownerRoleKey);
        if (!ownerRoleId) throw new Error(`owner role "${input.ownerRoleKey}" not seeded`);

        const membership: Membership = {
          id: `membership-${(seq += 1)}`,
          orgId: org.id,
          userId: input.ownerId,
          roleId: ownerRoleId,
          status: 'active',
          joinedAt: clock.now(),
        };
        membershipRows.set(membership.id, membership);
        return { org, membership };
      },

      async createEmployee(input) {
        if (!userRepo) throw new Error('createInMemoryOrgRepos: no user repo was provided');

        const clash = await userRepo.findByUsernameInOrg(input.orgId, input.username);
        if (clash) return { conflict: 'username_taken' };

        const user = await userRepo.create({
          username: input.username,
          orgScopeId: input.orgId,
          name: input.name ?? null,
          passwordHash: input.passwordHash,
          passwordAlgo: 'argon2id',
          status: 'active',
        });

        const membership: Membership = {
          id: `membership-${(seq += 1)}`,
          orgId: input.orgId,
          userId: user.id,
          roleId: input.roleId,
          status: 'active',
          joinedAt: clock.now(),
        };
        membershipRows.set(membership.id, membership);
        return { user, membership };
      },

      async findById(id) {
        return orgRows.get(id) ?? null;
      },
      async updateProfile(id, patch) {
        const org = orgRows.get(id);
        if (!org) throw new Error(`org ${id} not found`);
        // Mirrors the SQL: undefined keys are absent from the object, so spread
        // leaves those fields alone while an explicit null clears them.
        const updated = { ...org, ...patch };
        orgRows.set(id, updated);
        return updated;
      },
      async findBySlug(slug) {
        return [...orgRows.values()].find((o) => o.slug === slug) ?? null;
      },
      async count() {
        return orgRows.size;
      },
    },

    memberships: {
      async findActiveForUser(userId) {
        const row = [...membershipRows.values()].find(
          (m) => m.userId === userId && m.status === 'active',
        );
        return row ? viewOf(row) : null;
      },

      async findActive(userId, orgId) {
        const row = [...membershipRows.values()].find(
          (m) => m.userId === userId && m.orgId === orgId && m.status === 'active',
        );
        return row ? viewOf(row) : null;
      },

      async listForOrg(orgId) {
        return [...membershipRows.values()]
          .filter((m) => m.orgId === orgId)
          .map((m) => {
            const view = viewOf(m);
            return view ? { ...view, userId: m.userId, email: emails.get(m.userId) ?? null } : null;
          })
          .filter((v): v is MembershipView & { userId: UserId; email: string | null } => v !== null);
      },

      async create(input) {
        const membership: Membership = {
          id: `membership-${(seq += 1)}`,
          orgId: input.orgId,
          userId: input.userId,
          roleId: input.roleId,
          status: input.status,
          joinedAt: input.status === 'active' ? clock.now() : null,
        };
        membershipRows.set(membership.id, membership);
        return membership;
      },

      async activate(id, at) {
        const row = membershipRows.get(id);
        if (row) membershipRows.set(id, { ...row, status: 'active', joinedAt: at });
      },

      async updateRole(id, roleId) {
        const row = membershipRows.get(id);
        if (row) membershipRows.set(id, { ...row, roleId });
      },

      async remove(id) {
        membershipRows.delete(id);
      },

      async countActiveWithRole(orgId, roleKey) {
        return [...membershipRows.values()].filter(
          (m) =>
            m.orgId === orgId && m.status === 'active' && roleRows.get(m.roleId)?.key === roleKey,
        ).length;
      },
    },

    roles: {
      async findByKey(orgId, key) {
        return [...roleRows.values()].find((r) => r.orgId === orgId && r.key === key) ?? null;
      },
      async listForOrg(orgId) {
        return [...roleRows.values()].filter((r) => r.orgId === orgId);
      },
      async permissionsFor(roleId) {
        return rolePerms.get(roleId) ?? [];
      },
    },
  };
}

/** Records every event so a test can assert what was written, and in what order. */
export function createRecordingAuditRepo(): AuditRepo & {
  events: AuditEvent[];
  eventsOfType(type: string): AuditEvent[];
} {
  const events: AuditEvent[] = [];
  return {
    events,
    eventsOfType: (type) => events.filter((e) => e.event === type),
    async append(event) {
      events.push(event);
    },
  };
}

export function createRecordingMailer(): Mailer & { sent: RenderedMail[] } {
  const sent: RenderedMail[] = [];
  return {
    sent,
    async send(mail) {
      sent.push(mail);
    },
  };
}

export function createRecordingEventBus(): EventBus & { published: Array<{ type: string }> } {
  const published: Array<{ type: string }> = [];
  return {
    published,
    async publish(event) {
      published.push({ type: event.type });
    },
  };
}

export const silentLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

/**
 * A hasher that is instant and reversible — for tests that are not about hashing.
 *
 * `verifyDummy` counts its calls. Timing parity cannot be asserted against a
 * hasher this fast, so the unit tests assert the *call* instead: that the
 * unknown-user path did the same work as the wrong-password path. The real timing
 * property is measured against Argon2 in `@auth/crypto`'s password.test.ts.
 */
export function createFakeHasher(): PasswordHasher & { dummyVerifies: number } {
  return {
    dummyVerifies: 0,
    async hash(plain) {
      return { hash: `fake:${plain}`, algo: 'argon2id' };
    },
    async verify(plain, stored) {
      return stored === `fake:${plain}`;
    },
    async verifyDummy(_plain) {
      this.dummyVerifies += 1;
      return false;
    },
    needsRehash(stored) {
      return !stored.startsWith('fake:');
    },
  };
}

/** Mints inspectable, unsigned tokens. Signature behaviour is tested in @auth/crypto. */
export function createFakeTokenService(): TokenService & { minted: AccessClaimsLike[] } {
  const minted: AccessClaimsLike[] = [];
  return {
    minted,
    async mintAccess(claims) {
      minted.push(claims);
      return { token: `access:${claims.sub}:${claims.sid}:${minted.length}`, expiresIn: 600 };
    },
    async verifyAccess(token) {
      const [, sub, sid] = token.split(':');
      return {
        sub: sub ?? '',
        sid: sid ?? '',
        org: null,
        roles: [],
        perms: [],
        amr: [],
        iat: 0,
        exp: 0,
        jti: 'fake',
      };
    },
    async jwks() {
      return { keys: [] };
    },
  };
}

type AccessClaimsLike = Parameters<TokenService['mintAccess']>[0];

/**
 * A `SecretBox` that is trivially reversible but still enforces the one property
 * worth testing: the purpose is bound, so a ciphertext sealed for one use cannot
 * be opened for another.
 */
export function createFakeSecretBox(): SecretBox {
  return {
    encrypt(plaintext, purpose) {
      return new TextEncoder().encode(`${purpose}:${plaintext}`);
    },
    decrypt(payload, purpose) {
      const text = new TextDecoder().decode(payload);
      const prefix = `${purpose}:`;
      // ⚑ The real AEAD fails here too, via the AAD. A double that ignored the
      // purpose would let a test pass while production rejected the ciphertext.
      if (!text.startsWith(prefix)) throw new Error('decryption failed');
      return text.slice(prefix.length);
    },
  };
}

/**
 * A deterministic TOTP provider on the injected clock.
 *
 * `codeFor` is the point: a test needs to know what the authenticator app would be
 * showing at a given instant, including one timestep either side, so it can drive
 * the happy path and the drift-replay case without real time passing.
 */
export function createFakeTotp(
  clock: Clock = realClock,
  options: { period?: number; window?: number } = {},
): TotpProvider & { codeFor(secret: TotpSecret, at?: Date): string; timestepAt(at?: Date): number } {
  const period = options.period ?? 30;
  const window = options.window ?? 1;
  let seq = 0;

  const timestepAt = (at: Date = clock.now()) => Math.floor(at.getTime() / 1000 / period);

  const codeAt = (secret: TotpSecret, step: number): string => {
    const digest = createHash('sha256').update(`${secret.base32}:${step}`).digest();
    return String(digest.readUInt32BE(0) % 1_000_000).padStart(6, '0');
  };

  return {
    timestepAt,
    generateSecret: () => ({ base32: `FAKESECRET${(seq += 1)}` }),
    provisioningUri: (secret, account, issuer) =>
      `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret.base32}&issuer=${encodeURIComponent(issuer)}`,
    codeFor: (secret, at) => codeAt(secret, timestepAt(at)),
    verify(secret, code, at) {
      const current = timestepAt(at ?? clock.now());
      for (let drift = -window; drift <= window; drift += 1) {
        if (codeAt(secret, current + drift) === code) {
          return { valid: true, timestep: current + drift };
        }
      }
      return { valid: false, timestep: null };
    },
  };
}

/**
 * Deterministic `CryptoDeps`.
 *
 * `newSecret` counts rather than randomises, so a test can assert *which* secret
 * came back — "the second refresh token issued" is a thing you can name. The
 * hashing is real sha256 because the repositories index on it and a stub would
 * make collisions possible in a way production never is.
 */
export function createTestCryptoDeps(): CryptoDeps & { issued: string[] } {
  const issued: string[] = [];
  let seq = 0;
  return {
    issued,
    sha256: (input: string) => new Uint8Array(createHash('sha256').update(input).digest()),
    newSecret(prefix = 'secret') {
      const secret = `${prefix}_${(seq += 1)}`;
      issued.push(secret);
      return secret;
    },
    clientBinding: (request) =>
      new Uint8Array(
        createHash('sha256')
          .update(`${request.userAgent ?? ''}|${request.ip ?? ''}`)
          .digest(),
      ),
    hex,
  };
}

export interface InMemoryRepos {
  users: ReturnType<typeof createInMemoryUserRepo>;
  sessions: ReturnType<typeof createInMemorySessionRepo>;
  refreshTokens: ReturnType<typeof createInMemoryRefreshTokenRepo>;
  oneTimeTokens: OneTimeTokenRepo;
  otpChallenges: OtpChallengeRepo;
  mfa: MfaRepo;
  trustedDevices: TrustedDeviceRepo;
  orgs: OrgRepo;
  memberships: MembershipRepo;
  roles: RoleRepo;
  audit: ReturnType<typeof createRecordingAuditRepo>;
}

export function createInMemoryRepos(clock: Clock = realClock): InMemoryRepos {
  const users = createInMemoryUserRepo(clock);
  return {
    users,
    sessions: createInMemorySessionRepo(clock),
    refreshTokens: createInMemoryRefreshTokenRepo(clock),
    oneTimeTokens: createInMemoryOneTimeTokenRepo(clock),
    otpChallenges: createInMemoryOtpChallengeRepo(clock),
    mfa: createInMemoryMfaRepo(clock),
    trustedDevices: createInMemoryTrustedDeviceRepo(clock),
    ...createInMemoryOrgRepos(clock, users),
    audit: createRecordingAuditRepo(),
  };
}

export type { RevokeReason };
