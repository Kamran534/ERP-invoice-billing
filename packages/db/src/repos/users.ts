/**
 * User and audit repositories (AUTH-MODULE-PLAN.md §4.1, §4.7).
 */

import { eq, lt, sql } from 'drizzle-orm';
import type { AuditEvent, AuditRepo, User, UserId, UserRepo } from '@auth/core';
import type { Database } from '../pool.js';
import type { RepoDeps } from './deps.js';
import { auditEvents, loginAttempts, passwordHistory, users } from '../schema.js';

type Row = typeof users.$inferSelect;

const toUser = (row: Row): User => ({
  id: row.id,
  email: row.email,
  emailVerifiedAt: row.emailVerifiedAt,
  phone: row.phone,
  phoneVerifiedAt: row.phoneVerifiedAt,
  passwordHash: row.passwordHash,
  passwordAlgo: row.passwordAlgo ?? null,
  passwordUpdatedAt: row.passwordUpdatedAt,
  status: row.status,
  name: row.name,
  mfaRequiredAt: row.mfaRequiredAt,
  failedLoginCount: row.failedLoginCount,
  lockedUntil: row.lockedUntil,
  lastLoginAt: row.lastLoginAt,
  createdAt: row.createdAt,
});

export interface ExtendedUserRepo extends UserRepo {
  recordPasswordInHistory(userId: UserId, hash: string, keep: number): Promise<void>;
  passwordWasUsedBefore(
    userId: UserId,
    matches: (hash: string) => Promise<boolean>,
  ): Promise<boolean>;
}

export function createUserRepo(db: Database, deps: RepoDeps): ExtendedUserRepo {
  return {
    async findById(id) {
      const [row] = await db.select().from(users).where(eq(users.id, id));
      return row ? toUser(row) : null;
    },

    async findByEmail(email) {
      // `email` is citext, so this is already case-insensitive. Wrapping it in
      // LOWER() would also stop the unique index being used.
      const [row] = await db.select().from(users).where(eq(users.email, email.trim()));
      return row ? toUser(row) : null;
    },

    async create(input) {
      const [row] = await db
        .insert(users)
        .values({
          id: deps.uuid(),
          email: input.email.trim(),
          name: input.name ?? null,
          passwordHash: input.passwordHash ?? null,
          passwordAlgo: input.passwordAlgo ?? null,
          passwordUpdatedAt: input.passwordHash ? new Date() : null,
          status: input.status ?? 'pending',
          emailVerifiedAt: input.emailVerifiedAt ?? null,
        })
        .returning();
      return toUser(row!);
    },

    async update(id, patch) {
      // Built explicitly rather than spread: `undefined` must mean "leave alone"
      // while `null` means "clear", and a blanket spread loses that distinction.
      const set: Partial<typeof users.$inferInsert> = { updatedAt: new Date() };
      if (patch.email !== undefined) set.email = patch.email ?? null;
      if (patch.emailVerifiedAt !== undefined) set.emailVerifiedAt = patch.emailVerifiedAt;
      if (patch.phone !== undefined) set.phone = patch.phone;
      if (patch.phoneVerifiedAt !== undefined) set.phoneVerifiedAt = patch.phoneVerifiedAt;
      if (patch.passwordHash !== undefined) set.passwordHash = patch.passwordHash;
      if (patch.passwordAlgo !== undefined) set.passwordAlgo = patch.passwordAlgo;
      if (patch.passwordUpdatedAt !== undefined) set.passwordUpdatedAt = patch.passwordUpdatedAt;
      if (patch.status !== undefined) set.status = patch.status;
      if (patch.name !== undefined) set.name = patch.name;
      if (patch.mfaRequiredAt !== undefined) set.mfaRequiredAt = patch.mfaRequiredAt;
      if (patch.lastLoginAt !== undefined) set.lastLoginAt = patch.lastLoginAt;
      if (patch.lockedUntil !== undefined) set.lockedUntil = patch.lockedUntil;

      const [row] = await db.update(users).set(set).where(eq(users.id, id)).returning();
      if (!row) throw new Error(`user ${id} not found`);
      return toUser(row);
    },

    /**
     * ⚑ One statement. Read-modify-write would let parallel guesses each read the
     * same count and overwrite one another, so an attacker running requests
     * concurrently would never trip the lockout.
     */
    async registerFailedLogin(id, lockAfter, lockForMs) {
      const seconds = `${Math.ceil(lockForMs / 1000)} seconds`;
      const [row] = await db
        .update(users)
        .set({
          failedLoginCount: sql`${users.failedLoginCount} + 1`,
          lockedUntil: sql`CASE WHEN ${users.failedLoginCount} + 1 >= ${lockAfter}
                                THEN now() + ${seconds}::interval
                                ELSE ${users.lockedUntil} END`,
          updatedAt: new Date(),
        })
        .where(eq(users.id, id))
        .returning({ failedLoginCount: users.failedLoginCount, lockedUntil: users.lockedUntil });

      return {
        failedLoginCount: row?.failedLoginCount ?? 0,
        lockedUntil: row?.lockedUntil ?? null,
      };
    },

    async clearFailedLogins(id) {
      await db
        .update(users)
        .set({ failedLoginCount: 0, lockedUntil: null, updatedAt: new Date() })
        .where(eq(users.id, id));
    },

    /** Keeps the most recent `keep` hashes and drops the rest (§8.1). */
    async recordPasswordInHistory(userId, hash, keep) {
      await db.insert(passwordHistory).values({ id: deps.uuid(), userId, passwordHash: hash });
      if (keep <= 0) return;
      await db.execute(sql`
        DELETE FROM auth_password_history
        WHERE user_id = ${userId}
          AND id NOT IN (
            SELECT id FROM auth_password_history
            WHERE user_id = ${userId}
            ORDER BY created_at DESC
            LIMIT ${keep}
          )`);
    },

    /**
     * Argon2 hashes carry their own salt, so they cannot be compared directly. The
     * caller supplies the verifier and we walk the stored history.
     */
    async passwordWasUsedBefore(userId, matches) {
      const rows = await db
        .select({ hash: passwordHistory.passwordHash })
        .from(passwordHistory)
        .where(eq(passwordHistory.userId, userId));
      for (const { hash } of rows) {
        if (await matches(hash)) return true;
      }
      return false;
    },
  };
}

export interface ExtendedAuditRepo extends AuditRepo {
  recordLoginAttempt(input: {
    emailHash: Uint8Array | null;
    ip: string | null;
    success: boolean;
    reason?: string;
  }): Promise<void>;
  purgeLoginAttempts(olderThan: Date): Promise<number>;
}

export function createAuditRepo(db: Database, deps: RepoDeps): ExtendedAuditRepo {
  return {
    /**
     * ⚑ Append-only by convention here and by grant in production: the application
     * role should hold INSERT and SELECT, never UPDATE or DELETE, so a compromised
     * application credential cannot rewrite history (§4.7).
     */
    async append(event: AuditEvent) {
      await db.insert(auditEvents).values({
        id: deps.uuid(),
        event: event.event,
        actorType: event.actorType,
        actorUserId: event.actorUserId ?? null,
        orgId: event.orgId ?? null,
        targetType: event.targetType ?? null,
        targetId: event.targetId ?? null,
        sessionId: event.sessionId ?? null,
        ip: event.ip ?? null,
        userAgent: event.userAgent ?? null,
        outcome: event.outcome ?? 'success',
        metadata: event.metadata ?? {},
      });
    },

    async recordLoginAttempt(input) {
      await db.insert(loginAttempts).values({
        id: deps.uuid(),
        emailHash: input.emailHash ?? null,
        ip: input.ip ?? null,
        success: input.success,
        reason: input.reason ?? null,
      });
    },

    async purgeLoginAttempts(olderThan) {
      const result = await db.delete(loginAttempts).where(lt(loginAttempts.createdAt, olderThan));
      return result.rowCount ?? 0;
    },
  };
}
