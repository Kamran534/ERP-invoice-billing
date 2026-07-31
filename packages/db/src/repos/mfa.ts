/**
 * Second-factor and trusted-device repositories (AUTH-MODULE-PLAN.md §5.4).
 */

import { and, desc, eq, isNull, lt, sql } from 'drizzle-orm';
import type { DeviceId, MfaFactor, MfaRepo, TrustedDeviceRepo, UserId } from '@auth/core';
import type { Database } from '../pool.js';
import type { RepoDeps } from './deps.js';
import { mfaFactors, recoveryCodes, trustedDevices } from '../schema.js';

type FactorRow = typeof mfaFactors.$inferSelect;

const toFactor = (row: FactorRow): MfaFactor => ({
  id: row.id,
  userId: row.userId,
  type: row.type,
  label: row.label,
  secretEnc: row.secretEnc,
  confirmedAt: row.confirmedAt,
  lastUsedAt: row.lastUsedAt,
  createdAt: row.createdAt,
});

export function createMfaRepo(db: Database, deps: RepoDeps): MfaRepo {
  return {
    async addFactor(input) {
      const [row] = await db
        .insert(mfaFactors)
        .values({
          id: deps.uuid(),
          userId: input.userId,
          type: input.type,
          label: input.label,
          secretEnc: input.secretEnc,
          // confirmedAt deliberately left null — see listConfirmedFactors.
        })
        .returning();
      return toFactor(row!);
    },

    async findFactor(id) {
      const [row] = await db.select().from(mfaFactors).where(eq(mfaFactors.id, id));
      return row ? toFactor(row) : null;
    },

    /**
     * ⚑ Confirmed only. An enrolment that was started but never proved — the user
     * mis-scanned the QR code and wandered off — must never satisfy a challenge,
     * or it becomes a permanent unverified bypass.
     */
    async listConfirmedFactors(userId) {
      const rows = await db
        .select()
        .from(mfaFactors)
        .where(and(eq(mfaFactors.userId, userId), sql`${mfaFactors.confirmedAt} IS NOT NULL`))
        .orderBy(desc(mfaFactors.createdAt));
      return rows.map(toFactor);
    },

    async listAllFactors(userId) {
      const rows = await db
        .select()
        .from(mfaFactors)
        .where(eq(mfaFactors.userId, userId))
        .orderBy(desc(mfaFactors.createdAt));
      return rows.map(toFactor);
    },

    async confirmFactor(id, at) {
      await db.update(mfaFactors).set({ confirmedAt: at }).where(eq(mfaFactors.id, id));
    },

    async touchFactor(id, at) {
      await db.update(mfaFactors).set({ lastUsedAt: at }).where(eq(mfaFactors.id, id));
    },

    async removeFactor(id) {
      await db.delete(mfaFactors).where(eq(mfaFactors.id, id));
    },

    /** Half-finished enrolments are rubbish that would otherwise accumulate. */
    async purgeUnconfirmed(userId, olderThan) {
      const result = await db
        .delete(mfaFactors)
        .where(
          and(
            eq(mfaFactors.userId, userId),
            isNull(mfaFactors.confirmedAt),
            lt(mfaFactors.createdAt, olderThan),
          ),
        );
      return result.rowCount ?? 0;
    },

    /**
     * Regenerating replaces the whole set in one transaction. Anything else leaves
     * a window where both the old and new codes work, or neither does.
     */
    async replaceRecoveryCodes(userId, hashes) {
      await db.transaction(async (tx) => {
        await tx.delete(recoveryCodes).where(eq(recoveryCodes.userId, userId));
        if (hashes.length > 0) {
          await tx
            .insert(recoveryCodes)
            .values(hashes.map((codeHash) => ({ id: deps.uuid(), userId, codeHash })));
        }
      });
    },

    /** ⚑ Single atomic consume — a recovery code must never work twice. */
    async consumeRecoveryCode(userId, hash) {
      const result = await db.execute(
        sql`UPDATE auth_recovery_codes SET used_at = now()
            WHERE user_id = ${userId}
              AND code_hash = ${Buffer.from(hash)}
              AND used_at IS NULL
            RETURNING id`,
      );
      return (result.rowCount ?? 0) > 0;
    },

    async countUnusedRecoveryCodes(userId) {
      const [row] = await db
        .select({ count: sql<number>`count(*)::int` })
        .from(recoveryCodes)
        .where(and(eq(recoveryCodes.userId, userId), isNull(recoveryCodes.usedAt)));
      return row?.count ?? 0;
    },
  };
}

export function createTrustedDeviceRepo(db: Database, deps: RepoDeps): TrustedDeviceRepo {
  return {
    async create(input) {
      const [row] = await db
        .insert(trustedDevices)
        .values({
          id: deps.uuid(),
          userId: input.userId,
          tokenHash: input.hash,
          label: input.label,
          mfaSatisfiedAt: input.mfaSatisfiedAt,
          expiresAt: input.expiresAt,
        })
        .returning({ id: trustedDevices.id });
      return { id: row!.id };
    },

    /**
     * Live devices only: not revoked, not past the absolute expiry. There is no
     * sliding renewal — 30 days means 30 days from the 2FA that earned it (§5.4.5).
     */
    async findValidByHash(hash) {
      const [row] = await db
        .select({ id: trustedDevices.id, userId: trustedDevices.userId })
        .from(trustedDevices)
        .where(
          and(
            eq(trustedDevices.tokenHash, hash),
            isNull(trustedDevices.revokedAt),
            sql`${trustedDevices.expiresAt} > now()`,
          ),
        );
      return row ?? null;
    },

    async listForUser(userId) {
      return db
        .select({
          id: trustedDevices.id,
          label: trustedDevices.label,
          lastUsedAt: trustedDevices.lastUsedAt,
          expiresAt: trustedDevices.expiresAt,
        })
        .from(trustedDevices)
        .where(and(eq(trustedDevices.userId, userId), isNull(trustedDevices.revokedAt)))
        .orderBy(desc(trustedDevices.createdAt));
    },

    async revoke(id: DeviceId) {
      await db
        .update(trustedDevices)
        .set({ revokedAt: new Date() })
        .where(eq(trustedDevices.id, id));
    },

    /**
     * Called on password change, factor change, 2FA disable and logout-all. Trust
     * must not outlive the credential that justified it.
     */
    async revokeAllForUser(userId: UserId) {
      const result = await db
        .update(trustedDevices)
        .set({ revokedAt: new Date() })
        .where(and(eq(trustedDevices.userId, userId), isNull(trustedDevices.revokedAt)));
      return result.rowCount ?? 0;
    },
  };
}

/** Records that a trusted device was used, for the account-security screen. */
export async function touchTrustedDevice(db: Database, id: DeviceId): Promise<void> {
  await db.update(trustedDevices).set({ lastUsedAt: new Date() }).where(eq(trustedDevices.id, id));
}
