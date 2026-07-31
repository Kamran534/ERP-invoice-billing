/**
 * Session and refresh-token repositories (AUTH-MODULE-PLAN.md §5.5).
 *
 * The refresh chain is the most security-sensitive thing in the system, and the
 * subtlety is entirely in the ordering — see `claim`.
 */

import { and, desc, eq, isNull, sql } from 'drizzle-orm';
import type {
  Amr,
  RefreshClaim,
  RefreshTokenRepo,
  RefreshTokenRow,
  RevokeReason,
  Session,
  SessionId,
  OrgId,
  SessionRepo,
  UserId,
} from '@auth/core';
import type { Database } from '../pool.js';
import type { RepoDeps } from './deps.js';
import { refreshTokens, sessions } from '../schema.js';

type SessionRow = typeof sessions.$inferSelect;
type TokenRow = typeof refreshTokens.$inferSelect;

const toSession = (row: SessionRow): Session => ({
  id: row.id,
  userId: row.userId,
  orgId: row.orgId,
  createdAt: row.createdAt,
  lastSeenAt: row.lastSeenAt,
  idleExpiresAt: row.idleExpiresAt,
  absoluteExpiresAt: row.absoluteExpiresAt,
  revokedAt: row.revokedAt,
  revokedReason: (row.revokedReason as RevokeReason | null) ?? null,
  amr: (row.amr ?? []) as Amr[],
  mfaSatisfiedAt: row.mfaSatisfiedAt,
  impersonatedBy: row.impersonatedBy,
});

const toToken = (row: TokenRow): RefreshTokenRow => ({
  id: row.id,
  sessionId: row.sessionId,
  issuedAt: row.issuedAt,
  expiresAt: row.expiresAt,
  usedAt: row.usedAt,
  replacedById: row.replacedById,
  revokedAt: row.revokedAt,
});

export function createSessionRepo(db: Database, deps: RepoDeps): SessionRepo {
  return {
    async create(input) {
      const [row] = await db
        .insert(sessions)
        .values({
          id: input.id || deps.uuid(),
          userId: input.userId,
          orgId: input.orgId ?? null,
          idleExpiresAt: input.idleExpiresAt,
          absoluteExpiresAt: input.absoluteExpiresAt,
          amr: input.amr,
          mfaSatisfiedAt: input.mfaSatisfiedAt ?? null,
          impersonatedBy: input.impersonatedBy ?? null,
        })
        .returning();
      return toSession(row!);
    },

    async findById(id) {
      const [row] = await db.select().from(sessions).where(eq(sessions.id, id));
      return row ? toSession(row) : null;
    },

    async listActive(userId) {
      const rows = await db
        .select()
        .from(sessions)
        .where(
          and(
            eq(sessions.userId, userId),
            isNull(sessions.revokedAt),
            sql`${sessions.absoluteExpiresAt} > now()`,
          ),
        )
        .orderBy(desc(sessions.lastSeenAt));
      return rows.map(toSession);
    },

    async touch(id, at, idleExpiresAt) {
      await db.update(sessions).set({ lastSeenAt: at, idleExpiresAt }).where(eq(sessions.id, id));
    },

    /**
     * §10.9. ⚑ Changes the active tenant and nothing else — not the session id,
     * not the refresh chain. Switching org is not a new login.
     */
    async setOrg(id: SessionId, orgId: OrgId | null) {
      await db.update(sessions).set({ orgId }).where(eq(sessions.id, id));
    },

    async revoke(id, reason) {
      // Idempotent: revoking an already-dead session must not resurrect the
      // original reason or fail.
      await db
        .update(sessions)
        .set({ revokedAt: new Date(), revokedReason: reason })
        .where(and(eq(sessions.id, id), isNull(sessions.revokedAt)));
    },

    async revokeAllForUser(userId, reason, except) {
      const result = await db
        .update(sessions)
        .set({ revokedAt: new Date(), revokedReason: reason })
        .where(
          and(
            eq(sessions.userId, userId),
            isNull(sessions.revokedAt),
            except ? sql`${sessions.id} <> ${except}` : sql`true`,
          ),
        );
      return result.rowCount ?? 0;
    },
  };
}

export function createRefreshTokenRepo(db: Database, deps: RepoDeps): RefreshTokenRepo {
  return {
    async issue(sessionId, hash, expiresAt) {
      const [row] = await db
        .insert(refreshTokens)
        .values({ id: deps.uuid(), sessionId, tokenHash: hash, expiresAt })
        .returning();
      return toToken(row!);
    },

    /**
     * ⚑ Read first, then claim with a guard. The order is what makes one of the two
     * race cases provable:
     *
     *   read clean, guard updates 0   → certainly a race. Another request claimed
     *                                   this token between our read and our write.
     *   read shows used_at set        → the token was already spent when we looked.
     *
     * The second is **not** proof of theft, and an earlier version of this comment
     * claimed it was. Ten tabs refreshing at once do not all read before the winner
     * writes: the ones that arrive a few milliseconds later read a row that is
     * simply used, which is byte-for-byte what a replay looks like. Whether that is
     * a sibling or a thief is decided in the use-case from `usedAt` and
     * `inFlightWindowMs` — a policy, not something this query can know.
     *
     * Collapsing this into a single `UPDATE ... WHERE used_at IS NULL` would be one
     * round trip fewer and would lose the provable case entirely.
     */
    async claim(hash): Promise<RefreshClaim> {
      const [existing] = await db
        .select()
        .from(refreshTokens)
        .where(eq(refreshTokens.tokenHash, hash));

      if (!existing) return { outcome: 'unknown' };
      const token = toToken(existing);

      if (existing.revokedAt) return { outcome: 'revoked', token };
      if (existing.usedAt) return { outcome: 'reuse', token };
      if (existing.expiresAt.getTime() <= Date.now()) return { outcome: 'expired', token };

      const [claimed] = await db
        .update(refreshTokens)
        .set({ usedAt: new Date() })
        .where(and(eq(refreshTokens.id, existing.id), isNull(refreshTokens.usedAt)))
        .returning();

      return claimed ? { outcome: 'ok', token: toToken(claimed) } : { outcome: 'concurrent', token };
    },

    async link(tokenId, replacedById) {
      await db.update(refreshTokens).set({ replacedById }).where(eq(refreshTokens.id, tokenId));
    },

    /**
     * Kills every token in the session, used and unused alike. Revoking only the
     * token that was replayed would leave the thief's successor alive — which is
     * the entire failure this is meant to prevent.
     */
    async revokeChain(sessionId, _reason) {
      const result = await db
        .update(refreshTokens)
        .set({ revokedAt: new Date() })
        .where(and(eq(refreshTokens.sessionId, sessionId), isNull(refreshTokens.revokedAt)));
      return result.rowCount ?? 0;
    },

    async findBySessionAndSuccessor(tokenId) {
      const [row] = await db.select().from(refreshTokens).where(eq(refreshTokens.id, tokenId));
      return row ? toToken(row) : null;
    },
  };
}
