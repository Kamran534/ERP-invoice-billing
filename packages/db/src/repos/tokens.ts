/**
 * One-time tokens and OTP challenges (AUTH-MODULE-PLAN.md §4.4, §5.11).
 *
 * Both consume paths are single statements. That is not a micro-optimisation: a
 * read-then-write lets a password-reset link be redeemed twice, and lets parallel
 * OTP guesses each read the same attempt count and blow past the cap.
 */

import { and, eq, isNull, lt, or, sql } from 'drizzle-orm';
import type {
  OneTimeTokenPurpose,
  OneTimeTokenRepo,
  OtpChallenge,
  OtpChallengeRepo,
  OtpChannel,
  OtpPurpose,
  UserId,
} from '@auth/core';
import type { Database } from '../pool.js';
import type { RepoDeps } from './deps.js';
import { oneTimeTokens, otpChallenges } from '../schema.js';

type ChallengeRow = typeof otpChallenges.$inferSelect;

/**
 * Raw SQL returns the column names, not drizzle's camelCase mapping. Typing this
 * explicitly rather than reusing the inferred row type keeps the two from being
 * silently confused — reading `row.maxAttempts` off a raw result yields undefined,
 * and an undefined cap compares false against every attempt count.
 */
interface RawChallengeRow extends Record<string, unknown> {
  id: string;
  user_id: string | null;
  purpose: OtpPurpose;
  channel: OtpChannel;
  code_hash: Buffer;
  client_binding: Buffer | null;
  attempts: number;
  max_attempts: number;
  resend_count: number;
  expires_at: string | Date;
  consumed_at: string | Date | null;
  last_sent_at: string | Date;
}

const toChallenge = (row: ChallengeRow): OtpChallenge => ({
  id: row.id,
  userId: row.userId,
  purpose: row.purpose,
  channel: row.channel,
  attempts: row.attempts,
  maxAttempts: row.maxAttempts,
  resendCount: row.resendCount,
  expiresAt: row.expiresAt,
  consumedAt: row.consumedAt,
  lastSentAt: row.lastSentAt,
});

export function createOneTimeTokenRepo(db: Database, deps: RepoDeps): OneTimeTokenRepo & {
  purgeExpired(olderThan: Date): Promise<number>;
} {
  return {
    async issue(input) {
      await db.insert(oneTimeTokens).values({
        id: deps.uuid(),
        userId: input.userId,
        purpose: input.purpose,
        tokenHash: input.hash,
        payload: input.payload ?? {},
        expiresAt: input.expiresAt,
        requestedIp: input.requestedIp ?? null,
      });
    },

    /**
     * ⚑ One statement, exactly as specified in §4.4. Twelve concurrent redemptions
     * of the same reset link must produce exactly one winner, and the integration
     * suite asserts that.
     */
    async consume(hash, purpose) {
      const result = await db.execute<{ user_id: string | null; payload: Record<string, unknown> }>(
        sql`UPDATE auth_one_time_tokens SET consumed_at = now()
            WHERE token_hash = ${Buffer.from(hash)}
              AND purpose = ${purpose}
              AND consumed_at IS NULL
              AND expires_at > now()
            RETURNING user_id, payload`,
      );
      const row = result.rows[0];
      return row ? { userId: row.user_id, payload: row.payload ?? {} } : null;
    },

    /**
     * Used after a successful reset so a second outstanding link cannot be used,
     * and after an email change so a stale confirmation cannot resurrect the old
     * address.
     */
    async revokeAllForUser(userId: UserId, purpose: OneTimeTokenPurpose) {
      const result = await db
        .update(oneTimeTokens)
        .set({ consumedAt: new Date() })
        .where(
          and(
            eq(oneTimeTokens.userId, userId),
            eq(oneTimeTokens.purpose, purpose),
            isNull(oneTimeTokens.consumedAt),
          ),
        );
      return result.rowCount ?? 0;
    },

    async purgeExpired(olderThan) {
      const result = await db.delete(oneTimeTokens).where(lt(oneTimeTokens.expiresAt, olderThan));
      return result.rowCount ?? 0;
    },
  };
}

export function createOtpChallengeRepo(db: Database, deps: RepoDeps): OtpChallengeRepo & {
  purgeExpired(olderThan: Date): Promise<number>;
} {
  return {
    async create(input) {
      const [row] = await db
        .insert(otpChallenges)
        .values({
          id: deps.uuid(),
          userId: input.userId,
          purpose: input.purpose,
          channel: input.channel,
          destinationHash: input.destinationHash,
          codeHash: input.codeHash,
          maxAttempts: input.maxAttempts,
          clientBinding: input.clientBinding,
          expiresAt: input.expiresAt,
        })
        .returning();
      return toChallenge(row!);
    },

    /**
     * ⚑ Increments and returns in one statement, so parallel guesses cannot each
     * read the same count. Forty simultaneous attempts against a cap of five record
     * exactly five — asserted in the integration suite.
     *
     * Returns null when the challenge is consumed, expired or already at its cap;
     * the caller cannot tell which, and neither can an attacker.
     */
    async claimAttempt(id) {
      const result = await db.execute<RawChallengeRow>(
        sql`UPDATE auth_otp_challenges SET attempts = attempts + 1
            WHERE id = ${id}
              AND consumed_at IS NULL
              AND expires_at > now()
              AND attempts < max_attempts
            RETURNING *`,
      );
      const row = result.rows[0];
      if (!row) return null;

      return {
        id: row.id,
        userId: row.user_id,
        purpose: row.purpose,
        channel: row.channel,
        attempts: row.attempts,
        maxAttempts: row.max_attempts,
        resendCount: row.resend_count,
        expiresAt: new Date(row.expires_at),
        consumedAt: null,
        lastSentAt: new Date(row.last_sent_at),
        codeHash: new Uint8Array(row.code_hash),
        clientBinding: row.client_binding ? new Uint8Array(row.client_binding) : null,
      };
    },

    async markConsumed(id) {
      await db
        .update(otpChallenges)
        .set({ consumedAt: new Date() })
        .where(eq(otpChallenges.id, id));
    },

    /**
     * Enforces "exactly one live code per destination" (§5.11.1). Without it,
     * several codes are valid at once, which multiplies the guessing surface and
     * makes "the last code I received" ambiguous for the user.
     */
    async invalidateActive(destinationHash, purpose) {
      const result = await db
        .update(otpChallenges)
        .set({ consumedAt: new Date() })
        .where(
          and(
            eq(otpChallenges.destinationHash, destinationHash),
            eq(otpChallenges.purpose, purpose),
            isNull(otpChallenges.consumedAt),
          ),
        );
      return result.rowCount ?? 0;
    },

    /**
     * Server-side resend throttle. The client is told when it may resend, but the
     * limit is enforced here — a client-side timer is a suggestion.
     */
    async registerResend(id, minIntervalMs, maxResends) {
      const result = await db.execute<{ resend_count: number }>(
        sql`UPDATE auth_otp_challenges
            SET resend_count = resend_count + 1, last_sent_at = now()
            WHERE id = ${id}
              AND consumed_at IS NULL
              AND expires_at > now()
              AND resend_count < ${maxResends}
              AND last_sent_at <= now() - ${`${Math.ceil(minIntervalMs / 1000)} seconds`}::interval
            RETURNING resend_count`,
      );
      if (result.rows[0]) return 'sent';

      // Distinguish "too soon" from "no resends left" for the client's benefit;
      // neither reveals anything about whether the account exists.
      const [row] = await db.select().from(otpChallenges).where(eq(otpChallenges.id, id));
      if (!row || row.consumedAt || row.expiresAt.getTime() <= Date.now()) return 'exhausted';
      return row.resendCount >= maxResends ? 'exhausted' : 'too_soon';
    },

    async purgeExpired(olderThan) {
      const result = await db
        .delete(otpChallenges)
        .where(or(lt(otpChallenges.expiresAt, olderThan), lt(otpChallenges.createdAt, olderThan)));
      return result.rowCount ?? 0;
    },
  };
}
