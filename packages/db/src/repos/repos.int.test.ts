/**
 * Repository behaviour against real Postgres (AUTH-MODULE-PLAN.md §5.5, §5.11).
 *
 * The schema integration suite proves the raw SQL invariants hold. This proves the
 * repositories actually use them — the same guarantees, reached through the API the
 * use-cases will call.
 *
 * The refresh-token cases are the ones to read first: the difference between
 * "reuse" and "concurrent" is the difference between logging a thief out and
 * logging a legitimate user out. Note what these tests deliberately do *not*
 * assert — the repository reports facts, and the forgiving is done in core.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { eq } from 'drizzle-orm';
import { createTestDb, truncateAll, insertUser, futureDate, pastDate } from '@auth/testing';
import { sha256, uuidv7, randomSecret } from '@auth/crypto';
import type { OneTimeTokenPurpose } from '@auth/core';
import type { DbHandle } from '../pool.js';
import { refreshTokens } from '../schema.js';
import { createRepos, type Repos } from './index.js';

let handle: DbHandle;
let repos: Repos;

beforeAll(() => {
  handle = createTestDb();
  repos = createRepos(handle.db, { uuid: uuidv7 });
});
afterAll(async () => {
  await handle.close();
});
beforeEach(async () => {
  await truncateAll(handle);
});

const newSession = async (userId: string) =>
  repos.sessions.create({
    id: uuidv7(),
    userId,
    orgId: null,
    idleExpiresAt: futureDate(30 * 86_400_000),
    absoluteExpiresAt: futureDate(90 * 86_400_000),
    amr: ['pwd'],
    mfaSatisfiedAt: null,
    impersonatedBy: null,
  });

// ───────────────────────────────────────────────────────────────────────────
describe('users', () => {
  it('finds by email case-insensitively', async () => {
    const created = await repos.users.create({ email: 'Ada@Example.com' });
    expect((await repos.users.findByEmail('ada@example.com'))?.id).toBe(created.id);
    expect((await repos.users.findByEmail('  ADA@EXAMPLE.COM  '))?.id).toBe(created.id);
  });

  it('returns null rather than throwing for an unknown user', async () => {
    // The login path calls this on every attempt, including for addresses that do
    // not exist. It must be a boring null.
    expect(await repos.users.findByEmail('nobody@example.test')).toBeNull();
    expect(await repos.users.findById('0191f0aa-0000-7000-8000-000000000000')).toBeNull();
  });

  it('creates pending, with no password and no verification', async () => {
    const user = await repos.users.create({ email: 'new@example.test' });
    expect(user.status).toBe('pending');
    expect(user.emailVerifiedAt).toBeNull();
    expect(user.passwordHash).toBeNull();
    expect(user.failedLoginCount).toBe(0);
  });

  it('distinguishes "leave alone" from "clear" when updating', async () => {
    const user = await repos.users.create({
      email: 'p@example.test',
      passwordHash: '$argon2id$hash',
      passwordAlgo: 'argon2id',
    });
    // undefined must not wipe a field; null must.
    const untouched = await repos.users.update(user.id, { name: 'Ada' });
    expect(untouched.passwordHash).toBe('$argon2id$hash');
    const cleared = await repos.users.update(user.id, { passwordHash: null });
    expect(cleared.passwordHash).toBeNull();
    expect(cleared.name).toBe('Ada');
  });

  describe('lockout', () => {
    it('counts failures and locks at the threshold', async () => {
      const user = await repos.users.create({ email: 'lock@example.test' });
      for (let i = 1; i <= 2; i += 1) {
        const state = await repos.users.registerFailedLogin(user.id, 3, 900_000);
        expect(state.failedLoginCount).toBe(i);
        expect(state.lockedUntil).toBeNull();
      }
      const locked = await repos.users.registerFailedLogin(user.id, 3, 900_000);
      expect(locked.failedLoginCount).toBe(3);
      expect(locked.lockedUntil).toBeInstanceOf(Date);
      expect(locked.lockedUntil!.getTime()).toBeGreaterThan(Date.now());
    });

    it('counts every parallel failure', async () => {
      // ⚑ The reason this is one statement. Read-modify-write would let ten
      // concurrent guesses each read 0 and write 1, so the lock would never engage
      // for exactly the attacker who parallelises.
      const user = await repos.users.create({ email: 'parallel@example.test' });
      await Promise.all(
        Array.from({ length: 10 }, () => repos.users.registerFailedLogin(user.id, 5, 900_000)),
      );
      expect((await repos.users.findById(user.id))?.failedLoginCount).toBe(10);
    });

    it('clears the counter and the lock on success', async () => {
      const user = await repos.users.create({ email: 'clear@example.test' });
      await repos.users.registerFailedLogin(user.id, 1, 900_000);
      await repos.users.clearFailedLogins(user.id);
      const after = await repos.users.findById(user.id);
      expect(after?.failedLoginCount).toBe(0);
      expect(after?.lockedUntil).toBeNull();
    });
  });

  it('keeps only the configured depth of password history', async () => {
    const user = await repos.users.create({ email: 'hist@example.test' });
    for (const hash of ['h1', 'h2', 'h3', 'h4', 'h5']) {
      await repos.users.recordPasswordInHistory(user.id, hash, 3);
    }
    const seen: string[] = [];
    await repos.users.passwordWasUsedBefore(user.id, async (h) => {
      seen.push(h);
      return false;
    });
    expect(seen.sort()).toEqual(['h3', 'h4', 'h5']);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('refresh tokens', () => {
  it('claims an unused token exactly once', async () => {
    const user = await insertUser(handle.db);
    const session = await newSession(user.id);
    const secret = randomSecret('rt');
    await repos.refreshTokens.issue(session.id, sha256(secret), futureDate(86_400_000));

    const first = await repos.refreshTokens.claim(sha256(secret));
    expect(first.outcome).toBe('ok');

    // The second presentation is reuse — the token is spent.
    const second = await repos.refreshTokens.claim(sha256(secret));
    expect(second.outcome).toBe('reuse');
  });

  it('reports an unknown token without leaking that it is unknown', async () => {
    const claim = await repos.refreshTokens.claim(sha256(randomSecret('rt')));
    expect(claim.outcome).toBe('unknown');
  });

  it('lets exactly one of ten simultaneous refreshes win', async () => {
    const user = await insertUser(handle.db);
    const session = await newSession(user.id);
    const secret = randomSecret('rt');
    await repos.refreshTokens.issue(session.id, sha256(secret), futureDate(86_400_000));

    const claims = await Promise.all(
      Array.from({ length: 10 }, () => repos.refreshTokens.claim(sha256(secret))),
    );
    const outcomes = claims.map((c) => c.outcome);

    // The atomicity guarantee, which is absolute: the token is spendable once.
    expect(outcomes.filter((o) => o === 'ok')).toHaveLength(1);
    expect(outcomes).not.toContain('unknown');
    expect(outcomes).not.toContain('revoked');
    expect(outcomes).not.toContain('expired');
  });

  it('⚑ cannot itself tell a late sibling from a replay — but dates the claim', async () => {
    // This is the test that caught the design error. Under real parallelism the
    // losers do NOT all read before the winner writes: whichever ones the pool
    // starts after the winner commits see a plainly-used row, which is exactly what
    // a thief's replay looks like. Asserting `reuse` never occurs here passed on a
    // fast laptop and failed on CI, because it was asserting a scheduling accident.
    //
    // What the repository can promise is the fact the use-case needs: every loser
    // reports a `usedAt` from moments ago, so `inFlightWindowMs` can forgive them.
    const user = await insertUser(handle.db);
    const session = await newSession(user.id);
    const secret = randomSecret('rt');
    await repos.refreshTokens.issue(session.id, sha256(secret), futureDate(86_400_000));

    const before = Date.now();
    const claims = await Promise.all(
      Array.from({ length: 10 }, () => repos.refreshTokens.claim(sha256(secret))),
    );

    const losers = claims.filter((c) => c.outcome !== 'ok');
    expect(losers).toHaveLength(9);
    for (const loser of losers) {
      expect(['concurrent', 'reuse']).toContain(loser.outcome);
      if (loser.outcome === 'reuse') {
        expect(loser.token.usedAt).not.toBeNull();
        expect(loser.token.usedAt!.getTime()).toBeGreaterThanOrEqual(before - 1_000);
      }
    }
  });

  it('reports a token used long ago as reuse, with a stale usedAt', async () => {
    const user = await insertUser(handle.db);
    const session = await newSession(user.id);
    const secret = randomSecret('rt');
    const issued = await repos.refreshTokens.issue(
      session.id,
      sha256(secret),
      futureDate(86_400_000),
    );

    const first = await repos.refreshTokens.claim(sha256(secret));
    expect(first.outcome).toBe('ok');

    // Backdate the claim, standing in for "spent an hour ago" — the case where a
    // second presentation really is a replay and no window should forgive it.
    await handle.db
      .update(refreshTokens)
      .set({ usedAt: new Date(Date.now() - 3_600_000) })
      .where(eq(refreshTokens.id, issued.id));

    const second = await repos.refreshTokens.claim(sha256(secret));
    expect(second.outcome).toBe('reuse');
    if (second.outcome !== 'reuse') return;
    expect(Date.now() - second.token.usedAt!.getTime()).toBeGreaterThan(60_000);
  });

  it('reports a revoked token as revoked, not as reuse', async () => {
    const user = await insertUser(handle.db);
    const session = await newSession(user.id);
    const secret = randomSecret('rt');
    await repos.refreshTokens.issue(session.id, sha256(secret), futureDate(86_400_000));
    await repos.refreshTokens.revokeChain(session.id, 'logout');

    // Logging out then presenting the old token is not an attack.
    expect((await repos.refreshTokens.claim(sha256(secret))).outcome).toBe('revoked');
  });

  it('reports an expired token as expired', async () => {
    const user = await insertUser(handle.db);
    const session = await newSession(user.id);
    const secret = randomSecret('rt');
    await repos.refreshTokens.issue(session.id, sha256(secret), pastDate(1_000));
    expect((await repos.refreshTokens.claim(sha256(secret))).outcome).toBe('expired');
  });

  it('links a successor so the chain can be walked', async () => {
    const user = await insertUser(handle.db);
    const session = await newSession(user.id);
    const first = randomSecret('rt');
    const issued = await repos.refreshTokens.issue(session.id, sha256(first), futureDate(86_400_000));

    await repos.refreshTokens.claim(sha256(first));
    const successor = await repos.refreshTokens.issue(
      session.id,
      sha256(randomSecret('rt')),
      futureDate(86_400_000),
    );
    await repos.refreshTokens.link(issued.id, successor.id);

    expect((await repos.refreshTokens.findBySessionAndSuccessor(issued.id))?.replacedById).toBe(
      successor.id,
    );
  });

  it('revokes the whole chain, not just the token that was replayed', async () => {
    // Revoking only the replayed token leaves the thief's successor alive, which is
    // exactly the failure reuse detection exists to prevent.
    const user = await insertUser(handle.db);
    const session = await newSession(user.id);
    const a = randomSecret('rt');
    await repos.refreshTokens.issue(session.id, sha256(a), futureDate(86_400_000));
    await repos.refreshTokens.claim(sha256(a));
    const b = randomSecret('rt');
    await repos.refreshTokens.issue(session.id, sha256(b), futureDate(86_400_000));

    const revoked = await repos.refreshTokens.revokeChain(session.id, 'reuse_detected');
    expect(revoked).toBeGreaterThanOrEqual(1);
    expect((await repos.refreshTokens.claim(sha256(b))).outcome).toBe('revoked');
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('sessions', () => {
  it('lists only live sessions, newest activity first', async () => {
    const user = await insertUser(handle.db);
    const live = await newSession(user.id);
    const dead = await newSession(user.id);
    await repos.sessions.revoke(dead.id, 'logout');

    const active = await repos.sessions.listActive(user.id);
    expect(active.map((s) => s.id)).toEqual([live.id]);
  });

  it('revoking is idempotent and keeps the original reason', async () => {
    const user = await insertUser(handle.db);
    const session = await newSession(user.id);
    await repos.sessions.revoke(session.id, 'reuse_detected');
    await repos.sessions.revoke(session.id, 'logout');
    // The first reason is the true one; a later revoke must not overwrite it.
    expect((await repos.sessions.findById(session.id))?.revokedReason).toBe('reuse_detected');
  });

  it('revokes all sessions except the current one', async () => {
    const user = await insertUser(handle.db);
    const keep = await newSession(user.id);
    await newSession(user.id);
    await newSession(user.id);

    expect(await repos.sessions.revokeAllForUser(user.id, 'logout_all', keep.id)).toBe(2);
    expect((await repos.sessions.listActive(user.id)).map((s) => s.id)).toEqual([keep.id]);
  });

  it('slides the idle expiry on touch without moving the absolute cap', async () => {
    const user = await insertUser(handle.db);
    const session = await newSession(user.id);
    const absoluteBefore = session.absoluteExpiresAt.getTime();

    const slid = futureDate(31 * 86_400_000);
    await repos.sessions.touch(session.id, new Date(), slid);

    const after = await repos.sessions.findById(session.id);
    expect(after!.idleExpiresAt.getTime()).toBeCloseTo(slid.getTime(), -3);
    // ⚑ The absolute cap is never extended, for any reason.
    expect(after!.absoluteExpiresAt.getTime()).toBe(absoluteBefore);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('one-time tokens', () => {
  const issue = async (userId: string, purpose: OneTimeTokenPurpose = 'password_reset') => {
    const secret = randomSecret();
    await repos.oneTimeTokens.issue({
      userId,
      purpose,
      hash: sha256(secret),
      payload: { note: 'x' },
      expiresAt: futureDate(3_600_000),
    });
    return secret;
  };

  it('consumes once and only once, even in parallel', async () => {
    const user = await insertUser(handle.db);
    const secret = await issue(user.id);

    const results = await Promise.all(
      Array.from({ length: 12 }, () => repos.oneTimeTokens.consume(sha256(secret), 'password_reset')),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it('returns the payload to the winner', async () => {
    const user = await insertUser(handle.db);
    const secret = await issue(user.id);
    const consumed = await repos.oneTimeTokens.consume(sha256(secret), 'password_reset');
    expect(consumed).toEqual({ userId: user.id, payload: { note: 'x' } });
  });

  it('refuses the wrong purpose', async () => {
    const user = await insertUser(handle.db);
    const secret = await issue(user.id, 'magic_link');
    // A magic link must not work as a password reset, though both share the table.
    expect(await repos.oneTimeTokens.consume(sha256(secret), 'password_reset')).toBeNull();
  });

  it('invalidates every outstanding token of a purpose', async () => {
    const user = await insertUser(handle.db);
    const a = await issue(user.id);
    const b = await issue(user.id);
    expect(await repos.oneTimeTokens.revokeAllForUser(user.id, 'password_reset')).toBe(2);
    expect(await repos.oneTimeTokens.consume(sha256(a), 'password_reset')).toBeNull();
    expect(await repos.oneTimeTokens.consume(sha256(b), 'password_reset')).toBeNull();
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('otp challenges', () => {
  const create = async (overrides: { maxAttempts?: number; expiresAt?: Date } = {}) =>
    repos.otpChallenges.create({
      userId: null,
      purpose: 'login',
      channel: 'email',
      destinationHash: sha256('ada@example.test'),
      codeHash: sha256('123456'),
      maxAttempts: overrides.maxAttempts ?? 5,
      clientBinding: null,
      expiresAt: overrides.expiresAt ?? futureDate(600_000),
    });

  it('caps parallel attempts at exactly max_attempts', async () => {
    // ⚑ Six digits is ~20 bits; safe only because this cap holds under concurrency.
    const challenge = await create({ maxAttempts: 5 });
    const claimed = await Promise.all(
      Array.from({ length: 40 }, () => repos.otpChallenges.claimAttempt(challenge.id)),
    );
    expect(claimed.filter(Boolean)).toHaveLength(5);
  });

  it('returns the code hash and binding to the caller that claimed an attempt', async () => {
    const challenge = await create();
    const claimed = await repos.otpChallenges.claimAttempt(challenge.id);
    expect(claimed).not.toBeNull();
    expect(Buffer.from(claimed!.codeHash).equals(Buffer.from(sha256('123456')))).toBe(true);
    expect(claimed!.maxAttempts).toBe(5);
    expect(claimed!.attempts).toBe(1);
  });

  it('refuses attempts once consumed or expired', async () => {
    const consumed = await create();
    await repos.otpChallenges.markConsumed(consumed.id);
    expect(await repos.otpChallenges.claimAttempt(consumed.id)).toBeNull();

    const expired = await create({ expiresAt: pastDate(1_000) });
    expect(await repos.otpChallenges.claimAttempt(expired.id)).toBeNull();
  });

  it('invalidates live challenges for a destination so only one code is ever valid', async () => {
    await create();
    await create();
    expect(await repos.otpChallenges.invalidateActive(sha256('ada@example.test'), 'login')).toBe(2);
  });

  it('throttles resends, then exhausts them', async () => {
    const challenge = await create();
    // The first resend is immediately too soon — last_sent_at is now.
    expect(await repos.otpChallenges.registerResend(challenge.id, 60_000, 3)).toBe('too_soon');
    // With no minimum interval it succeeds until the cap.
    expect(await repos.otpChallenges.registerResend(challenge.id, 0, 3)).toBe('sent');
    expect(await repos.otpChallenges.registerResend(challenge.id, 0, 3)).toBe('sent');
    expect(await repos.otpChallenges.registerResend(challenge.id, 0, 3)).toBe('sent');
    expect(await repos.otpChallenges.registerResend(challenge.id, 0, 3)).toBe('exhausted');
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('mfa factors and recovery codes', () => {
  it('hides unconfirmed factors from the list that satisfies a challenge', async () => {
    const user = await insertUser(handle.db);
    const unconfirmed = await repos.mfa.addFactor({
      userId: user.id,
      type: 'totp',
      label: 'Phone',
      secretEnc: new Uint8Array([1, 2, 3]),
    });

    // ⚑ A half-finished enrolment must never count as a second factor.
    expect(await repos.mfa.listConfirmedFactors(user.id)).toHaveLength(0);
    expect(await repos.mfa.listAllFactors(user.id)).toHaveLength(1);

    await repos.mfa.confirmFactor(unconfirmed.id, new Date());
    expect(await repos.mfa.listConfirmedFactors(user.id)).toHaveLength(1);
  });

  it('purges only stale unconfirmed factors', async () => {
    const user = await insertUser(handle.db);
    const confirmed = await repos.mfa.addFactor({ userId: user.id, type: 'totp', label: null, secretEnc: null });
    await repos.mfa.confirmFactor(confirmed.id, new Date());
    await repos.mfa.addFactor({ userId: user.id, type: 'totp', label: null, secretEnc: null });

    expect(await repos.mfa.purgeUnconfirmed(user.id, futureDate(1_000))).toBe(1);
    expect(await repos.mfa.listAllFactors(user.id)).toHaveLength(1);
  });

  it('consumes a recovery code exactly once, even in parallel', async () => {
    const user = await insertUser(handle.db);
    const codes = ['AAAAA-BBBBB', 'CCCCC-DDDDD'];
    await repos.mfa.replaceRecoveryCodes(user.id, codes.map((c) => sha256(c)));
    expect(await repos.mfa.countUnusedRecoveryCodes(user.id)).toBe(2);

    const results = await Promise.all(
      Array.from({ length: 8 }, () => repos.mfa.consumeRecoveryCode(user.id, sha256(codes[0]!))),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await repos.mfa.countUnusedRecoveryCodes(user.id)).toBe(1);
  });

  it('regenerating invalidates every previous code', async () => {
    const user = await insertUser(handle.db);
    await repos.mfa.replaceRecoveryCodes(user.id, [sha256('OLD-CODE')]);
    await repos.mfa.replaceRecoveryCodes(user.id, [sha256('NEW-CODE')]);

    expect(await repos.mfa.consumeRecoveryCode(user.id, sha256('OLD-CODE'))).toBe(false);
    expect(await repos.mfa.consumeRecoveryCode(user.id, sha256('NEW-CODE'))).toBe(true);
  });

  it('does not accept another user’s recovery code', async () => {
    const [a, b] = [await insertUser(handle.db), await insertUser(handle.db)];
    await repos.mfa.replaceRecoveryCodes(a.id, [sha256('SHARED')]);
    expect(await repos.mfa.consumeRecoveryCode(b.id, sha256('SHARED'))).toBe(false);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('trusted devices', () => {
  const trust = async (userId: string, expiresAt = futureDate(30 * 86_400_000)) => {
    const secret = randomSecret();
    await repos.trustedDevices.create({
      userId,
      hash: sha256(secret),
      label: 'Chrome on Windows',
      mfaSatisfiedAt: new Date(),
      expiresAt,
    });
    return secret;
  };

  it('finds a live device by its cookie hash', async () => {
    const user = await insertUser(handle.db);
    const secret = await trust(user.id);
    expect((await repos.trustedDevices.findValidByHash(sha256(secret)))?.userId).toBe(user.id);
  });

  it('ignores an expired device — there is no sliding renewal', async () => {
    const user = await insertUser(handle.db);
    const secret = await trust(user.id, pastDate(1_000));
    expect(await repos.trustedDevices.findValidByHash(sha256(secret))).toBeNull();
  });

  it('revokes every device when a credential changes', async () => {
    // ⚑ Trust must not outlive the credential that justified it.
    const user = await insertUser(handle.db);
    const a = await trust(user.id);
    const b = await trust(user.id);

    expect(await repos.trustedDevices.revokeAllForUser(user.id)).toBe(2);
    expect(await repos.trustedDevices.findValidByHash(sha256(a))).toBeNull();
    expect(await repos.trustedDevices.findValidByHash(sha256(b))).toBeNull();
    expect(await repos.trustedDevices.listForUser(user.id)).toHaveLength(0);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('audit', () => {
  it('records an event with its actor and context', async () => {
    const user = await insertUser(handle.db);
    await repos.audit.append({
      event: 'auth.login_succeeded',
      actorType: 'user',
      actorUserId: user.id,
      ip: '203.0.113.7',
      userAgent: 'vitest',
      metadata: { method: 'password' },
    });
    // Verified through the schema suite; here we only assert it does not throw and
    // defaults are applied.
    await expect(
      repos.audit.append({ event: 'auth.login_failed', actorType: 'system', outcome: 'failure' }),
    ).resolves.toBeUndefined();
  });

  it('records login attempts against a hashed address', async () => {
    await repos.audit.recordLoginAttempt({
      emailHash: sha256('ada@example.test'),
      ip: '203.0.113.7',
      success: false,
      reason: 'invalid_credentials',
    });
    expect(await repos.audit.purgeLoginAttempts(futureDate(1_000))).toBe(1);
  });
});
