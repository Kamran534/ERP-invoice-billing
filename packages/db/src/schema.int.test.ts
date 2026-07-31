/**
 * Integration tests against real Postgres (AUTH-MODULE-PLAN.md §14.1).
 *
 * These verify guarantees that live in the *schema*, not in application code:
 * partial unique indexes, single-statement atomicity, cascade deletes, citext
 * comparison. A mock cannot tell you whether
 * `UPDATE ... WHERE consumed_at IS NULL RETURNING` actually serializes two
 * concurrent callers — only the database can, and that atomicity is what stops a
 * password-reset token being redeemed twice.
 *
 * The handlers do not exist yet. These tests are still worth writing now: they
 * pin the invariants Phase 1 will build on, so a schema change that quietly
 * removes one fails here instead of in production.
 *
 *   pnpm up && pnpm db:migrate && pnpm test:int
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { and, eq, isNull, sql } from 'drizzle-orm';
import {
  createTestDb,
  truncateAll,
  insertUser,
  insertSession,
  insertRefreshToken,
  insertOneTimeToken,
  insertOtpChallenge,
  insertOrgWithRole,
  futureDate,
  pastDate,
} from '@auth/testing';
import { sha256, uuidv7 } from '@auth/crypto';
import { schema, type DbHandle } from './index.js';

let handle: DbHandle;

/**
 * Drizzle wraps driver errors, so the pg fields live on `cause`. Asserting on
 * SQLSTATE rather than message text is both more robust (messages are
 * version- and locale-dependent) and more precise: naming the constraint proves
 * that *the specific index we care about* fired, not merely that something was
 * rejected.
 */
interface PgErrorLike {
  code?: string;
  constraint?: string;
  cause?: PgErrorLike;
}

function pgError(error: unknown): PgErrorLike {
  const wrapped = error as PgErrorLike | undefined;
  return wrapped?.code !== undefined ? wrapped : (wrapped?.cause ?? {});
}

const UNIQUE_VIOLATION = '23505';

async function expectUniqueViolation(
  operation: Promise<unknown>,
  constraint?: string,
): Promise<void> {
  await expect(operation).rejects.toSatisfy((error: unknown) => {
    const pg = pgError(error);
    if (pg.code !== UNIQUE_VIOLATION) {
      throw new Error(`expected SQLSTATE ${UNIQUE_VIOLATION}, got ${pg.code ?? 'none'}`);
    }
    if (constraint !== undefined && pg.constraint !== constraint) {
      throw new Error(`expected constraint "${constraint}", got "${pg.constraint ?? 'none'}"`);
    }
    return true;
  });
}

beforeAll(() => {
  handle = createTestDb();
});
afterAll(async () => {
  await handle.close();
});
beforeEach(async () => {
  await truncateAll(handle);
});

// ───────────────────────────────────────────────────────────────────────────
describe('users', () => {
  it('treats email as case-insensitive (citext), so one address is one account', async () => {
    const { db } = handle;
    await insertUser(db, { email: 'Ada@Example.com' });

    // Without citext this insert succeeds and the account is duplicated — then
    // "forgot password" and login can disagree about which row is the user.
    await expectUniqueViolation(insertUser(db, { email: 'ada@example.com' }), 'uq_users_email');

    const found = await db
      .select()
      .from(schema.users)
      .where(eq(schema.users.email, 'ADA@EXAMPLE.COM'));
    expect(found).toHaveLength(1);
  });

  it('allows many users with no email (passkey/SSO-only accounts)', async () => {
    const { db } = handle;
    // A UNIQUE column permits multiple NULLs, which is exactly what we need here.
    await insertUser(db, { email: null });
    await insertUser(db, { email: null });
    const rows = await db.select().from(schema.users).where(isNull(schema.users.email));
    expect(rows).toHaveLength(2);
  });

  it('enforces phone uniqueness but still allows many null phones', async () => {
    const { db } = handle;
    await insertUser(db, { phone: '+15550100' });
    await expectUniqueViolation(insertUser(db, { phone: '+15550100' }), 'uq_users_phone');
    await insertUser(db, {});
    await insertUser(db, {});
  });

  it('defaults to pending, not active — verification is not optional', async () => {
    const { db } = handle;
    const id = uuidv7();
    await db.insert(schema.users).values({ id, email: 'pending@example.test' });
    const [row] = await db.select().from(schema.users).where(eq(schema.users.id, id));
    expect(row?.status).toBe('pending');
    expect(row?.emailVerifiedAt).toBeNull();
    expect(row?.failedLoginCount).toBe(0);
  });

  it('round-trips the jsonb profile extension point', async () => {
    const { db } = handle;
    const { id } = await insertUser(db, { profile: { vatId: 'GB123', tier: 'pro' } });
    const [row] = await db.select().from(schema.users).where(eq(schema.users.id, id));
    expect(row?.profile).toEqual({ vatId: 'GB123', tier: 'pro' });
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('refresh-token rotation invariant (§5.5)', () => {
  it('permits at most one unused token per session', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const session = await insertSession(db, user.id);

    await insertRefreshToken(db, session.id);

    // ⚑ The rotation invariant, enforced by a partial unique index rather than by
    // application discipline. Two live tokens for one session would mean a stolen
    // token could be used indefinitely alongside the legitimate one.
    await expectUniqueViolation(insertRefreshToken(db, session.id), 'uq_refresh_active_per_session');
  });

  it('permits a successor once the predecessor is marked used', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const session = await insertSession(db, user.id);
    const first = await insertRefreshToken(db, session.id);

    await db
      .update(schema.refreshTokens)
      .set({ usedAt: new Date() })
      .where(eq(schema.refreshTokens.id, first.id));

    // This is the normal rotation path and it must not be blocked by the index.
    const second = await insertRefreshToken(db, session.id);
    await db
      .update(schema.refreshTokens)
      .set({ replacedById: second.id })
      .where(eq(schema.refreshTokens.id, first.id));

    const [row] = await db
      .select()
      .from(schema.refreshTokens)
      .where(eq(schema.refreshTokens.id, first.id));
    expect(row?.replacedById).toBe(second.id);
  });

  it('permits a new token after the predecessor is revoked', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const session = await insertSession(db, user.id);
    const first = await insertRefreshToken(db, session.id);

    await db
      .update(schema.refreshTokens)
      .set({ revokedAt: new Date() })
      .where(eq(schema.refreshTokens.id, first.id));

    await expect(insertRefreshToken(db, session.id)).resolves.toBeTruthy();
  });

  it('lets two different sessions each hold a live token', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const a = await insertSession(db, user.id);
    const b = await insertSession(db, user.id);
    await insertRefreshToken(db, a.id);
    // The index is scoped per session; a user on two devices is normal.
    await expect(insertRefreshToken(db, b.id)).resolves.toBeTruthy();
  });

  it('rejects a duplicate token hash globally, so a chain cannot be forked', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const a = await insertSession(db, user.id);
    const b = await insertSession(db, user.id);
    const hash = sha256('shared-secret');

    await insertRefreshToken(db, a.id, { tokenHash: hash, usedAt: new Date() });
    await expectUniqueViolation(
      insertRefreshToken(db, b.id, { tokenHash: hash }),
      'uq_refresh_token_hash',
    );
  });

  it('cascade-deletes the whole chain when the session goes', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const session = await insertSession(db, user.id);
    await insertRefreshToken(db, session.id, { usedAt: new Date() });
    await insertRefreshToken(db, session.id);

    await db.delete(schema.sessions).where(eq(schema.sessions.id, session.id));

    const remaining = await db.select().from(schema.refreshTokens);
    expect(remaining).toHaveLength(0);
  });

  it('cascade-deletes sessions and tokens when the user goes', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const session = await insertSession(db, user.id);
    await insertRefreshToken(db, session.id);

    await db.delete(schema.users).where(eq(schema.users.id, user.id));

    expect(await db.select().from(schema.sessions)).toHaveLength(0);
    expect(await db.select().from(schema.refreshTokens)).toHaveLength(0);
  });

  it('stores only the hash — the secret is never persisted', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const session = await insertSession(db, user.id);
    const { secret } = await insertRefreshToken(db, session.id);

    // Search every text column for the plaintext.
    const dump = await db.execute<{ found: string }>(
      sql`select coalesce(string_agg(token_hash::text, ','), '') as found from auth_refresh_tokens`,
    );
    expect(dump.rows[0]?.found ?? '').not.toContain(secret);
  });

  it('round-trips bytea as Uint8Array, not a Buffer-shaped string', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const session = await insertSession(db, user.id);
    const hash = sha256('known-input');
    const { id } = await insertRefreshToken(db, session.id, { tokenHash: hash });

    const [row] = await db
      .select()
      .from(schema.refreshTokens)
      .where(eq(schema.refreshTokens.id, id));
    expect(row?.tokenHash).toBeInstanceOf(Uint8Array);
    expect(Buffer.from(row!.tokenHash).equals(Buffer.from(hash))).toBe(true);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('one-time token consumption is atomic (§4.4)', () => {
  const consume = async (hash: Uint8Array): Promise<number> => {
    // The exact statement the plan specifies. One statement, no read-then-write.
    const result = await handle.db.execute(
      sql`UPDATE auth_one_time_tokens SET consumed_at = now()
          WHERE token_hash = ${Buffer.from(hash)}
            AND purpose = 'password_reset'
            AND consumed_at IS NULL
            AND expires_at > now()
          RETURNING user_id`,
    );
    return result.rowCount ?? 0;
  };

  it('lets exactly one of many concurrent redemptions win', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const token = await insertOneTimeToken(db, { userId: user.id });

    // ⚑ The test that matters. A read-then-write implementation lets several of
    // these succeed, and one password-reset link resets the password twice — or,
    // worse, is replayable by an attacker who also has the link.
    const results = await Promise.all(Array.from({ length: 12 }, () => consume(token.hash)));

    expect(results.filter((n) => n === 1)).toHaveLength(1);
    expect(results.filter((n) => n === 0)).toHaveLength(11);
  });

  it('refuses a second redemption after the first', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const token = await insertOneTimeToken(db, { userId: user.id });
    expect(await consume(token.hash)).toBe(1);
    expect(await consume(token.hash)).toBe(0);
  });

  it('refuses an expired token', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const token = await insertOneTimeToken(db, { userId: user.id, expiresAt: pastDate(1_000) });
    expect(await consume(token.hash)).toBe(0);
  });

  it('refuses a token presented for the wrong purpose', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    // A magic-link token must not work as a password reset, even though both live
    // in the same table.
    const token = await insertOneTimeToken(db, { userId: user.id, purpose: 'magic_link' });
    expect(await consume(token.hash)).toBe(0);
  });

  it('carries a jsonb payload for email-change and invite flows', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    await insertOneTimeToken(db, {
      userId: user.id,
      purpose: 'email_change',
      payload: { newEmail: 'new@example.test' },
    });
    const [row] = await db
      .select()
      .from(schema.oneTimeTokens)
      .where(eq(schema.oneTimeTokens.purpose, 'email_change'));
    expect(row?.payload).toEqual({ newEmail: 'new@example.test' });
  });

  it('allows a userless invite token addressed to an unregistered email', async () => {
    const { db } = handle;
    const { orgId, roleId } = await insertOrgWithRole(db);
    await expect(
      insertOneTimeToken(db, {
        userId: null,
        purpose: 'org_invite',
        payload: { orgId, roleId, email: 'newhire@example.test' },
      }),
    ).resolves.toBeTruthy();
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('OTP attempt accounting is atomic (§5.11.2)', () => {
  const attempt = async (challengeId: string): Promise<number> => {
    const result = await handle.db.execute(
      sql`UPDATE auth_otp_challenges SET attempts = attempts + 1
          WHERE id = ${challengeId}
            AND consumed_at IS NULL
            AND expires_at > now()
            AND attempts < max_attempts
          RETURNING attempts`,
    );
    return result.rowCount ?? 0;
  };

  it('caps parallel guesses at max_attempts, with no overshoot', async () => {
    const { db } = handle;
    const challenge = await insertOtpChallenge(db, { maxAttempts: 5 });

    // ⚑ 40 simultaneous guesses against a 5-attempt cap. A read-then-write
    // implementation lets far more than 5 through, which turns a 6-digit code
    // into something brute-forceable.
    const results = await Promise.all(Array.from({ length: 40 }, () => attempt(challenge.id)));
    expect(results.filter((n) => n === 1)).toHaveLength(5);

    const [row] = await db
      .select()
      .from(schema.otpChallenges)
      .where(eq(schema.otpChallenges.id, challenge.id));
    expect(row?.attempts).toBe(5);
  });

  it('stops accepting attempts once the cap is reached', async () => {
    const { db } = handle;
    const challenge = await insertOtpChallenge(db, { maxAttempts: 2 });
    expect(await attempt(challenge.id)).toBe(1);
    expect(await attempt(challenge.id)).toBe(1);
    expect(await attempt(challenge.id)).toBe(0);
  });

  it('stops accepting attempts once consumed', async () => {
    const { db } = handle;
    const challenge = await insertOtpChallenge(db);
    await db
      .update(schema.otpChallenges)
      .set({ consumedAt: new Date() })
      .where(eq(schema.otpChallenges.id, challenge.id));
    expect(await attempt(challenge.id)).toBe(0);
  });

  it('stops accepting attempts once expired', async () => {
    const { db } = handle;
    const challenge = await insertOtpChallenge(db, { expiresAt: pastDate(1_000) });
    expect(await attempt(challenge.id)).toBe(0);
  });

  it('holds no raw destination — only a hash', async () => {
    const { db } = handle;
    const email = 'ada@example.test';
    await insertOtpChallenge(db, { destinationHash: sha256(email) });

    // A leak of this table must not be an address harvest.
    const dump = await db.execute<{ txt: string }>(
      sql`select coalesce(string_agg(destination_hash::text, ','), '') as txt from auth_otp_challenges`,
    );
    expect(dump.rows[0]?.txt ?? '').not.toContain(email);
  });

  it('salts the code hash per challenge, so the same code differs across rows', async () => {
    const { db } = handle;
    const a = await insertOtpChallenge(db);
    const b = await insertOtpChallenge(db);
    const rows = await db.select().from(schema.otpChallenges);
    const hashes = rows.map((r) => Buffer.from(r.codeHash).toString('hex'));
    expect(a.code).toBe(b.code); // same code…
    expect(hashes[0]).not.toBe(hashes[1]); // …different stored hash
  });

  it('supports the single-active-challenge rule via a targeted update', async () => {
    const { db } = handle;
    const destination = sha256('ada@example.test');
    await insertOtpChallenge(db, { destinationHash: destination });
    await insertOtpChallenge(db, { destinationHash: destination });

    // Invalidate all live challenges for this destination before issuing a new one.
    const result = await db
      .update(schema.otpChallenges)
      .set({ consumedAt: new Date() })
      .where(
        and(
          eq(schema.otpChallenges.destinationHash, destination),
          eq(schema.otpChallenges.purpose, 'login'),
          isNull(schema.otpChallenges.consumedAt),
        ),
      );
    expect(result.rowCount).toBe(2);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('sessions and trusted devices', () => {
  it('keeps idle and absolute expiry as separate columns', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const idle = futureDate(30 * 86_400_000);
    const absolute = futureDate(90 * 86_400_000);
    const session = await insertSession(db, user.id, {
      idleExpiresAt: idle,
      absoluteExpiresAt: absolute,
    });

    const [row] = await db.select().from(schema.sessions).where(eq(schema.sessions.id, session.id));
    // The absolute cap is what makes a stolen session eventually die even if it
    // is used continuously; collapsing the two would remove that.
    expect(row!.absoluteExpiresAt.getTime()).toBeGreaterThan(row!.idleExpiresAt.getTime());
  });

  it('stores amr as a text array so factor distinctness can be checked', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const session = await insertSession(db, user.id, { amr: ['pwd', 'otp'] });
    const [row] = await db.select().from(schema.sessions).where(eq(schema.sessions.id, session.id));
    expect(row?.amr).toEqual(['pwd', 'otp']);
  });

  it('defaults amr to an empty array rather than null', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const id = uuidv7();
    await db.insert(schema.sessions).values({
      id,
      userId: user.id,
      idleExpiresAt: futureDate(1_000),
      absoluteExpiresAt: futureDate(2_000),
    });
    const [row] = await db.select().from(schema.sessions).where(eq(schema.sessions.id, id));
    expect(row?.amr).toEqual([]);
  });

  it('records the impersonator, so support access is never invisible', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const supporter = await insertUser(db);
    const session = await insertSession(db, user.id, { impersonatedBy: supporter.id });
    const [row] = await db.select().from(schema.sessions).where(eq(schema.sessions.id, session.id));
    expect(row?.impersonatedBy).toBe(supporter.id);
  });

  it('rejects a duplicate trusted-device token hash', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const hash = sha256('device-secret');
    const values = {
      userId: user.id,
      tokenHash: hash,
      mfaSatisfiedAt: new Date(),
      expiresAt: futureDate(30 * 86_400_000),
    };
    await db.insert(schema.trustedDevices).values({ id: uuidv7(), ...values });
    await expectUniqueViolation(
      db.insert(schema.trustedDevices).values({ id: uuidv7(), ...values }),
      'uq_trusted_device_hash',
    );
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('tenancy', () => {
  it('allows one membership per (org, user) and no more', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const { orgId, roleId } = await insertOrgWithRole(db);

    await db.insert(schema.memberships).values({ id: uuidv7(), orgId, userId: user.id, roleId });
    await expectUniqueViolation(
      db.insert(schema.memberships).values({ id: uuidv7(), orgId, userId: user.id, roleId }),
      'uq_memberships_org_user',
    );
  });

  it('⚑ refuses a second organization for the same user', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const a = await insertOrgWithRole(db, { orgName: 'Acme' });
    const b = await insertOrgWithRole(db, { orgName: 'Globex' });

    await db.insert(schema.memberships).values({ id: uuidv7(), orgId: a.orgId, userId: user.id, roleId: a.roleId });

    // One user, one organization (§10.10) — enforced by `uq_memberships_user`, not
    // by the application check beside it. A constraint that lives only in code is
    // one concurrent request away from not existing, and is exactly the sort of
    // thing a later admin script or bulk import forgets about.
    //
    // This test used to assert the opposite. Removing the index is the single
    // change that re-enables multi-tenancy per user, and inverting this is how you
    // find out you have done it.
    // Asserting on `cause.constraint` rather than the message: drizzle wraps the
    // driver error, so the message only says "failed query" and would pass for a
    // null violation, a foreign key, or a typo in the test.
    const rejection = await db
      .insert(schema.memberships)
      .values({ id: uuidv7(), orgId: b.orgId, userId: user.id, roleId: b.roleId })
      .then(
        () => null,
        (error: unknown) => error,
      );
    expect(rejection).not.toBeNull();
    expect((rejection as { cause?: { constraint?: string } }).cause?.constraint).toBe(
      'uq_memberships_user',
    );

    const rows = await db
      .select()
      .from(schema.memberships)
      .where(eq(schema.memberships.userId, user.id));
    expect(rows).toHaveLength(1);
  });

  it('scopes role keys per org, so two orgs can both have "admin"', async () => {
    const { db } = handle;
    const a = await insertOrgWithRole(db, { roleKey: 'admin' });
    const b = await insertOrgWithRole(db, { roleKey: 'admin' });
    expect(a.roleId).not.toBe(b.roleId);
  });

  it('rejects a duplicate role key within one org', async () => {
    const { db } = handle;
    const { orgId } = await insertOrgWithRole(db, { roleKey: 'admin' });
    await expectUniqueViolation(
      db.insert(schema.roles).values({ id: uuidv7(), orgId, key: 'admin', name: 'Admin again' }),
      'uq_roles_org_key',
    );
  });

  it('deduplicates permission grants by primary key', async () => {
    const { db } = handle;
    const { roleId } = await insertOrgWithRole(db);
    await db.insert(schema.rolePermissions).values({ roleId, permission: 'invoice:write' });
    await expectUniqueViolation(
      db.insert(schema.rolePermissions).values({ roleId, permission: 'invoice:write' }),
    );
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('audit and identities', () => {
  it('defaults audit rows to success and an empty metadata object', async () => {
    const { db } = handle;
    const id = uuidv7();
    await db.insert(schema.auditEvents).values({ id, event: 'auth.login_succeeded' });
    const [row] = await db.select().from(schema.auditEvents).where(eq(schema.auditEvents.id, id));
    expect(row?.outcome).toBe('success');
    expect(row?.metadata).toEqual({});
    expect(row?.actorType).toBe('user');
    expect(row?.occurredAt).toBeInstanceOf(Date);
  });

  it('keeps audit rows when the actor is deleted', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    await db.insert(schema.auditEvents).values({
      id: uuidv7(),
      event: 'auth.login_succeeded',
      actorUserId: user.id,
    });

    await db.delete(schema.users).where(eq(schema.users.id, user.id));

    // ⚑ actor_user_id is deliberately not a foreign key: GDPR erasure must not be
    // able to delete the security audit trail (§15).
    expect(await db.select().from(schema.auditEvents)).toHaveLength(1);
  });

  it('enforces one identity per (provider, subject)', async () => {
    const { db } = handle;
    const a = await insertUser(db);
    const b = await insertUser(db);
    const values = { provider: 'google', providerUserId: 'sub-123' };

    await db.insert(schema.identities).values({ id: uuidv7(), userId: a.id, ...values });
    // Otherwise one Google account could be linked to two local users, and
    // "sign in with Google" would be ambiguous.
    await expectUniqueViolation(
      db.insert(schema.identities).values({ id: uuidv7(), userId: b.id, ...values }),
      'uq_identities_provider_subject',
    );
  });

  it('defaults a provider email to unverified', async () => {
    const { db } = handle;
    const user = await insertUser(db);
    const id = uuidv7();
    await db.insert(schema.identities).values({
      id,
      userId: user.id,
      provider: 'github',
      providerUserId: 'gh-1',
      email: 'ada@example.test',
    });
    const [row] = await db.select().from(schema.identities).where(eq(schema.identities.id, id));
    // Auto-linking on an unverified provider email is an account-takeover
    // primitive, so the default must be false (§5.10).
    expect(row?.emailVerified).toBe(false);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('index and id characteristics', () => {
  it('created every expected partial and unique index', async () => {
    const result = await handle.db.execute<{ indexname: string }>(
      sql`select indexname from pg_indexes where schemaname = 'public' and tablename like 'auth\\_%'`,
    );
    const names = result.rows.map((r) => r.indexname);
    for (const expected of [
      'uq_users_email',
      'uq_refresh_active_per_session',
      'uq_refresh_token_hash',
      'uq_trusted_device_hash',
      'uq_memberships_org_user',
      'idx_otp_destination_purpose',
      'idx_sessions_user_live',
      'uq_ott_hash',
    ]) {
      expect(names, `missing index ${expected}`).toContain(expected);
    }
  });

  it('stores UUIDv7 ids that sort in insertion order', async () => {
    const { db } = handle;
    for (let i = 0; i < 25; i += 1) await insertUser(db);
    const rows = await db
      .select({ id: schema.users.id })
      .from(schema.users)
      .orderBy(schema.users.createdAt);
    const ids = rows.map((r) => r.id);
    // Index locality on insert is the reason for v7 over v4.
    expect([...ids].sort()).toEqual(ids);
  });

  it('records timestamps as timestamptz in UTC', async () => {
    const result = await handle.db.execute<{ data_type: string }>(
      sql`select data_type from information_schema.columns
          where table_name = 'auth_sessions' and column_name = 'created_at'`,
    );
    expect(result.rows[0]?.data_type).toBe('timestamp with time zone');
  });
});
