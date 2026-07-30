/**
 * Test fixtures. Each builder takes overrides so a test states only the field it
 * cares about — a test that sets `usedAt` is visibly about token reuse, and one
 * that sets `expiresAt` is visibly about expiry.
 */

import { sha256, uuidv7, randomSecret } from '@auth/crypto';
import {
  schema,
  type Database,
} from '@auth/db';

type Overrides<T> = Partial<T>;

export const futureDate = (ms: number): Date => new Date(Date.now() + ms);
export const pastDate = (ms: number): Date => new Date(Date.now() - ms);

export interface InsertedUser {
  id: string;
  email: string;
}

export async function insertUser(
  db: Database,
  overrides: Overrides<typeof schema.users.$inferInsert> = {},
): Promise<InsertedUser> {
  const id = overrides.id ?? uuidv7();
  // ⚑ Uses the WHOLE id, not a prefix. The leading 48 bits of a UUIDv7 are the
  // millisecond timestamp, so `id.slice(0, 8)` is identical for every row created
  // in the same millisecond — a fixture that looked unique and wasn't.
  const email = overrides.email ?? `user-${id}@example.test`;
  await db.insert(schema.users).values({
    id,
    email,
    status: 'active',
    emailVerifiedAt: new Date(),
    ...overrides,
  });
  return { id, email };
}

export async function insertSession(
  db: Database,
  userId: string,
  overrides: Overrides<typeof schema.sessions.$inferInsert> = {},
): Promise<{ id: string }> {
  const id = overrides.id ?? uuidv7();
  await db.insert(schema.sessions).values({
    id,
    userId,
    idleExpiresAt: futureDate(30 * 86_400_000),
    absoluteExpiresAt: futureDate(90 * 86_400_000),
    amr: ['pwd'],
    ...overrides,
  });
  return { id };
}

/** Returns the plaintext secret too, so a test can present it back. */
export async function insertRefreshToken(
  db: Database,
  sessionId: string,
  overrides: Overrides<typeof schema.refreshTokens.$inferInsert> = {},
): Promise<{ id: string; secret: string }> {
  const id = overrides.id ?? uuidv7();
  const secret = randomSecret('rt');
  await db.insert(schema.refreshTokens).values({
    id,
    sessionId,
    tokenHash: overrides.tokenHash ?? sha256(secret),
    expiresAt: futureDate(30 * 86_400_000),
    ...overrides,
  });
  return { id, secret };
}

export async function insertOneTimeToken(
  db: Database,
  overrides: Overrides<typeof schema.oneTimeTokens.$inferInsert> = {},
): Promise<{ id: string; secret: string; hash: Uint8Array }> {
  const id = overrides.id ?? uuidv7();
  const secret = randomSecret();
  const hash = overrides.tokenHash ?? sha256(secret);
  await db.insert(schema.oneTimeTokens).values({
    id,
    purpose: 'password_reset',
    tokenHash: hash,
    expiresAt: futureDate(3_600_000),
    ...overrides,
  });
  return { id, secret, hash };
}

export async function insertOtpChallenge(
  db: Database,
  overrides: Overrides<typeof schema.otpChallenges.$inferInsert> = {},
): Promise<{ id: string; code: string }> {
  const id = overrides.id ?? uuidv7();
  const code = '123456';
  await db.insert(schema.otpChallenges).values({
    id,
    purpose: 'login',
    channel: 'email',
    destinationHash: sha256('ada@example.test'),
    codeHash: sha256(`${code}:${id}`),
    maxAttempts: 5,
    expiresAt: futureDate(600_000),
    ...overrides,
  });
  return { id, code };
}

export async function insertOrgWithRole(
  db: Database,
  overrides: { orgName?: string; roleKey?: string } = {},
): Promise<{ orgId: string; roleId: string }> {
  const orgId = uuidv7();
  const roleId = uuidv7();
  await db.insert(schema.orgs).values({
    id: orgId,
    name: overrides.orgName ?? 'Acme',
    // Full id, for the same reason as insertUser's email.
    slug: `acme-${orgId}`,
  });
  await db.insert(schema.roles).values({
    id: roleId,
    orgId,
    key: overrides.roleKey ?? 'admin',
    name: 'Admin',
  });
  return { orgId, roleId };
}
