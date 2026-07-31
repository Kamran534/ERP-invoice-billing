/**
 * Database helpers for integration tests (AUTH-MODULE-PLAN.md §14.1).
 *
 * Integration tests run against the real Postgres from docker-compose, not a
 * mock. The whole point is to verify the guarantees that live in the *schema* —
 * partial unique indexes, atomic single-statement updates, cascade deletes.
 * A mock cannot tell you whether `UPDATE ... WHERE consumed_at IS NULL` actually
 * serializes two concurrent callers; only Postgres can.
 */

// Everything ORM-shaped comes through @auth/db, so the ORM choice stays behind
// that package boundary (plan §3.2) — the test helpers do not get their own
// drizzle dependency.
import { createDb, schema, sql, getTableName, type DbHandle } from '@auth/db';

/**
 * ⚑ The fallback port is 55432 — what our compose stack publishes — and not the
 * conventional 5432, which on a machine running several stacks is somebody else's
 * database. This module hands out a handle that `truncateAll` empties between
 * tests, so a plausible-but-wrong default is not a connection error, it is data
 * loss in a project nobody was thinking about.
 *
 * `vitest.config.ts` loads `.env` before any of this runs, so in practice the
 * fallback is only reached by something importing these helpers outside vitest.
 */
export const TEST_DATABASE_URL =
  process.env['TEST_DATABASE_URL'] ??
  process.env['DATABASE_URL'] ??
  'postgres://app:app_dev_password@localhost:55432/billing';

/** Every auth table, derived from the schema so it can never drift. */
export const authTableNames: string[] = Object.values(schema).map((table) => getTableName(table));

export function createTestDb(): DbHandle {
  return createDb({
    connectionString: TEST_DATABASE_URL,
    // Integration tests deliberately open several connections at once to prove
    // the concurrency invariants; a pool of 1 would serialize them and the tests
    // would pass for the wrong reason.
    max: 10,
    applicationName: 'billing-test',
    statementTimeoutMs: 10_000,
  });
}

/**
 * Wipes every auth table. One statement so it is atomic, CASCADE so foreign-key
 * order does not matter, RESTART IDENTITY so sequence-backed columns are reset.
 */
export async function truncateAll(handle: DbHandle): Promise<void> {
  const list = authTableNames.map((name) => `"${name}"`).join(', ');
  await handle.db.execute(sql.raw(`TRUNCATE TABLE ${list} RESTART IDENTITY CASCADE`));
}

/**
 * Fails loudly with an actionable message rather than 40 confusing test errors.
 * Called from the integration/e2e global setup.
 */
export async function assertSchemaReady(handle: DbHandle): Promise<void> {
  const result = await handle.db.execute<{ count: string }>(
    sql`select count(*)::text as count
        from information_schema.tables
        where table_schema = 'public' and table_name like 'auth\\_%'`,
  );
  const found = Number(result.rows[0]?.count ?? 0);
  if (found < authTableNames.length) {
    throw new Error(
      `Expected ${authTableNames.length} auth_* tables but found ${found}.\n` +
        `Run:  pnpm up && pnpm db:migrate`,
    );
  }
}
