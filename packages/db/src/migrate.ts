/**
 * Migration runner. Safe to run on every deploy and from multiple replicas at
 * once — Drizzle takes an advisory lock and records applied migrations in
 * `drizzle.__drizzle_migrations`.
 *
 *   pnpm db:generate    # author SQL from the schema diff
 *   pnpm db:migrate     # apply
 *
 * ⚑ Deploy rule (plan §16): migrations must stay backward-compatible for one
 * release so N-1 pods keep serving during a rolling deploy. Expand, then
 * migrate, then contract — never rename or drop in the same release that stops
 * writing the old column.
 */

import { fileURLToPath } from 'node:url';
import path from 'node:path';
import pg from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';

const migrationsFolder = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../migrations');

async function main(): Promise<void> {
  // `MIGRATE_TARGET=test` runs against the throwaway database the integration
  // suite uses, so `pnpm db:test:setup` has something to migrate into.
  const target = process.env['MIGRATE_TARGET'] === 'test' ? 'TEST_DATABASE_URL' : 'DATABASE_URL';
  const connectionString = process.env[target];
  if (!connectionString) {
    console.error(`${target} is not set`);
    process.exit(1);
  }

  // A dedicated single connection — never the app pool. Migrations can take
  // locks, and they must not compete with request traffic for pool slots.
  const client = new pg.Client({
    connectionString,
    application_name: 'billing-migrate',
    // Long enough for an index build; migrations are not request-path work.
    statement_timeout: 300_000,
  });

  await client.connect();
  const startedAt = Date.now();
  try {
    console.log(`[migrate] applying from ${migrationsFolder}`);
    await migrate(drizzle(client), { migrationsFolder, migrationsSchema: 'drizzle' });
    console.log(`[migrate] done in ${Date.now() - startedAt}ms`);
  } finally {
    await client.end();
  }
}

main().catch((error: unknown) => {
  console.error('[migrate] failed:', error);
  process.exit(1);
});
