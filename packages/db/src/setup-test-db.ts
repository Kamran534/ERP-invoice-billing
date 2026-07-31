/**
 * Creates a throwaway database for the integration suite, and points `.env` at it.
 *
 * ⚑ This exists because the suite truncates every `auth_*` table between tests. It
 * used to do that against whatever `DATABASE_URL` named — which is the database the
 * developer is actually using — and it silently deleted real data. The helpers now
 * refuse that, and this is the one-command way to satisfy them.
 *
 *   pnpm db:test:setup
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

// ⚑ Lives in this package rather than in scripts/, because `pg` is a dependency
// of @auth/db and pnpm's isolated node_modules will not resolve it from the repo
// root — the same class of problem as the CI argon2 probe.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const envFile = path.join(root, '.env');

if (fs.existsSync(envFile)) process.loadEnvFile(envFile);

const source = process.env['DATABASE_URL'];
if (!source) {
  console.error('DATABASE_URL is not set. Copy .env.example to .env first.');
  process.exit(1);
}

const url = new URL(source);
const development = url.pathname.replace(/^\//, '');
const testDatabase = `${development}_test`;

// Connect to `postgres`, not to the database we are about to create.
const adminUrl = new URL(source);
adminUrl.pathname = '/postgres';

const client = new pg.Client({ connectionString: adminUrl.toString() });
await client.connect();

const existing = await client.query('select 1 from pg_database where datname = $1', [testDatabase]);
if (existing.rowCount === 0) {
  // No parameters: CREATE DATABASE cannot take them. The name is derived from a
  // URL we just parsed, not from user input, and is quoted.
  await client.query(`CREATE DATABASE "${testDatabase}"`);
  console.log(`[test-db] created ${testDatabase}`);
} else {
  console.log(`[test-db] ${testDatabase} already exists`);
}
await client.end();

const testUrl = new URL(source);
testUrl.pathname = `/${testDatabase}`;

// ⚑ `docker/postgres/init/01-extensions.sql` only runs against the database the
// container creates on first boot, so a database made afterwards has no `citext`
// — and the very first migration fails with `type "citext" does not exist`, which
// reads like a broken migration rather than a missing extension.
const testClient = new pg.Client({ connectionString: testUrl.toString() });
await testClient.connect();
for (const extension of ['citext', 'pgcrypto']) {
  await testClient.query(`CREATE EXTENSION IF NOT EXISTS ${extension}`);
}
console.log('[test-db] extensions ready: citext, pgcrypto');
await testClient.end();

if (fs.existsSync(envFile)) {
  const contents = fs.readFileSync(envFile, 'utf8');
  if (/^TEST_DATABASE_URL=/m.test(contents)) {
    console.log('[test-db] .env already sets TEST_DATABASE_URL — leaving it alone');
  } else {
    fs.appendFileSync(
      envFile,
      `\n# Created by \`pnpm db:test:setup\`. The integration suite truncates every\n` +
        `# auth_* table between tests, so it must not share a database with your work.\n` +
        `TEST_DATABASE_URL=${testUrl.toString()}\n`,
    );
    console.log('[test-db] added TEST_DATABASE_URL to .env');
  }
}

console.log(`[test-db] now run: pnpm db:migrate:test`);
