import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'drizzle-kit';

/**
 * ⚑ drizzle-kit has no `--env-file`, so this config loads `.env` itself.
 *
 * Without it, `db:studio`, `db:generate` and `db:push` see an empty
 * `DATABASE_URL` — the value only ever arrived because someone had exported it by
 * hand, or because `db:migrate` passes `--env-file-if-exists` and everyone assumed
 * the others did too. `vitest.config.ts` does exactly this, for exactly this
 * reason.
 *
 * `process.loadEnvFile` does not clobber variables already in the environment, so
 * an explicit `DATABASE_URL=... pnpm db:studio` still wins.
 */
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const envFile = path.join(root, '.env');
if (fs.existsSync(envFile)) {
  process.loadEnvFile(envFile);
}

const url = process.env['DATABASE_URL'];

/**
 * ⚑ No fallback, deliberately.
 *
 * This used to default to `postgres://app:app_dev_password@localhost:5432/billing`,
 * which is not this project's database. Our compose stack publishes Postgres on
 * **55432**; 5432 is whatever other stack the developer happens to have running.
 * The failure that exposed it was `password authentication failed for user "app"`
 * against a *different project's* server that happened to have an `app` role —
 * and only the password mismatch stopped Studio from opening the wrong database
 * and offering to edit it.
 *
 * A tool that connects somewhere plausible-but-wrong is worse than one that
 * refuses to start.
 */
if (!url) {
  throw new Error(
    'DATABASE_URL is not set, and there is no .env at the repo root.\n' +
      'Copy .env.example to .env, then start the stack with `pnpm up`.',
  );
}

export default defineConfig({
  dialect: 'postgresql',
  schema: './src/schema.ts',
  out: './migrations',
  // Drizzle emits snake_case column names from camelCase fields, matching the
  // explicit names in schema.ts.
  casing: 'snake_case',
  dbCredentials: { url },
  // Keep generated SQL reviewable — this is a security-relevant schema, so the
  // diff gets read by a human before it is applied.
  verbose: true,
  strict: true,
});
