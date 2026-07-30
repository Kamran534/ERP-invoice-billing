/**
 * Test configuration for the whole workspace.
 *
 * Three projects, separated by what they need to run — because a suite you can
 * only run when Docker is up is a suite people stop running:
 *
 *   unit         *.test.ts       no I/O at all. Runs anywhere, in milliseconds.
 *   integration  *.int.test.ts   real Postgres. Verifies schema-level guarantees.
 *   e2e          *.e2e.test.ts   the whole app over HTTP, all dependencies live.
 *
 *   pnpm test              unit only          (default; no Docker needed)
 *   pnpm test:int          integration only
 *   pnpm test:e2e          e2e only
 *   pnpm test:all          everything
 *   pnpm test:coverage     unit + coverage report
 *
 * Workspace packages are aliased to their SOURCE, not their build output, so
 * tests never require a prior `pnpm build`, coverage maps to real files, and a
 * stale dist/ can't silently make a passing test lie.
 */

import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const root = path.dirname(fileURLToPath(import.meta.url));

// Load .env into process.env for the integration and e2e projects.
//
// Vite only exposes `VITE_`-prefixed variables to client code and never populates
// process.env, so without this the tests would silently use the schema defaults
// (port 5432) instead of whatever the developer's .env remapped them to — and the
// failure reads as "Postgres is down" rather than "wrong port".
//
// Workers are forked from this process, so they inherit what we set here.
const envFile = path.join(root, '.env');
if (fs.existsSync(envFile)) {
  process.loadEnvFile(envFile);
}
const pkg = (name: string): string => path.join(root, 'packages', name, 'src', 'index.ts');

const alias = {
  '@auth/core': pkg('core'),
  '@auth/crypto': pkg('crypto'),
  '@auth/db': pkg('db'),
  '@auth/mail': pkg('mail'),
  '@auth/testing': pkg('testing'),
};

const NEVER = ['**/node_modules/**', '**/dist/**', '**/.turbo/**'];

export default defineConfig({
  resolve: { alias },
  test: {
    projects: [
      {
        resolve: { alias },
        test: {
          name: 'unit',
          include: ['packages/*/src/**/*.test.ts', 'apps/*/src/**/*.test.ts'],
          // Integration and e2e files also end in .test.ts; keep them out.
          exclude: [...NEVER, '**/*.int.test.ts', '**/*.e2e.test.ts'],
          environment: 'node',
          // Unit tests touch nothing shared, so let them run in parallel.
          fileParallelism: true,
          testTimeout: 15_000,
        },
      },
      {
        resolve: { alias },
        test: {
          name: 'integration',
          include: ['packages/*/src/**/*.int.test.ts'],
          exclude: NEVER,
          environment: 'node',
          globalSetup: ['./test/global-setup.ts'],
          // ⚑ Serial. These share one database and truncate between tests; running
          // files in parallel would have them wipe each other's rows and fail
          // intermittently — the worst kind of test.
          fileParallelism: false,
          testTimeout: 30_000,
          hookTimeout: 30_000,
        },
      },
      {
        resolve: { alias },
        test: {
          name: 'e2e',
          include: ['apps/*/src/**/*.e2e.test.ts'],
          exclude: NEVER,
          environment: 'node',
          globalSetup: ['./test/global-setup.ts'],
          fileParallelism: false,
          testTimeout: 60_000,
          hookTimeout: 60_000,
        },
      },
    ],

    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      reportsDirectory: './coverage',
      include: ['packages/*/src/**/*.ts', 'apps/*/src/**/*.ts'],
      exclude: [
        '**/*.test.ts',
        '**/index.ts', // barrel re-exports carry no logic
        '**/schema.ts', // table declarations, exercised by the integration suite
        'packages/core/src/ports.ts', // interfaces only — erased at compile time
        'packages/db/src/migrate.ts', // CLI entrypoint, run by `pnpm db:migrate`
        'packages/testing/**', // test scaffolding, not product code
        'apps/api/src/scripts/**', // operator tooling, covered by `pnpm smoke`
        'apps/api/src/index.ts', // process bootstrap; verified by starting it
      ],
      thresholds: {
        // ⚑ Measured over the WHOLE suite (unit + integration + e2e), which is
        // why `test:coverage` runs every project and needs the docker stack. A
        // unit-only number would be meaningless here: the HTTP layer is covered
        // by e2e and the schema by integration.
        //
        // Floors are set just below the current measurement — high enough to
        // catch a real regression, not so high that an unrelated refactor turns
        // CI red and teaches people to lower them. Currently ~95.7% lines,
        // ~87.7% branches, ~94.4% functions.
        lines: 90,
        functions: 90,
        branches: 82,
        statements: 90,

        // The places where an off-by-one is a vulnerability, not a bug.
        'packages/crypto/src/semaphore.ts': {
          lines: 100,
          branches: 90,
          functions: 100,
        },
        'packages/crypto/src/random.ts': {
          lines: 90,
          branches: 85,
          functions: 90,
        },
        'packages/core/src/errors.ts': {
          lines: 90,
          branches: 85,
          functions: 85,
        },
        'packages/core/src/duration.ts': {
          lines: 95,
          branches: 90,
          functions: 100,
        },
      },
    },

    // Fail the run if a test file contains no tests — usually a bad `include`
    // pattern or an `it.only` left behind, both of which silently reduce coverage.
    passWithNoTests: false,
    reporters: process.env['CI'] ? ['default', 'junit'] : ['default'],
    outputFile: { junit: './coverage/junit.xml' },
  },
});
