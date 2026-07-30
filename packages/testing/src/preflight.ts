/**
 * Preflight for tests that need real infrastructure.
 *
 * A missing container should produce one clear message telling you what to run,
 * not fifty timeout failures that each look like a different bug.
 */

import { Redis } from 'ioredis';
import { createTestDb, assertSchemaReady, TEST_DATABASE_URL } from './db.js';

export const TEST_REDIS_URL = process.env['REDIS_URL'] ?? 'redis://localhost:6379';

export interface PreflightResult {
  postgres: boolean;
  redis: boolean;
  problems: string[];
}

export async function checkInfra(): Promise<PreflightResult> {
  const problems: string[] = [];
  let postgres = false;
  let redis = false;

  const handle = createTestDb();
  try {
    postgres = await handle.ping();
    if (!postgres) {
      problems.push(`Postgres unreachable at ${redact(TEST_DATABASE_URL)}`);
    } else {
      await assertSchemaReady(handle);
    }
  } catch (error) {
    postgres = false;
    problems.push((error as Error).message);
  } finally {
    await handle.close();
  }

  const client = new Redis(TEST_REDIS_URL, {
    maxRetriesPerRequest: 1,
    connectTimeout: 2_000,
    lazyConnect: true,
    // Otherwise ioredis retries forever and the setup hangs instead of failing.
    retryStrategy: () => null,
  });
  try {
    await client.connect();
    redis = (await client.ping()) === 'PONG';
    if (!redis) problems.push(`Redis unreachable at ${TEST_REDIS_URL}`);
  } catch {
    redis = false;
    problems.push(`Redis unreachable at ${TEST_REDIS_URL}`);
  } finally {
    client.disconnect();
  }

  return { postgres, redis, problems };
}

/** Throws with an actionable message. Call from a vitest globalSetup. */
export async function assertInfraReachable(): Promise<void> {
  const result = await checkInfra();
  if (result.problems.length === 0) return;

  throw new Error(
    [
      '',
      'Integration/e2e tests need the docker stack running.',
      '',
      ...result.problems.map((p) => `  - ${p}`),
      '',
      '  Start it with:  pnpm up && pnpm db:migrate',
      '  Unit tests need none of this:  pnpm test',
      '',
    ].join('\n'),
  );
}

function redact(url: string): string {
  return url.replace(/\/\/[^@]*@/, '//***@');
}
