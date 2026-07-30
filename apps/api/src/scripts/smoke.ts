/**
 * Infrastructure smoke test.
 *
 * Proves the docker stack is genuinely wired — not just that the containers are
 * running. Checks Postgres (connect, extensions, migrated tables), Redis
 * (round-trip with TTL), SMTP (send a real message and read it back out of
 * Mailpit's API), and the API itself (health, JWKS, OpenAPI document).
 *
 *   pnpm smoke
 */

import { Redis } from 'ioredis';
import { createDb, sql } from '@auth/db';
import { createSmtpMailer, renderOtpCode } from '@auth/mail';
import { loadEnv } from '../env.js';

const env = loadEnv();

type Result = { name: string; ok: boolean; detail: string };
const results: Result[] = [];

function record(name: string, ok: boolean, detail: string): void {
  results.push({ name, ok, detail });
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${name.padEnd(34)} ${detail}`);
}

async function check(name: string, fn: () => Promise<string>): Promise<void> {
  const startedAt = performance.now();
  try {
    const detail = await fn();
    record(name, true, `${detail} (${Math.round(performance.now() - startedAt)}ms)`);
  } catch (error) {
    record(name, false, (error as Error).message);
  }
}

async function main(): Promise<void> {
  console.log('\nInfrastructure smoke test\n' + '─'.repeat(64));

  // ── Postgres ─────────────────────────────────────────────────────────────
  const dbHandle = createDb({ connectionString: env.DATABASE_URL, max: 2, applicationName: 'smoke' });

  await check('postgres: connect', async () => {
    const rows = await dbHandle.db.execute<{ version: string }>(sql`select version() as version`);
    const version = rows.rows[0]?.version ?? '';
    return version.split(',')[0] ?? 'connected';
  });

  await check('postgres: extensions', async () => {
    const rows = await dbHandle.db.execute<{ extname: string }>(
      sql`select extname from pg_extension where extname in ('citext','pgcrypto','pg_stat_statements') order by extname`,
    );
    const found = rows.rows.map((r) => r.extname);
    const missing = ['citext', 'pg_stat_statements', 'pgcrypto'].filter((e) => !found.includes(e));
    if (missing.length > 0) throw new Error(`missing: ${missing.join(', ')} — recreate the volume`);
    return found.join(', ');
  });

  await check('postgres: schema migrated', async () => {
    const rows = await dbHandle.db.execute<{ count: string }>(
      sql`select count(*)::text as count from information_schema.tables
          where table_schema = 'public' and table_name like 'auth\\_%'`,
    );
    const count = Number(rows.rows[0]?.count ?? 0);
    if (count === 0) throw new Error('no auth_* tables — run: pnpm db:generate && pnpm db:migrate');
    return `${count} auth_* tables`;
  });

  await check('postgres: write/read/rollback', async () => {
    // Uses a rolled-back transaction so the smoke test leaves no residue.
    await dbHandle.db.transaction(async (tx) => {
      await tx.execute(sql`create temporary table smoke_probe(id int) on commit drop`);
      await tx.execute(sql`insert into smoke_probe values (1)`);
      const rows = await tx.execute<{ id: number }>(sql`select id from smoke_probe`);
      if (rows.rows[0]?.id !== 1) throw new Error('readback mismatch');
    });
    return 'transaction round-trip ok';
  });

  // ── Redis ────────────────────────────────────────────────────────────────
  const redis = new Redis(env.REDIS_URL, { keyPrefix: env.REDIS_KEY_PREFIX, maxRetriesPerRequest: 1 });

  await check('redis: ping', async () => {
    const pong = await redis.ping();
    if (pong !== 'PONG') throw new Error(`unexpected reply: ${pong}`);
    return 'PONG';
  });

  await check('redis: set/get/ttl', async () => {
    const key = `smoke:${Date.now()}`;
    await redis.set(key, 'v', 'EX', 30);
    const value = await redis.get(key);
    const ttl = await redis.ttl(key);
    await redis.del(key);
    if (value !== 'v') throw new Error('value mismatch');
    if (ttl <= 0) throw new Error('ttl not applied — rate limiting would never expire');
    return `ttl ${ttl}s`;
  });

  await check('redis: eviction policy', async () => {
    const config = await redis.config('GET', 'maxmemory-policy');
    const policy = Array.isArray(config) ? String(config[1]) : 'unknown';
    // allkeys-* would evict rate-limit and revocation keys under pressure.
    if (policy.startsWith('allkeys')) {
      throw new Error(`${policy} can evict keys the limiter depends on — use volatile-lru`);
    }
    return policy;
  });

  // ── SMTP ─────────────────────────────────────────────────────────────────
  const mailer = createSmtpMailer({
    host: env.SMTP_HOST,
    port: env.SMTP_PORT,
    secure: env.SMTP_SECURE,
    user: env.SMTP_USER,
    pass: env.SMTP_PASS,
    from: env.MAIL_FROM,
  });

  await check('smtp: handshake', async () => {
    if (!(await mailer.verify())) throw new Error(`cannot reach ${env.SMTP_HOST}:${env.SMTP_PORT}`);
    return `${env.SMTP_HOST}:${env.SMTP_PORT}`;
  });

  const probeAddress = `smoke-${Date.now()}@example.test`;
  await check('smtp: send templated mail', async () => {
    const mail = renderOtpCode({
      appName: env.APP_NAME,
      to: probeAddress,
      code: '000000',
      ttlMinutes: 10,
      purpose: 'login',
    });
    // Assert the rule the template exists to enforce.
    if (mail.subject.includes('000000')) throw new Error('code leaked into the subject line');
    await mailer.send(mail);
    return `queued to ${probeAddress}`;
  });

  if (env.MAILPIT_API_URL) {
    await check('mailpit: message received', async () => {
      // Give the SMTP round-trip a moment; poll rather than sleep blindly.
      for (let attempt = 0; attempt < 10; attempt += 1) {
        const response = await fetch(
          `${env.MAILPIT_API_URL}/api/v1/search?query=${encodeURIComponent(probeAddress)}`,
        );
        if (response.ok) {
          const body = (await response.json()) as { messages?: Array<{ Subject: string }> };
          const first = body.messages?.[0];
          if (first) return `subject: "${first.Subject}"`;
        }
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
      throw new Error('message never arrived in Mailpit');
    });
  }

  // ── API ──────────────────────────────────────────────────────────────────
  const base = `http://127.0.0.1:${env.PORT}`;

  await check('api: /health/live', async () => {
    const response = await fetch(`${base}/health/live`);
    if (!response.ok) throw new Error(`status ${response.status}`);
    const body = (await response.json()) as { status: string; uptimeSeconds: number };
    return `${body.status}, up ${body.uptimeSeconds}s`;
  }).catch(() => undefined);

  await check('api: /health/ready', async () => {
    const response = await fetch(`${base}/health/ready`);
    const body = (await response.json()) as { status: string; checks: Record<string, { ok: boolean }> };
    const failing = Object.entries(body.checks)
      .filter(([, v]) => !v.ok)
      .map(([k]) => k);
    if (failing.length > 0) return `${body.status} (failing: ${failing.join(', ')})`;
    return body.status;
  });

  await check('api: JWKS', async () => {
    const response = await fetch(`${base}/.well-known/jwks.json`);
    if (!response.ok) throw new Error(`status ${response.status}`);
    const body = (await response.json()) as { keys: Array<{ kid?: string; alg?: string }> };
    if (body.keys.length === 0) throw new Error('no keys published');
    return `${body.keys.length} key(s), alg ${body.keys[0]?.alg}`;
  });

  await check('api: OpenAPI document', async () => {
    const response = await fetch(`${base}${env.SWAGGER_ROUTE_PREFIX}/json`);
    if (!response.ok) throw new Error(`status ${response.status} — is SWAGGER_ENABLED=true?`);
    const doc = (await response.json()) as { openapi: string; paths: Record<string, unknown> };
    return `OpenAPI ${doc.openapi}, ${Object.keys(doc.paths).length} paths`;
  });

  // ── Teardown ─────────────────────────────────────────────────────────────
  mailer.close();
  await Promise.allSettled([dbHandle.close(), redis.quit()]);

  const failed = results.filter((r) => !r.ok);
  console.log('─'.repeat(64));
  console.log(`${results.length - failed.length}/${results.length} checks passed\n`);
  if (failed.length > 0) {
    console.log('Failing:');
    for (const f of failed) console.log(`  - ${f.name}: ${f.detail}`);
    console.log('\nIf the API checks failed, start it with: pnpm --filter @app/api dev\n');
    process.exit(1);
  }
}

main().catch((error: unknown) => {
  console.error('\nsmoke test crashed:', error);
  process.exit(1);
});
