/**
 * Infrastructure wiring: Postgres, Redis, SMTP, hasher, token service.
 *
 * Everything is created once and decorated onto the instance, so handlers get
 * dependencies by property access rather than by importing a module-level
 * singleton — which is what makes the app constructible in a test with fakes.
 */

import fp from 'fastify-plugin';
import { Redis } from 'ioredis';
import { createDb, type DbHandle } from '@auth/db';
import { createSmtpMailer, type AppMailer } from '@auth/mail';
import {
  createArgon2Hasher,
  createInMemoryKeyStore,
  createJwtTokenService,
} from '@auth/crypto';
import type { PasswordHasher, TokenService } from '@auth/core';
import type { Env } from '../env.js';

type Hasher = PasswordHasher & {
  stats(): { queueDepth: number; peakQueueDepth: number; shed: number };
  verifyDummy(plain: string): Promise<false>;
};

declare module 'fastify' {
  interface FastifyInstance {
    env: Env;
    dbHandle: DbHandle;
    redis: Redis;
    mailer: AppMailer;
    hasher: Hasher;
    tokens: TokenService;
  }
}

export const infraPlugin = fp(
  async (app, opts: { env: Env }) => {
    const { env } = opts;

    // ── Postgres ────────────────────────────────────────────────────────────
    const dbHandle = createDb({
      connectionString: env.DATABASE_URL,
      max: env.DB_POOL_MAX,
      idleTimeoutMs: env.DB_IDLE_TIMEOUT_MS,
      connectTimeoutMs: env.DB_CONNECT_TIMEOUT_MS,
      statementTimeoutMs: env.DB_STATEMENT_TIMEOUT_MS,
      applicationName: 'billing-api',
      slowQueryMs: env.DB_QUERY_LOG_THRESHOLD_MS,
      onSlowQuery: ({ durationMs, text }) => {
        app.log.warn({ durationMs: Math.round(durationMs), sql: text.slice(0, 300) }, 'slow query');
      },
    });

    // ── Redis ───────────────────────────────────────────────────────────────
    const redis = new Redis(env.REDIS_URL, {
      keyPrefix: env.REDIS_KEY_PREFIX,
      // Fail fast instead of buffering commands forever: a rate-limit check that
      // hangs is worse than one that errors, because the caller can decide.
      enableOfflineQueue: false,
      maxRetriesPerRequest: 2,
      connectTimeout: 3_000,
      commandTimeout: env.REDIS_COMMAND_TIMEOUT_MS,
      retryStrategy: (times) => Math.min(times * 200, 3_000),
      // Reconnect on a failover-induced READONLY reply.
      reconnectOnError: (err) => err.message.includes('READONLY'),
    });
    redis.on('error', (err: Error) => {
      // Logged, not fatal. Fail-closed/fail-open policy lives at the call site
      // (plan §8.2): closed for login and reset, open for refresh.
      app.log.error({ err: err.message }, 'redis error');
    });

    // ⚑ Wait for the first connection before declaring the app ready.
    //
    // `enableOfflineQueue: false` means a command issued before the socket is up
    // throws immediately ("Stream isn't writeable"). Combined with fail-closed
    // rate limiting, the first requests after boot would surface as 500s rather
    // than anything retryable. Bounded wait, and a failure is not fatal — the
    // readiness probe reports it and the orchestrator withholds traffic.
    if (redis.status !== 'ready') {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          app.log.error(
            { redisStatus: redis.status },
            'redis not ready within 5s — readiness will report degraded until it connects',
          );
          resolve();
        }, 5_000);
        timer.unref();
        redis.once('ready', () => {
          clearTimeout(timer);
          resolve();
        });
      });
    }

    // ── Mail ────────────────────────────────────────────────────────────────
    const mailer = createSmtpMailer({
      host: env.SMTP_HOST,
      port: env.SMTP_PORT,
      secure: env.SMTP_SECURE,
      user: env.SMTP_USER,
      pass: env.SMTP_PASS,
      from: env.MAIL_FROM,
      onResult: ({ ok, error }) => {
        if (!ok) app.log.error({ err: error }, 'mail delivery failed');
      },
    });

    // ── Password hashing ────────────────────────────────────────────────────
    const hasher = createArgon2Hasher({
      memoryCost: env.ARGON2_MEMORY_KIB,
      timeCost: env.ARGON2_TIME_COST,
      parallelism: env.ARGON2_PARALLELISM,
      maxConcurrency: env.HASH_MAX_CONCURRENCY,
      queueTimeoutMs: env.HASH_QUEUE_TIMEOUT_MS,
    });

    // ── Token service ───────────────────────────────────────────────────────
    // ⚑ In-memory keys: restarts invalidate access tokens and replicas do not
    // share a key. Replace with the auth_signing_keys-backed store before
    // running more than one instance (plan §8.6, Phase 8).
    const keyStore = await createInMemoryKeyStore();
    if (env.NODE_ENV === 'production') {
      app.log.warn(
        'Using the in-memory signing key store — access tokens will not verify across replicas or restarts',
      );
    }
    const tokens = createJwtTokenService({
      keyStore,
      issuer: env.JWT_ISSUER,
      audience: env.JWT_AUDIENCE,
      accessTtlMs: env.ACCESS_TOKEN_TTL_S * 1_000,
    });

    app.decorate('env', env);
    app.decorate('dbHandle', dbHandle);
    app.decorate('redis', redis);
    app.decorate('mailer', mailer);
    app.decorate('hasher', hasher);
    app.decorate('tokens', tokens);

    // Reverse order of creation; each step is independent so one failure does
    // not strand the others.
    app.addHook('onClose', async (instance) => {
      instance.log.info('closing infrastructure');
      mailer.close();
      await Promise.allSettled([dbHandle.close(), redis.quit()]);
    });
  },
  { name: 'infra' },
);
