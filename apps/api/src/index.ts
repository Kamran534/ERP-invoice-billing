/**
 * Entrypoint: validate env, build the app, listen, and shut down cleanly.
 *
 * Graceful shutdown is not cosmetic. Without it, a rolling deploy kills
 * in-flight logins and drops pool connections mid-transaction, so users see
 * random 502s on every release.
 */

import { loadEnv } from './env.js';
import { buildApp } from './app.js';

const env = loadEnv();

// The libuv threadpool runs native Argon2. The default of 4 caps concurrent
// logins at 4 regardless of HASH_MAX_CONCURRENCY, and it is shared with DNS and
// fs. Setting it here has no effect once the pool is created, so it must come
// from the environment — hence the check rather than an assignment.
const uvThreads = Number(process.env['UV_THREADPOOL_SIZE'] ?? 4);

async function main(): Promise<void> {
  const app = await buildApp(env);

  app.log.info(
    {
      nodeEnv: env.NODE_ENV,
      uvThreadpoolSize: uvThreads,
      hashConcurrency: env.HASH_MAX_CONCURRENCY,
      dbPoolMax: env.DB_POOL_MAX,
      docs: env.SWAGGER_ENABLED ? env.SWAGGER_ROUTE_PREFIX : 'disabled',
    },
    'starting api',
  );

  try {
    await app.listen({ host: env.HOST, port: env.PORT });
  } catch (error) {
    app.log.fatal({ err: error }, 'failed to bind');
    process.exit(1);
  }

  // ── Shutdown ─────────────────────────────────────────────────────────────
  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return; // a second SIGTERM must not race the first
    shuttingDown = true;
    app.log.info({ signal }, 'shutting down');

    // Hard deadline: if in-flight work will not finish, exiting non-zero is
    // better than an orchestrator SIGKILL that skips every onClose hook.
    const killer = setTimeout(() => {
      app.log.error({ timeoutMs: env.SHUTDOWN_TIMEOUT_MS }, 'shutdown timed out — forcing exit');
      process.exit(1);
    }, env.SHUTDOWN_TIMEOUT_MS);
    killer.unref();

    try {
      // close() drains connections, then runs onClose hooks (db, redis, smtp).
      await app.close();
      clearTimeout(killer);
      app.log.info('shutdown complete');
      process.exit(0);
    } catch (error) {
      app.log.error({ err: error }, 'error during shutdown');
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));

  // An unhandled rejection leaves the process in an unknown state. Log it with
  // full context, then exit and let the orchestrator restart a clean one.
  process.on('unhandledRejection', (reason) => {
    app.log.fatal({ err: reason }, 'unhandled rejection');
    void shutdown('unhandledRejection');
  });
  process.on('uncaughtException', (error) => {
    app.log.fatal({ err: error }, 'uncaught exception');
    void shutdown('uncaughtException');
  });
}

void main();
