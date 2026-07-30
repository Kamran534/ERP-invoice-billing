/**
 * Postgres pool + Drizzle client.
 *
 * Sizing (the thing that actually decides whether you scale):
 *   total_connections = replicas × DB_POOL_MAX  ≪  postgres max_connections
 * Postgres allocates ~5–10 MiB per backend and context-switches between them, so
 * pushing connections past roughly (2 × cores + spindles) makes throughput
 * *worse*, not better. A small pool with queueing beats a large pool that
 * thrashes. Past ~10 replicas, put pgBouncer in transaction mode in front and
 * drop DB_POOL_MAX to 2–3 (see README "Scaling").
 *
 * Timeouts are set on the connection itself, not only in application code, so a
 * hung query can never hold a pool slot forever.
 */

import pg from 'pg';
import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import { sql } from 'drizzle-orm';
import { schema } from './schema.js';

const { Pool } = pg;

export interface DbOptions {
  connectionString: string;
  /** Per-process pool ceiling. See the sizing note above. */
  max?: number;
  idleTimeoutMs?: number;
  connectTimeoutMs?: number;
  /** Server-side kill switch: Postgres cancels a query that runs longer. */
  statementTimeoutMs?: number;
  applicationName?: string;
  /** Report any query slower than this. 0 disables the wrapper entirely. */
  slowQueryMs?: number;
  onSlowQuery?: (info: { durationMs: number; text: string }) => void;
}

export type Database = NodePgDatabase<typeof schema>;

export interface DbHandle {
  db: Database;
  pool: pg.Pool;
  /** Cheap liveness probe for /health/ready. */
  ping(): Promise<boolean>;
  /** `waiting > 0` sustained means the pool is the bottleneck, not Postgres. */
  stats(): { total: number; idle: number; waiting: number };
  close(): Promise<void>;
}

type PoolQuery = pg.Pool['query'];

export function createDb(opts: DbOptions): DbHandle {
  const pool = new Pool({
    connectionString: opts.connectionString,
    max: opts.max ?? 10,
    idleTimeoutMillis: opts.idleTimeoutMs ?? 10_000,
    connectionTimeoutMillis: opts.connectTimeoutMs ?? 5_000,
    // Recycle connections periodically: bounds the blast radius of a slow leak
    // and lets a rolling Postgres upgrade drain cleanly.
    maxUses: 7_500,
    keepAlive: true,
    application_name: opts.applicationName ?? 'billing-api',
    statement_timeout: opts.statementTimeoutMs ?? 15_000,
    // An abandoned open transaction holds locks and blocks vacuum. Fail it.
    idle_in_transaction_session_timeout: 30_000,
  });

  // An 'error' on an *idle* client is routine (network blip, server restart).
  // Unhandled, it terminates the process — so absorb it and let the pool heal.
  pool.on('error', (err) => {
    process.emitWarning(`pg pool idle client error: ${err.message}`, 'DbPoolWarning');
  });

  // Slow-query surfacing. pg_stat_statements (enabled in docker-compose) tells
  // you *which* statements are slow across the cluster; this tells you which
  // request produced one, which is what you need to fix it.
  const slowQueryMs = opts.slowQueryMs ?? 0;
  const report = opts.onSlowQuery;
  if (slowQueryMs > 0 && report) {
    const original = pool.query.bind(pool) as PoolQuery;
    const wrapped = async (...args: unknown[]): Promise<unknown> => {
      const startedAt = performance.now();
      try {
        return await (original as (...a: unknown[]) => Promise<unknown>)(...args);
      } finally {
        const durationMs = performance.now() - startedAt;
        if (durationMs >= slowQueryMs) {
          const first = args[0];
          const text =
            typeof first === 'string'
              ? first
              : ((first as { text?: string } | undefined)?.text ?? '<unknown>');
          report({ durationMs, text });
        }
      }
    };
    pool.query = wrapped as unknown as PoolQuery;
  }

  const db = drizzle(pool, { schema, casing: 'snake_case' });

  return {
    db,
    pool,
    async ping() {
      try {
        await db.execute(sql`select 1`);
        return true;
      } catch {
        return false;
      }
    },
    stats() {
      return { total: pool.totalCount, idle: pool.idleCount, waiting: pool.waitingCount };
    },
    async close() {
      await pool.end();
    },
  };
}
