-- Runs once, on first cluster init only (empty data dir).
-- Extensions the auth schema depends on — see AUTH-MODULE-PLAN.md §4.

-- citext: case-insensitive email/slug columns without LOWER() on every lookup,
-- so UNIQUE(email) genuinely means "one account per address".
CREATE EXTENSION IF NOT EXISTS citext;

-- pgcrypto: gen_random_bytes / digest for DB-side hashing where needed.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- pg_stat_statements: the only honest way to find your slow queries.
-- Requires shared_preload_libraries=pg_stat_statements (set in docker-compose).
--   SELECT calls, mean_exec_time, query FROM pg_stat_statements
--   ORDER BY mean_exec_time DESC LIMIT 20;
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- UUIDv7 note: Postgres 18 ships uuidv7(). On 17 we generate ids in the
-- application (packages/crypto) so they stay time-sortable either way.

-- Sane per-database defaults. Statement timeout is also set per-connection by
-- the pool, but a server-side default protects psql/adminer sessions too.
ALTER DATABASE billing SET statement_timeout = '30s';
ALTER DATABASE billing SET idle_in_transaction_session_timeout = '60s';
ALTER DATABASE billing SET lock_timeout = '10s';
ALTER DATABASE billing SET timezone = 'UTC';
