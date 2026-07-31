/**
 * Environment validation. The process refuses to start on a bad value rather
 * than discovering it at 3am on the first request that needs it.
 *
 * Anything security-relevant has NO permissive default: AUTH_KEK and APP_ORIGIN
 * must be supplied. Defaults exist only where a wrong guess is harmless.
 */

import { z } from 'zod';

const bool = z
  .union([z.boolean(), z.enum(['true', 'false', '1', '0'])])
  .transform((v) => v === true || v === 'true' || v === '1');

const int = (fallback: number) =>
  z
    .union([z.number(), z.string()])
    .optional()
    .transform((v) => (v === undefined || v === '' ? fallback : Number(v)))
    .pipe(z.number().int().nonnegative());

const csv = (fallback: string[]) =>
  z
    .string()
    .optional()
    .transform((v) =>
      v === undefined || v.trim() === '' ? fallback : v.split(',').map((s) => s.trim()).filter(Boolean),
    );

export const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  HOST: z.string().default('0.0.0.0'),
  PORT: int(3000),
  LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'silent']).default('info'),
  LOG_PRETTY: bool.default(false),

  APP_NAME: z.string().min(1).default('Invoice & Billing'),
  APP_ORIGIN: z.string().url(),

  // ── Postgres ──────────────────────────────────────────────────────────────
  DATABASE_URL: z.string().min(1),
  DB_POOL_MAX: int(10),
  DB_IDLE_TIMEOUT_MS: int(10_000),
  DB_CONNECT_TIMEOUT_MS: int(5_000),
  DB_STATEMENT_TIMEOUT_MS: int(15_000),
  DB_QUERY_LOG_THRESHOLD_MS: int(200),

  // ── Redis ─────────────────────────────────────────────────────────────────
  REDIS_URL: z.string().min(1),
  REDIS_KEY_PREFIX: z.string().default('billing:'),
  // A rate-limit check that hangs is worse than one that errors, so commands are
  // given a hard deadline. Configurable because the right value depends on
  // network distance to Redis — and because a loaded CI box needs more slack than
  // production.
  REDIS_COMMAND_TIMEOUT_MS: int(1_000),

  // ── Mail ──────────────────────────────────────────────────────────────────
  SMTP_HOST: z.string().default('localhost'),
  SMTP_PORT: int(1025),
  SMTP_SECURE: bool.default(false),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  MAIL_FROM: z.string().default('Invoice & Billing <no-reply@localhost>'),
  MAILPIT_API_URL: z.string().optional(),

  // ── Auth ──────────────────────────────────────────────────────────────────
  // 32 bytes, base64. Encrypts TOTP secrets and signing keys at rest.
  AUTH_KEK: z
    .string()
    .min(4)
    .refine((v) => !v.startsWith('REPLACE_ME'), 'AUTH_KEK still holds the placeholder value')
    .refine((v) => {
      try {
        return Buffer.from(v, 'base64').length === 32;
      } catch {
        return false;
      }
    }, 'AUTH_KEK must be exactly 32 bytes of base64'),
  JWT_ISSUER: z.string().url(),
  JWT_AUDIENCE: csv(['billing-api']),
  ACCESS_TOKEN_TTL_S: int(600),
  REFRESH_IDLE_TTL_S: int(2_592_000),
  REFRESH_ABSOLUTE_TTL_S: int(7_776_000),

  /**
   * Where the tokens live (plan §5.5.6).
   *
   *  - `cookie` — httpOnly cookies, nothing in the response body. Right for a
   *    first-party web app: XSS cannot read the tokens.
   *  - `bearer` — tokens in the body, client stores them. For native apps and
   *    cross-origin SPAs that have no usable cookie jar.
   *  - `both`   — sets the cookies *and* returns the tokens. Convenient for
   *    poking at the API from Swagger UI or curl; ⚑ in production it puts the
   *    refresh token everywhere a response body goes, so prefer one or the other.
   */
  COOKIE_MODE: z.enum(['cookie', 'bearer', 'both']).default('cookie'),

  MFA_ENABLED: bool.default(true),
  /** 'admins' falls back to the per-user marker until RBAC lands (plan §10). */
  MFA_ENFORCE: z.enum(['optional', 'admins', 'all']).default('admins'),
  /**
   * ⚑ The riskiest toggle in the module (plan §5.4.5). A remembered device skips
   * the second factor for 30 days; off unless a deployment decides otherwise.
   */
  MFA_TRUSTED_DEVICES: bool.default(false),

  /**
   * ⚑ Off means known-breached passwords are accepted. It exists because an
   * air-gapped deployment cannot reach api.pwnedpasswords.com and would otherwise
   * pay the timeout on every signup — not because it is a reasonable default.
   */
  PASSWORD_BREACH_CHECK: bool.default(true),
  PASSWORD_BREACH_TIMEOUT_MS: int(1_500),

  ARGON2_MEMORY_KIB: int(19_456),
  ARGON2_TIME_COST: int(2),
  ARGON2_PARALLELISM: int(1),
  HASH_MAX_CONCURRENCY: int(8),
  HASH_QUEUE_TIMEOUT_MS: int(2_000),

  // ── HTTP ──────────────────────────────────────────────────────────────────
  /**
   * Are clients reaching this API over HTTPS — directly, or through a
   * TLS-terminating proxy? Drives HSTS, `upgrade-insecure-requests`,
   * Cross-Origin-Opener-Policy and the `Secure` cookie flag, which must never
   * disagree with each other.
   *
   * ⚑ Leaving this on over plain HTTP breaks the site for anyone not on
   * `localhost`: `upgrade-insecure-requests` rewrites every subresource to
   * https://, and a LAN address has no TLS listener. localhost is exempt because
   * it counts as a trustworthy origin, which is exactly why the breakage only
   * shows up once someone opens the app from another machine.
   *
   * Defaults to true in production, false otherwise.
   */
  HTTPS_ENABLED: bool.optional(),
  TRUST_PROXY: bool.default(false),
  CORS_ORIGINS: csv([]),
  BODY_LIMIT_BYTES: int(65_536),
  REQUEST_TIMEOUT_MS: int(10_000),
  SHUTDOWN_TIMEOUT_MS: int(15_000),

  // ── Docs ──────────────────────────────────────────────────────────────────
  SWAGGER_ENABLED: bool.default(true),
  SWAGGER_ROUTE_PREFIX: z.string().default('/docs'),

  // ── Observability ─────────────────────────────────────────────────────────
  METRICS_ENABLED: bool.default(true),
  METRICS_ROUTE: z.string().default('/metrics'),
  MAX_EVENT_LOOP_DELAY_MS: int(200),
  MAX_HEAP_USED_BYTES: int(734_003_200),
  MAX_RSS_BYTES: int(943_718_400),
})
  // Resolved after parsing because the default depends on another field.
  .transform((env) => ({
    ...env,
    HTTPS_ENABLED: env.HTTPS_ENABLED ?? env.NODE_ENV === 'production',
  }));

export type Env = z.output<typeof envSchema>;

export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const result = envSchema.safeParse(source);
  if (!result.success) {
    const lines = result.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`);
    // Deliberately not the logger: the logger is configured *from* this.
    console.error(`\nInvalid environment:\n${lines.join('\n')}\n`);
    console.error('Copy .env.example to .env and fill in the blanks.\n');
    process.exit(1);
  }

  const env = result.data;

  // Cross-field checks a per-field schema can't see.
  const warnings: string[] = [];
  const uvThreads = Number(source['UV_THREADPOOL_SIZE'] ?? 4);
  if (uvThreads < env.HASH_MAX_CONCURRENCY) {
    warnings.push(
      `UV_THREADPOOL_SIZE=${uvThreads} < HASH_MAX_CONCURRENCY=${env.HASH_MAX_CONCURRENCY}: ` +
        `argon2 will queue behind libuv's shared pool (DNS, fs) instead of running concurrently.`,
    );
  }
  if (env.REFRESH_IDLE_TTL_S > env.REFRESH_ABSOLUTE_TTL_S) {
    console.error('REFRESH_IDLE_TTL_S must not exceed REFRESH_ABSOLUTE_TTL_S');
    process.exit(1);
  }
  if (env.NODE_ENV === 'production') {
    const fatal: string[] = [];
    if (env.SWAGGER_ENABLED) {
      warnings.push('SWAGGER_ENABLED=true in production — the docs UI is publicly reachable.');
    }
    if (!env.APP_ORIGIN.startsWith('https://')) {
      fatal.push('APP_ORIGIN must be https in production — emailed links would be downgradeable.');
    }
    if (env.CORS_ORIGINS.length === 0) {
      warnings.push('CORS_ORIGINS is empty — no browser origin will be able to call this API.');
    }
    if (fatal.length > 0) {
      console.error(`\nProduction config errors:\n${fatal.map((f) => `  - ${f}`).join('\n')}\n`);
      process.exit(1);
    }
  }
  for (const w of warnings) console.warn(`[env] warning: ${w}`);

  return env;
}
