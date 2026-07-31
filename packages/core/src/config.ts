/**
 * The module's entire configuration surface (AUTH-MODULE-PLAN.md §7).
 *
 * Validated once at boot; the process refuses to start on a bad value. Every
 * weakening of the defaults is an explicit field with a comment saying what it
 * costs you — there are no hidden switches.
 *
 * Durations accept '10m' | '90d' | milliseconds and are normalized to ms.
 */

import { z } from 'zod';
import { parseDuration } from './duration.js';

/**
 * Version-agnostic defaulted duration. `.optional().transform()` behaves the
 * same on zod 3 and 4, unlike `.default()` on a transformed schema.
 */
const dur = (fallback: string) =>
  z
    .union([z.string(), z.number()])
    .optional()
    .transform((v) => parseDuration(v ?? fallback));

export const tokensConfigSchema = z.object({
  issuer: z.string().url(),
  audience: z.array(z.string().min(1)).min(1),
  alg: z.enum(['EdDSA', 'ES256', 'RS256']).default('EdDSA'),
  accessTtl: dur('10m'),
  mfaChallengeTtl: dur('5m'),
  stepUpMaxAge: dur('15m'),
  refresh: z
    .object({
      idleTtl: dur('30d'),
      absoluteTtl: dur('90d'),
      /** ⚑ Never false in production — rotation is what makes theft detectable (§5.5.4). */
      rotate: z.boolean().default(true),
      /**
       * ⚑ Grace window for re-presenting the *immediate predecessor* (§5.5.5).
       * Anything above 0 widens the theft window. Ships at 0.
       */
      reuseGraceMs: z.number().int().min(0).max(10_000).default(0),
      /**
       * ⚑ How recently a token must have been claimed for a *second presentation of
       * that same token* to read as one client racing itself rather than as theft
       * (§5.5.5).
       *
       * This cannot be zero. Ten tabs refreshing at once do not arrive in lockstep:
       * some read the row before the winner's write and are detectably a race, but
       * the ones that arrive a few milliseconds later read a row that is simply
       * used — identical, at the database, to a replay. The only thing separating
       * them is how recently the winner claimed it.
       *
       * Forgiving them costs little: a `409` hands the caller no tokens either way,
       * so an attacker inside the window gains nothing but a retry, and every
       * attempt outside it still trips detection. Refusing to forgive them costs a
       * lot: real users get signed out for opening a second tab.
       */
      inFlightWindowMs: z.number().int().min(0).max(30_000).default(2_000),
      /** Nuclear option on theft: kill every session, not just the compromised one. */
      reuseRevokesAllSessions: z.boolean().default(false),
      concurrentRetry: z
        .object({
          attempts: z.number().int().min(0).max(3).default(1),
          backoffMs: z.number().int().min(0).max(2_000).default(200),
        })
        .prefault({}),
    })
    .prefault({}),
  /** 'cache' = O(1) Redis check per request for instant revocation (§5.5.9). */
  revocationCheck: z.enum(['none', 'cache']).default('none'),
});

export const passwordConfigSchema = z.object({
  // NIST 800-63B: length over composition rules, and no forced expiry.
  minLength: z.number().int().min(8).max(64).default(12),
  maxLength: z.number().int().min(64).max(1024).default(200),
  /** HIBP k-anonymity range check (§5.1 step 2). */
  checkBreached: z.boolean().default(true),
  historyDepth: z.number().int().min(0).max(24).default(5),
  argon2: z
    .object({
      memoryCost: z.number().int().min(8_192).default(19_456), // KiB
      timeCost: z.number().int().min(1).default(2),
      parallelism: z.number().int().min(1).default(1),
    })
    .prefault({}),
  /**
   * ⚑ memoryCost × maxConcurrency = worst-case hashing RAM. Unbounded login
   * concurrency against a memory-hard KDF is a self-inflicted OOM.
   */
  maxConcurrency: z.number().int().min(1).max(64).default(8),
  queueTimeoutMs: z.number().int().min(100).default(2_000),
});

export const mfaConfigSchema = z.object({
  enabled: z.boolean().default(true),
  methods: z
    .array(z.enum(['totp', 'webauthn', 'email_otp', 'sms_otp']))
    .default(['totp', 'webauthn', 'email_otp']),
  /** 'admins' = required for privileged roles only (§5.4.6). */
  enforce: z.enum(['optional', 'admins', 'all']).default('admins'),
  /** Quarantine-with-countdown instead of a hard lockout. */
  gracePeriod: dur('7d'),
  recoveryCodeCount: z.number().int().min(5).max(20).default(10),
  maxAttemptsPerChallenge: z.number().int().min(3).max(10).default(5),
  totp: z
    .object({
      digits: z.union([z.literal(6), z.literal(8)]).default(6),
      period: z.number().int().min(15).max(60).default(30),
      /** ±N timesteps for clock drift. 1 = ±30s. Consumed steps are tracked (§5.4.3). */
      window: z.number().int().min(0).max(2).default(1),
    })
    .prefault({}),
  /** ⚑ Off by default — see plan §5.4.5 for why this is the riskiest toggle here. */
  trustedDevices: z
    .object({
      enabled: z.boolean().default(false),
      ttl: dur('30d'),
      max: z.number().int().min(1).max(50).default(10),
    })
    .prefault({}),
});

export const otpConfigSchema = z.object({
  enabled: z.boolean().default(true),
  channels: z.array(z.enum(['email', 'sms'])).default(['email']),
  codeLength: z.number().int().min(4).max(10).default(6),
  ttl: dur('10m'),
  /** Load-bearing: 6 digits is ~20 bits, safe only because of this cap. */
  maxAttempts: z.number().int().min(3).max(10).default(5),
  resendAfter: dur('60s'),
  maxResends: z.number().int().min(0).max(10).default(3),
  /** ⚑ Binds the code to the requesting UA + /24 — kills the "read me your code" scam. */
  bindToClient: z.boolean().default(true),
  singleActiveChallenge: z.boolean().default(true),
  /** ⚑ true means anyone who can receive mail can create an account. */
  allowSignup: z.boolean().default(false),
  /** Privileged roles keep password + 2FA; a mailbox must not be enough (§5.11.3). */
  excludeRoles: z.array(z.string()).default(['owner', 'admin']),
});

export const lockoutConfigSchema = z.object({
  maxFailures: z.number().int().min(3).max(100).default(10),
  lockFor: dur('15m'),
  resetWindow: dur('15m'),
});

export const cookieConfigSchema = z
  .object({
    /** 'cookie' for first-party web, 'bearer' for native/cross-origin (§5.5.6). */
    mode: z.enum(['cookie', 'bearer', 'both']).default('cookie'),
    domain: z.string().optional(),
    sameSite: z.enum(['strict', 'lax', 'none']).default('lax'),
    secure: z.boolean().default(true),
    names: z
      .object({
        access: z.string().default('at'),
        refresh: z.string().default('rt'),
        csrf: z.string().default('csrf'),
        trustedDevice: z.string().default('td'),
      })
      .prefault({}),
    /** Scoping the refresh cookie means it is never sent to ordinary API routes. */
    refreshPath: z.string().default('/auth/token'),
  })
  .transform(applyCookiePrefixes);

/**
 * ⚑ Cookie name prefixes are not decoration — a browser **rejects** a cookie whose
 * name claims a guarantee its attributes do not provide, and says nothing.
 *
 *   `__Host-`   requires Secure **and** `Path=/` **and** no `Domain`
 *   `__Secure-` requires Secure
 *
 * This is applied here rather than left to the deployment because getting it wrong
 * does not fail loudly. It shipped wrong: `__Host-at` was sent without `Secure`
 * over plain HTTP, and `__Host-rt` was sent with `Path=/auth/token`, so every
 * browser silently discarded both. Login returned `200`, set two cookies, stored
 * none of them, and the next request was an anonymous `TOKEN_INVALID`.
 *
 * So the prefix is *derived* from what the attributes can actually back:
 *
 *  - **access**, **trusted device** — `Path=/`, so `__Host-` when secure and no
 *    domain is set; `__Secure-` when a domain rules `__Host-` out; bare otherwise.
 *  - **refresh** — deliberately scoped to `refreshPath`, which permanently
 *    disqualifies `__Host-`. `__Secure-` when secure, bare otherwise. Path scoping
 *    keeps the long-lived credential off every ordinary API call, which is worth
 *    more day to day than the subdomain-shadowing protection `__Host-` adds.
 *  - **csrf** — never prefixed. It is deliberately readable by JavaScript, and a
 *    prefix would imply a hardening it does not have.
 */
function applyCookiePrefixes<T extends {
  secure: boolean;
  domain?: string | undefined;
  names: { access: string; refresh: string; csrf: string; trustedDevice: string };
}>(config: T): T {
  const strip = (name: string) => name.replace(/^(__Host-|__Secure-)/, '');
  const hostPrefix = config.secure && !config.domain ? '__Host-' : config.secure ? '__Secure-' : '';
  const securePrefix = config.secure ? '__Secure-' : '';

  return {
    ...config,
    names: {
      access: `${hostPrefix}${strip(config.names.access)}`,
      refresh: `${securePrefix}${strip(config.names.refresh)}`,
      csrf: strip(config.names.csrf),
      trustedDevice: `${hostPrefix}${strip(config.names.trustedDevice)}`,
    },
  };
}

export const authConfigSchema = z.object({
  appName: z.string().min(1),
  urls: z.object({
    /** ⚑ Every emailed link is built from this — never from the Host header (§5.7). */
    appOrigin: z.string().url(),
    verifyPath: z.string().default('/verify'),
    resetPath: z.string().default('/reset-password'),
    invitePath: z.string().default('/invite'),
    magicLinkPath: z.string().default('/magic'),
    /** Exact-match allowlist. Reflecting an arbitrary redirect leaks tokens (§5.10). */
    postLoginRedirectAllowlist: z.array(z.string()).default(['/']),
  }),
  tenancy: z.enum(['none', 'orgs']).default('orgs'),
  loginMethods: z
    .array(z.enum(['password', 'otp', 'magic_link', 'oauth', 'passkey']))
    .default(['password', 'otp']),
  tokens: tokensConfigSchema,
  // ⚑ `.prefault({})`, not `.default({})`. In zod 4 `.default()` short-circuits
  // parsing and returns the literal you gave it, so `.default({})` would hand
  // back an empty object and silently discard every nested default — including
  // `cookies.secure: true`. `.prefault()` feeds `{}` through the schema so the
  // inner defaults actually apply.
  cookies: cookieConfigSchema.prefault({}),
  password: passwordConfigSchema.prefault({}),
  lockout: lockoutConfigSchema.prefault({}),
  mfa: mfaConfigSchema.prefault({}),
  otp: otpConfigSchema.prefault({}),
  email: z
    .object({
      requireVerification: z.boolean().default(true),
      allowUnverifiedLogin: z.boolean().default(false),
      fromAddress: z.string().min(3),
    })
    .prefault({ fromAddress: 'no-reply@localhost' }),
  audit: z
    .object({
      retention: dur('400d'),
      includeIp: z.boolean().default(true),
      ipPrecision: z.enum(['full', 'masked']).default('full'),
    })
    .prefault({}),
  impersonation: z
    .object({
      enabled: z.boolean().default(false),
      maxTtl: dur('30m'),
      requiredPermission: z.string().default('support:impersonate'),
    })
    .prefault({}),
});

export type AuthConfig = z.output<typeof authConfigSchema>;
export type AuthConfigInput = z.input<typeof authConfigSchema>;

/** Throws a readable aggregate error listing every bad field at once. */
export function defineAuthConfig(input: AuthConfigInput): AuthConfig {
  const result = authConfigSchema.safeParse(input);
  if (!result.success) {
    const lines = result.error.issues.map(
      (i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`,
    );
    throw new Error(`Invalid auth config:\n${lines.join('\n')}`);
  }
  return result.data;
}

/**
 * Production guardrails that a schema can't express. Call at boot when
 * NODE_ENV === 'production'; returns human-readable violations.
 */
export function auditProductionConfig(config: AuthConfig): string[] {
  const problems: string[] = [];
  if (!config.tokens.refresh.rotate) {
    problems.push('tokens.refresh.rotate is false — refresh-token theft becomes undetectable (§5.5.4)');
  }
  if (config.tokens.refresh.inFlightWindowMs === 0) {
    problems.push(
      'tokens.refresh.inFlightWindowMs is 0 — every multi-tab refresh race will be reported as token theft and sign the user out (§5.5.5)',
    );
  }
  if (config.tokens.refresh.inFlightWindowMs > 5_000) {
    problems.push(
      `tokens.refresh.inFlightWindowMs is ${config.tokens.refresh.inFlightWindowMs}ms — far longer than a request takes, so replays are forgiven for no benefit (§5.5.5)`,
    );
  }
  if (config.tokens.refresh.reuseGraceMs > 0) {
    problems.push(
      `tokens.refresh.reuseGraceMs is ${config.tokens.refresh.reuseGraceMs}ms — widens the theft window (§5.5.5)`,
    );
  }
  if (!config.cookies.secure) {
    problems.push('cookies.secure is false — tokens will traverse plaintext HTTP');
  }
  if (config.cookies.sameSite === 'none' && config.cookies.mode !== 'bearer') {
    problems.push('cookies.sameSite=none removes the CSRF baseline (§8.3)');
  }
  if (!config.password.checkBreached) {
    problems.push('password.checkBreached is false — known-breached passwords will be accepted');
  }
  if (!config.urls.appOrigin.startsWith('https://')) {
    problems.push('urls.appOrigin is not https — emailed links would be downgradeable');
  }
  if (config.otp.allowSignup && config.otp.excludeRoles.length === 0) {
    problems.push('otp.allowSignup with no excludeRoles — a mailbox alone could reach a privileged account (§5.11.3)');
  }
  if (!config.otp.bindToClient) {
    problems.push('otp.bindToClient is false — the "read me your code" attack works (§5.11.2)');
  }
  if (config.mfa.trustedDevices.enabled && config.mfa.enforce === 'all') {
    problems.push(
      'mfa.trustedDevices with enforce=all — decide deliberately whether trust may satisfy a mandatory factor (§5.4.5)',
    );
  }
  return problems;
}
