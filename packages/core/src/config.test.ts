/**
 * Config tests, and one regression test that matters more than it looks.
 *
 * Zod 4 changed `.default()` on a nested schema to short-circuit parsing and
 * return the literal you passed. So `cookieConfigSchema.default({})` silently
 * yields `{}` — discarding every inner default, including `cookies.secure: true`
 * and `otp.bindToClient: true`. That is a security control quietly evaporating
 * with no error anywhere. `.prefault({})` feeds `{}` through the schema instead.
 *
 * The "applies nested defaults" tests below exist to catch that class of bug.
 */

import { describe, it, expect } from 'vitest';
import { auditProductionConfig, defineAuthConfig, type AuthConfigInput } from './config.js';

const minimal: AuthConfigInput = {
  appName: 'Acme Billing',
  urls: { appOrigin: 'https://app.acme.com' },
  tokens: { issuer: 'https://auth.acme.com', audience: ['api.acme.com'] },
};

describe('defineAuthConfig', () => {
  it('accepts a minimal config', () => {
    expect(() => defineAuthConfig(minimal)).not.toThrow();
  });

  it('applies nested defaults instead of returning empty objects', () => {
    // The `.prefault()` regression guard. If these come back undefined, a nested
    // schema has been switched to `.default({})`.
    const config = defineAuthConfig(minimal);

    expect(config.cookies.secure).toBe(true);
    expect(config.cookies.mode).toBe('cookie');
    expect(config.cookies.sameSite).toBe('lax');
    expect(config.cookies.names.access).toBe('__Host-at');
    expect(config.cookies.refreshPath).toBe('/auth/token');

    expect(config.password.minLength).toBe(12);
    expect(config.password.checkBreached).toBe(true);
    expect(config.password.argon2.memoryCost).toBe(19_456);
    expect(config.password.maxConcurrency).toBe(8);

    expect(config.otp.bindToClient).toBe(true);
    expect(config.otp.singleActiveChallenge).toBe(true);
    expect(config.otp.allowSignup).toBe(false);
    expect(config.otp.maxAttempts).toBe(5);
    expect(config.otp.excludeRoles).toEqual(['owner', 'admin']);

    expect(config.mfa.enabled).toBe(true);
    expect(config.mfa.enforce).toBe('admins');
    expect(config.mfa.trustedDevices.enabled).toBe(false);
    expect(config.mfa.totp.window).toBe(1);

    expect(config.lockout.maxFailures).toBe(10);
    expect(config.audit.ipPrecision).toBe('full');
    expect(config.impersonation.enabled).toBe(false);
  });

  it('normalizes every duration to milliseconds', () => {
    const config = defineAuthConfig(minimal);
    expect(config.tokens.accessTtl).toBe(600_000); // 10m
    expect(config.tokens.refresh.idleTtl).toBe(2_592_000_000); // 30d
    expect(config.tokens.refresh.absoluteTtl).toBe(7_776_000_000); // 90d
    expect(config.tokens.stepUpMaxAge).toBe(900_000); // 15m
    expect(config.otp.ttl).toBe(600_000); // 10m
    expect(config.otp.resendAfter).toBe(60_000); // 60s
    expect(config.mfa.gracePeriod).toBe(604_800_000); // 7d
  });

  it('ships rotation on and the reuse grace window at zero', () => {
    const config = defineAuthConfig(minimal);
    // Rotation off makes refresh-token theft undetectable; a non-zero grace
    // window widens it. Both must be safe by default (§5.5.4, §5.5.5).
    expect(config.tokens.refresh.rotate).toBe(true);
    expect(config.tokens.refresh.reuseGraceMs).toBe(0);
    expect(config.tokens.refresh.reuseRevokesAllSessions).toBe(false);
  });

  it('overrides survive alongside siblings that keep their defaults', () => {
    const config = defineAuthConfig({
      ...minimal,
      otp: { codeLength: 8, allowSignup: true },
    });
    expect(config.otp.codeLength).toBe(8);
    expect(config.otp.allowSignup).toBe(true);
    expect(config.otp.bindToClient).toBe(true); // untouched default preserved
    expect(config.otp.maxAttempts).toBe(5);
  });

  it('reports every invalid field at once, with its path', () => {
    let message = '';
    try {
      defineAuthConfig({
        appName: '',
        urls: { appOrigin: 'not-a-url' },
        tokens: { issuer: 'also-not-a-url', audience: [] },
      } as AuthConfigInput);
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain('Invalid auth config');
    expect(message).toContain('urls.appOrigin');
    expect(message).toContain('tokens.issuer');
    expect(message).toContain('tokens.audience');
  });

  it('rejects out-of-range values that would weaken a control', () => {
    // 4-char passwords, a 10-attempt OTP cap, a 60s grace window.
    expect(() => defineAuthConfig({ ...minimal, password: { minLength: 4 } })).toThrow();
    expect(() => defineAuthConfig({ ...minimal, otp: { maxAttempts: 99 } })).toThrow();
    expect(() =>
      defineAuthConfig({
        ...minimal,
        tokens: { ...minimal.tokens, refresh: { reuseGraceMs: 60_000 } },
      }),
    ).toThrow();
  });

  it('rejects an invalid duration string', () => {
    expect(() => defineAuthConfig({ ...minimal, otp: { ttl: '10 minutes' } })).toThrow(
      /Invalid duration|Invalid auth config/,
    );
  });
});

describe('auditProductionConfig', () => {
  it('passes a hardened config', () => {
    expect(auditProductionConfig(defineAuthConfig(minimal))).toEqual([]);
  });

  it('flags disabled refresh rotation', () => {
    const config = defineAuthConfig({
      ...minimal,
      tokens: { ...minimal.tokens, refresh: { rotate: false } },
    });
    expect(auditProductionConfig(config).join('\n')).toMatch(/rotate is false/);
  });

  it('flags a non-zero reuse grace window', () => {
    const config = defineAuthConfig({
      ...minimal,
      tokens: { ...minimal.tokens, refresh: { reuseGraceMs: 5_000 } },
    });
    expect(auditProductionConfig(config).join('\n')).toMatch(/reuseGraceMs/);
  });

  it('flags insecure cookies and a CSRF-less SameSite setting', () => {
    const config = defineAuthConfig({
      ...minimal,
      cookies: { secure: false, sameSite: 'none' },
    });
    const problems = auditProductionConfig(config).join('\n');
    expect(problems).toMatch(/cookies.secure is false/);
    expect(problems).toMatch(/sameSite=none/);
  });

  it('flags a plaintext appOrigin, because every emailed link is built from it', () => {
    const config = defineAuthConfig({ ...minimal, urls: { appOrigin: 'http://app.acme.com' } });
    expect(auditProductionConfig(config).join('\n')).toMatch(/not https/);
  });

  it('flags a disabled breach check', () => {
    const config = defineAuthConfig({ ...minimal, password: { checkBreached: false } });
    expect(auditProductionConfig(config).join('\n')).toMatch(/checkBreached is false/);
  });

  it('flags OTP signup that could reach a privileged account', () => {
    const config = defineAuthConfig({
      ...minimal,
      otp: { allowSignup: true, excludeRoles: [] },
    });
    expect(auditProductionConfig(config).join('\n')).toMatch(/privileged account/);
  });

  it('flags OTP without client binding', () => {
    const config = defineAuthConfig({ ...minimal, otp: { bindToClient: false } });
    expect(auditProductionConfig(config).join('\n')).toMatch(/bindToClient is false/);
  });

  it('flags trusted devices combined with mandatory 2FA as a decision to make', () => {
    const config = defineAuthConfig({
      ...minimal,
      mfa: { enforce: 'all', trustedDevices: { enabled: true } },
    });
    expect(auditProductionConfig(config).join('\n')).toMatch(/trustedDevices/);
  });

  it('accumulates every problem rather than stopping at the first', () => {
    const config = defineAuthConfig({
      ...minimal,
      urls: { appOrigin: 'http://app.acme.com' },
      cookies: { secure: false },
      password: { checkBreached: false },
      otp: { bindToClient: false },
      tokens: { ...minimal.tokens, refresh: { rotate: false } },
    });
    expect(auditProductionConfig(config).length).toBeGreaterThanOrEqual(5);
  });
});
