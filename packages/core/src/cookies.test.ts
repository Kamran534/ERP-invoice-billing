/**
 * Cookie name prefixes (AUTH-MODULE-PLAN.md §5.5.6, §8.3).
 *
 * ⚑ These assert a *browser* rule, not ours. A cookie whose name claims a
 * guarantee its attributes do not provide is rejected outright and silently — so
 * getting this wrong looks exactly like "login works but nothing is logged in",
 * which is what shipped until someone tried it in a real browser.
 */

import { describe, it, expect } from 'vitest';
import { defineAuthConfig, type AuthConfigInput } from './config.js';

const config = (cookies: AuthConfigInput['cookies'] = {}) =>
  defineAuthConfig({
    appName: 'Acme',
    urls: { appOrigin: 'https://app.acme.test' },
    tokens: { issuer: 'https://auth.acme.test', audience: ['api.acme.test'] },
    email: { fromAddress: 'no-reply@acme.test' },
    cookies,
  }).cookies;

describe('over HTTPS, first-party', () => {
  it('uses __Host- for the cookies that can back it', () => {
    const { names } = config({ secure: true });
    // Path=/, Secure, no Domain — every __Host- condition met.
    expect(names.access).toBe('__Host-at');
    expect(names.trustedDevice).toBe('__Host-td');
  });

  it('⚑ never uses __Host- for the refresh cookie', () => {
    const cookies = config({ secure: true });
    // It is scoped to /auth/token so the long-lived credential stays off ordinary
    // API calls — and `__Host-` requires Path=/. The two cannot both be true, and
    // the path scoping is worth more.
    expect(cookies.refreshPath).toBe('/auth/token');
    expect(cookies.names.refresh).toBe('__Secure-rt');
    expect(cookies.names.refresh).not.toMatch(/^__Host-/);
  });

  it('leaves the CSRF cookie unprefixed', () => {
    // It is readable by JavaScript on purpose; a prefix would imply hardening it
    // does not have.
    expect(config({ secure: true }).names.csrf).toBe('csrf');
  });
});

describe('with a Domain set', () => {
  it('drops to __Secure-, because __Host- forbids Domain', () => {
    const { names } = config({ secure: true, domain: 'acme.test' });
    expect(names.access).toBe('__Secure-at');
    expect(names.trustedDevice).toBe('__Secure-td');
  });
});

describe('over plain HTTP', () => {
  it('⚑ strips every prefix, because none of them can be honoured', () => {
    const { names } = config({ secure: false });
    // This is the case that broke: `__Host-at` without `Secure` is discarded by
    // the browser, so the session existed server-side and nowhere else.
    expect(names.access).toBe('at');
    expect(names.refresh).toBe('rt');
    expect(names.trustedDevice).toBe('td');
    expect(Object.values(names).some((n) => n.startsWith('__'))).toBe(false);
  });
});

describe('explicitly configured names', () => {
  it('keeps the name but corrects the prefix', () => {
    const secure = config({ secure: true, names: { access: 'session' } });
    expect(secure.names.access).toBe('__Host-session');

    const insecure = config({ secure: false, names: { access: '__Host-session' } });
    // A deployment that hardcoded the prefix and then turned Secure off would
    // otherwise ship a cookie no browser accepts.
    expect(insecure.names.access).toBe('session');
  });
});
