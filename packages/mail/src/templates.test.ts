/**
 * Template tests (AUTH-MODULE-PLAN.md §12).
 *
 * These assert the *rules* the templates exist to enforce, not their wording.
 * The subject-line rule in particular is a real leak: subjects render in
 * lock-screen previews and notification banners, so a code there is a code anyone
 * standing nearby can read.
 */

import { describe, it, expect } from 'vitest';
import {
  renderOtpCode,
  renderVerifyEmail,
  renderPasswordReset,
  renderPasswordChanged,
  renderSuspiciousActivity,
} from './templates.js';

const base = { appName: 'Acme Billing', to: 'ada@example.com' };

describe('every template', () => {
  const all = [
    renderOtpCode({ ...base, code: '481920', ttlMinutes: 10, purpose: 'login' }),
    renderOtpCode({ ...base, code: '481920', ttlMinutes: 5, purpose: 'mfa' }),
    renderVerifyEmail({ ...base, verifyUrl: 'https://app.acme.com/verify?t=abc', ttlHours: 24 }),
    renderPasswordReset({ ...base, resetUrl: 'https://app.acme.com/reset?t=abc', ttlMinutes: 60 }),
    renderPasswordChanged({ ...base, when: new Date('2026-07-30T12:00:00Z') }),
    renderSuspiciousActivity({ ...base, when: new Date('2026-07-30T12:00:00Z') }),
  ];

  it('produces both HTML and plaintext', () => {
    for (const mail of all) {
      // Plaintext is what mail gateways and screen readers actually use.
      expect(mail.text.length, mail.subject).toBeGreaterThan(20);
      expect(mail.html).toContain('<!doctype html>');
      expect(mail.to).toBe('ada@example.com');
    }
  });

  it('names the app in the subject so it is recognisable in a crowded inbox', () => {
    for (const mail of all) expect(mail.subject).toContain('Acme Billing');
  });

  it('keeps subjects short enough not to be truncated by mail clients', () => {
    for (const mail of all) expect(mail.subject.length).toBeLessThan(78);
  });
});

describe('renderOtpCode', () => {
  it('never puts the code in the subject line', () => {
    const mail = renderOtpCode({ ...base, code: '481920', ttlMinutes: 10, purpose: 'login' });
    // ⚑ The rule this template exists to enforce.
    expect(mail.subject).not.toContain('481920');
    expect(mail.html).toContain('481920');
    expect(mail.text).toContain('481920');
  });

  it('states the expiry and that the code is single-use', () => {
    const mail = renderOtpCode({ ...base, code: '111111', ttlMinutes: 10, purpose: 'login' });
    expect(mail.text).toContain('10 minutes');
    expect(mail.text.toLowerCase()).toContain('single use');
    expect(mail.html).toContain('10 minutes');
  });

  it('warns against reading the code out — the relay attack (§5.11.2)', () => {
    const mail = renderOtpCode({ ...base, code: '111111', ttlMinutes: 10, purpose: 'login' });
    expect(mail.text.toLowerCase()).toContain('never share');
    expect(mail.text.toLowerCase()).toContain('read it out');
  });

  it('tells the recipient what to do if they did not request it', () => {
    const mail = renderOtpCode({ ...base, code: '111111', ttlMinutes: 10, purpose: 'login' });
    expect(mail.text.toLowerCase()).toMatch(/didn't request/);
  });

  it('distinguishes a sign-in code from a verification code', () => {
    const login = renderOtpCode({ ...base, code: '1', ttlMinutes: 10, purpose: 'login' });
    const mfa = renderOtpCode({ ...base, code: '1', ttlMinutes: 10, purpose: 'mfa' });
    expect(login.subject).toContain('sign-in code');
    expect(mfa.subject).toContain('verification code');
  });
});

describe('link templates', () => {
  it('embeds the caller-supplied URL verbatim in both parts', () => {
    const url = 'https://app.acme.com/reset?t=abc123';
    const mail = renderPasswordReset({ ...base, resetUrl: url, ttlMinutes: 60 });
    expect(mail.html).toContain(url);
    expect(mail.text).toContain(url);
  });

  it('states the link TTL', () => {
    expect(renderVerifyEmail({ ...base, verifyUrl: 'https://x.test/v', ttlHours: 24 }).text).toContain(
      '24 hours',
    );
    expect(
      renderPasswordReset({ ...base, resetUrl: 'https://x.test/r', ttlMinutes: 60 }).text,
    ).toContain('60 minutes');
  });

  it('reassures that the current password still works until reset', () => {
    const mail = renderPasswordReset({ ...base, resetUrl: 'https://x.test/r', ttlMinutes: 60 });
    // Without this line, users assume requesting a reset locked them out.
    expect(mail.html.toLowerCase()).toContain('current password stays valid');
  });
});

describe('notification templates', () => {
  it('password-changed states when, and that other devices were signed out', () => {
    const mail = renderPasswordChanged({ ...base, when: new Date('2026-07-30T12:00:00Z') });
    expect(mail.text).toContain('30 Jul 2026');
    expect(mail.text.toLowerCase()).toContain('signed out');
    // The out-of-band tamper signal: tell them how to react if it wasn't them.
    expect(mail.text.toLowerCase()).toContain('reset your password immediately');
  });

  it('suspicious-activity explains the sign-out without teaching the mechanism', () => {
    const mail = renderSuspiciousActivity({ ...base, when: new Date('2026-07-30T12:00:00Z') });
    expect(mail.text.toLowerCase()).toContain('reused');
    expect(mail.text.toLowerCase()).toContain('precaution');
    // Must not describe the detection internals to whoever is reading the mailbox.
    expect(mail.text.toLowerCase()).not.toContain('refresh token');
    expect(mail.text.toLowerCase()).not.toContain('rotation');
  });
});

describe('HTML escaping', () => {
  it('escapes interpolated values so a hostile app name cannot inject markup', () => {
    const mail = renderOtpCode({
      appName: '<script>alert(1)</script>',
      to: 'ada@example.com',
      code: '111111',
      ttlMinutes: 10,
      purpose: 'login',
    });
    expect(mail.html).not.toContain('<script>');
    expect(mail.html).toContain('&lt;script&gt;');
  });

  it('escapes quotes in URLs so an attribute cannot be broken out of', () => {
    const mail = renderVerifyEmail({
      ...base,
      verifyUrl: 'https://x.test/v?t=a"onmouseover="alert(1)',
      ttlHours: 24,
    });
    expect(mail.html).not.toContain('onmouseover="alert(1)"');
    expect(mail.html).toContain('&quot;');
  });
});
