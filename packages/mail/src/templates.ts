/**
 * Mail templates (AUTH-MODULE-PLAN.md §12).
 *
 * Rules encoded here, not left to the author of the next template:
 *  - ⚑ No secret in the subject line. Subjects render in lock-screen previews and
 *    notification banners; an OTP code there is a code anyone standing nearby can read.
 *  - Every message states the app name, what was requested, how long it is valid,
 *    and what to do if it wasn't you.
 *  - HTML *and* plaintext always. Plaintext is what mail gateways and screen
 *    readers actually use.
 *  - Links are built from a caller-supplied origin (config), never a request header.
 */

import type { RenderedMail } from '@auth/core';

export type TemplateId =
  | 'login-otp-code'
  | 'mfa-otp-code'
  | 'verify-email'
  | 'password-reset'
  | 'password-changed'
  | 'signed-out-suspicious-activity';

interface BaseVars {
  appName: string;
  to: string;
}

const escape = (s: string): string =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function layout(appName: string, heading: string, bodyHtml: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(heading)}</title></head>
<body style="margin:0;padding:24px;background:#f5f6f8;font:16px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1a1a1a">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center">
    <table role="presentation" width="100%" style="max-width:520px;background:#fff;border-radius:12px;padding:32px" cellpadding="0" cellspacing="0">
      <tr><td style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#6b7280;padding-bottom:8px">${escape(appName)}</td></tr>
      <tr><td style="font-size:20px;font-weight:600;padding-bottom:16px">${escape(heading)}</td></tr>
      <tr><td>${bodyHtml}</td></tr>
      <tr><td style="padding-top:24px;border-top:1px solid #e5e7eb;color:#6b7280;font-size:13px">
        You are receiving this because someone entered this address at ${escape(appName)}.
        If that wasn't you, no action is needed — you can safely ignore this message.
      </td></tr>
    </table>
  </td></tr></table>
</body></html>`;
}

const codeBlock = (code: string): string =>
  `<div style="font:600 32px/1.2 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.25em;background:#f3f4f6;border-radius:8px;padding:18px;text-align:center;margin:8px 0 20px">${escape(code)}</div>`;

const button = (href: string, label: string): string =>
  `<a href="${escape(href)}" style="display:inline-block;background:#111827;color:#fff;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:600">${escape(label)}</a>`;

// ── OTP codes ──────────────────────────────────────────────────────────────

export function renderOtpCode(
  vars: BaseVars & { code: string; ttlMinutes: number; purpose: 'login' | 'mfa' },
): RenderedMail {
  const heading = vars.purpose === 'login' ? 'Your sign-in code' : 'Your verification code';
  // ⚑ Subject deliberately carries no code.
  const subject = `${heading} — ${vars.appName}`;
  return {
    to: vars.to,
    subject,
    html: layout(
      vars.appName,
      heading,
      `<p style="margin:0 0 4px">Enter this code to continue:</p>
       ${codeBlock(vars.code)}
       <p style="margin:0;color:#6b7280;font-size:14px">
         It expires in ${vars.ttlMinutes} minutes and can only be used once.
         Never share it with anyone — ${escape(vars.appName)} will never ask you to read it out.
       </p>`,
    ),
    text: [
      `${heading} — ${vars.appName}`,
      '',
      `Code: ${vars.code}`,
      '',
      `Expires in ${vars.ttlMinutes} minutes. Single use.`,
      `Never share this code. ${vars.appName} will never ask you to read it out.`,
      '',
      `If you didn't request it, ignore this message.`,
    ].join('\n'),
  };
}

// ── Email verification ─────────────────────────────────────────────────────

export function renderVerifyEmail(
  vars: BaseVars & { verifyUrl: string; ttlHours: number },
): RenderedMail {
  const heading = 'Confirm your email address';
  return {
    to: vars.to,
    subject: `${heading} — ${vars.appName}`,
    html: layout(
      vars.appName,
      heading,
      `<p style="margin:0 0 20px">Confirm this address to finish setting up your account.</p>
       <p style="margin:0 0 20px">${button(vars.verifyUrl, 'Confirm email')}</p>
       <p style="margin:0;color:#6b7280;font-size:14px">This link expires in ${vars.ttlHours} hours.</p>`,
    ),
    text: [heading, '', vars.verifyUrl, '', `Expires in ${vars.ttlHours} hours.`].join('\n'),
  };
}

// ── Password reset ─────────────────────────────────────────────────────────

export function renderPasswordReset(
  vars: BaseVars & { resetUrl: string; ttlMinutes: number },
): RenderedMail {
  const heading = 'Reset your password';
  return {
    to: vars.to,
    subject: `${heading} — ${vars.appName}`,
    html: layout(
      vars.appName,
      heading,
      `<p style="margin:0 0 20px">Someone asked to reset the password for this account.</p>
       <p style="margin:0 0 20px">${button(vars.resetUrl, 'Choose a new password')}</p>
       <p style="margin:0;color:#6b7280;font-size:14px">
         This link expires in ${vars.ttlMinutes} minutes and can be used once.
         Your current password stays valid until you set a new one.
       </p>`,
    ),
    text: [heading, '', vars.resetUrl, '', `Expires in ${vars.ttlMinutes} minutes. Single use.`].join('\n'),
  };
}

/** Out-of-band tamper signal: sent after every password change (§5.7 step 4). */
export function renderPasswordChanged(vars: BaseVars & { when: Date }): RenderedMail {
  const heading = 'Your password was changed';
  return {
    to: vars.to,
    subject: `${heading} — ${vars.appName}`,
    html: layout(
      vars.appName,
      heading,
      `<p style="margin:0 0 12px">The password for your account was changed on ${vars.when.toUTCString()}.</p>
       <p style="margin:0;color:#6b7280;font-size:14px">
         All other signed-in devices were signed out. If this wasn't you, reset your password
         immediately and contact support.
       </p>`,
    ),
    text: [
      heading,
      '',
      `Changed at ${vars.when.toUTCString()}.`,
      'All other devices were signed out.',
      `If this wasn't you, reset your password immediately and contact support.`,
    ].join('\n'),
  };
}

/** Sent on refresh-token reuse detection (§5.5.4 step 4). */
export function renderSuspiciousActivity(vars: BaseVars & { when: Date }): RenderedMail {
  const heading = 'We signed out a device on your account';
  return {
    to: vars.to,
    subject: `${heading} — ${vars.appName}`,
    html: layout(
      vars.appName,
      heading,
      `<p style="margin:0 0 12px">
         On ${vars.when.toUTCString()} we detected a sign-in credential being reused from more than
         one place, so we signed that session out as a precaution.
       </p>
       <p style="margin:0;color:#6b7280;font-size:14px">
         If you were signed out unexpectedly, sign in again. If you don't recognise this,
         change your password and review your active devices.
       </p>`,
    ),
    text: [
      heading,
      '',
      `At ${vars.when.toUTCString()} a sign-in credential was reused from more than one place.`,
      'That session was signed out as a precaution.',
      `If you don't recognise this, change your password and review your active devices.`,
    ].join('\n'),
  };
}
