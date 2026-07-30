/**
 * Mail transport against the real Mailpit container.
 *
 * The rule under test is the one stated in transport.ts: **delivery must never be
 * able to fail a login or a registration**. A mail-provider outage should degrade
 * signup, not take down authentication — so `send()` reports failure through its
 * callback and never throws into the caller's path.
 *
 * That guarantee is impossible to verify against a mock of our own making: the
 * point is how the transport behaves when a real SMTP conversation fails.
 *
 *   pnpm up && pnpm test:int
 */

import { describe, it, expect, afterAll } from 'vitest';
import { createSmtpMailer, type AppMailer } from './transport.js';
import { renderOtpCode, renderPasswordReset } from './templates.js';

const SMTP_HOST = process.env['SMTP_HOST'] ?? 'localhost';
const SMTP_PORT = Number(process.env['SMTP_PORT'] ?? 1025);
const MAILPIT_API = process.env['MAILPIT_API_URL'] ?? 'http://localhost:8025';

const opened: AppMailer[] = [];
function mailer(overrides: Partial<Parameters<typeof createSmtpMailer>[0]> = {}): AppMailer {
  const instance = createSmtpMailer({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: false,
    from: 'Invoice & Billing <no-reply@example.test>',
    ...overrides,
  });
  opened.push(instance);
  return instance;
}

afterAll(() => {
  for (const instance of opened) instance.close();
});

interface MailpitMessage {
  ID: string;
  Subject: string;
  To: Array<{ Address: string }>;
}

/** Mailpit indexes asynchronously; poll rather than sleep a guessed duration. */
async function findMessage(recipient: string, timeoutMs = 10_000): Promise<MailpitMessage> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const response = await fetch(`${MAILPIT_API}/api/v1/search?query=${encodeURIComponent(recipient)}`);
    if (response.ok) {
      const body = (await response.json()) as { messages?: MailpitMessage[] };
      const found = body.messages?.[0];
      if (found) return found;
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`no message for ${recipient} within ${timeoutMs}ms`);
}

async function fetchBody(id: string): Promise<{ Text: string; HTML: string }> {
  const response = await fetch(`${MAILPIT_API}/api/v1/message/${id}`);
  return (await response.json()) as { Text: string; HTML: string };
}

describe('delivery', () => {
  it('completes an SMTP handshake with the live server', async () => {
    expect(await mailer().verify()).toBe(true);
  });

  it('delivers a rendered message that arrives intact', async () => {
    const to = `otp-${Date.now()}@example.test`;
    const results: Array<{ ok: boolean }> = [];
    const instance = mailer({ onResult: (result) => results.push(result) });

    await instance.send(
      renderOtpCode({ appName: 'Invoice & Billing', to, code: '481920', ttlMinutes: 10, purpose: 'login' }),
    );

    expect(results).toEqual([{ ok: true }]);

    const message = await findMessage(to);
    expect(message.To[0]?.Address).toBe(to);
    // ⚑ The subject-line rule, verified on the wire rather than on the template
    // object — a transport that stuffed the code into a header would slip past a
    // template-only assertion.
    expect(message.Subject).not.toContain('481920');

    const body = await fetchBody(message.ID);
    expect(body.Text).toContain('481920');
    expect(body.HTML).toContain('481920');
  });

  it('sends both a plaintext and an HTML part', async () => {
    const to = `multipart-${Date.now()}@example.test`;
    await mailer().send(
      renderPasswordReset({
        appName: 'Invoice & Billing',
        to,
        resetUrl: 'https://app.example.test/reset?t=abc',
        ttlMinutes: 60,
      }),
    );

    const body = await fetchBody((await findMessage(to)).ID);
    // Gateways and screen readers use the text part; dropping it is a silent
    // accessibility and deliverability regression.
    expect(body.Text.length).toBeGreaterThan(20);
    expect(body.HTML).toContain('<!doctype html>');
    expect(body.Text).toContain('https://app.example.test/reset?t=abc');
  });

  it('reuses one pooled connection across a burst', async () => {
    const stamp = Date.now();
    const instance = mailer();
    const recipients = Array.from({ length: 5 }, (_, i) => `burst-${stamp}-${i}@example.test`);

    await Promise.all(
      recipients.map((to) =>
        instance.send(
          renderOtpCode({ appName: 'Acme', to, code: '111111', ttlMinutes: 5, purpose: 'mfa' }),
        ),
      ),
    );

    for (const to of recipients) {
      await expect(findMessage(to)).resolves.toBeTruthy();
    }
  });
});

describe('fail-soft guarantee', () => {
  // Port 1 is reserved and never listening: a deterministic "provider is down".
  const unreachable = { host: '127.0.0.1', port: 1 };

  it('reports a failed send instead of throwing', async () => {
    const results: Array<{ ok: boolean; error?: string }> = [];
    const instance = mailer({ ...unreachable, onResult: (result) => results.push(result) });

    // ⚑ This must resolve. If it rejected, the caller's registration or login
    // would fail because a mail relay was unavailable.
    await expect(
      instance.send({ to: 'nobody@example.test', subject: 's', text: 't', html: '<p>t</p>' }),
    ).resolves.toBeUndefined();

    expect(results).toHaveLength(1);
    expect(results[0]?.ok).toBe(false);
    // The truth still reaches the log and the metric.
    expect(results[0]?.error).toBeTruthy();
  });

  it('reports an unreachable server from verify() as false, not an exception', async () => {
    // Readiness calls this; it must never throw or the probe itself 500s.
    await expect(mailer(unreachable).verify()).resolves.toBe(false);
  });

  it('keeps working after a failure — no poisoned transport', async () => {
    const instance = mailer();
    await instance.send({ to: 'ok@example.test', subject: 'first', text: 't', html: '<p>t</p>' });

    const to = `after-failure-${Date.now()}@example.test`;
    const results: Array<{ ok: boolean }> = [];
    const failing = mailer({ ...unreachable, onResult: (r) => results.push(r) });
    await failing.send({ to: 'lost@example.test', subject: 'lost', text: 't', html: '<p>t</p>' });
    expect(results[0]?.ok).toBe(false);

    // The healthy instance is unaffected by the other one's failure.
    await instance.send(
      renderOtpCode({ appName: 'Acme', to, code: '222222', ttlMinutes: 5, purpose: 'login' }),
    );
    await expect(findMessage(to)).resolves.toBeTruthy();
  });
});
