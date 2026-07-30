/**
 * SMTP transport (AUTH-MODULE-PLAN.md §12).
 *
 * In dev this points at Mailpit, which accepts everything and delivers nothing
 * outside the machine. In production, point it at a real relay.
 *
 * ⚑ Delivery must never be able to fail a login or a registration. `send()`
 * therefore never throws into the caller's path — it resolves with an outcome and
 * the caller records a metric. A mail-provider outage degrades signup, it does
 * not take down authentication.
 */

import nodemailer, { type Transporter } from 'nodemailer';
import type { Mailer, RenderedMail } from '@auth/core';

export interface MailerOptions {
  host: string;
  port: number;
  secure: boolean;
  user?: string | undefined;
  pass?: string | undefined;
  from: string;
  /** Connection reuse: one TCP+TLS handshake per burst instead of per message. */
  maxConnections?: number;
  maxMessages?: number;
  /** Provider-side throttle guard: at most `rateLimit` messages per `rateDelta` ms. */
  rateDelta?: number;
  rateLimit?: number;
  onResult?: (result: { template?: string; ok: boolean; error?: string }) => void;
}

export interface AppMailer extends Mailer {
  /** Handshake check for /health/ready. */
  verify(): Promise<boolean>;
  close(): void;
}

export function createSmtpMailer(opts: MailerOptions): AppMailer {
  const transporter: Transporter = nodemailer.createTransport({
    host: opts.host,
    port: opts.port,
    secure: opts.secure,
    ...(opts.user ? { auth: { user: opts.user, pass: opts.pass ?? '' } } : {}),
    pool: true,
    maxConnections: opts.maxConnections ?? 5,
    maxMessages: opts.maxMessages ?? 100,
    rateDelta: opts.rateDelta ?? 1_000,
    rateLimit: opts.rateLimit ?? 20,
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 20_000,
    // Mailpit presents a self-signed cert; only tolerate that when not secure.
    tls: { rejectUnauthorized: opts.secure },
  });

  return {
    async send(mail: RenderedMail): Promise<void> {
      try {
        await transporter.sendMail({
          from: opts.from,
          to: mail.to,
          subject: mail.subject,
          text: mail.text,
          html: mail.html,
          headers: {
            // Stops well-behaved clients and gateways from prefetching links,
            // which would otherwise consume single-use magic links (§5.12).
            'X-Auto-Response-Suppress': 'All',
            'Auto-Submitted': 'auto-generated',
          },
        });
        opts.onResult?.({ ok: true });
      } catch (error) {
        // Swallow: see the header comment. The caller sees success; the metric
        // and the log see the truth.
        opts.onResult?.({ ok: false, error: (error as Error).message });
      }
    },

    async verify(): Promise<boolean> {
      try {
        await transporter.verify();
        return true;
      } catch {
        return false;
      }
    },

    close(): void {
      transporter.close();
    },
  };
}
