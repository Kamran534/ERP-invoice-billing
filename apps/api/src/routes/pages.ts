/**
 * The handful of HTML pages the API serves so that emailed links are clickable.
 *
 * Every link this system sends lands on a *page*, never on an endpoint that acts.
 * Normally that page belongs to the front-end; these exist so a backend-only
 * deployment — or a developer with no front-end running — is not left with links
 * that go nowhere.
 *
 * ⚑ The `GET` renders; the `POST` commits. That split is the whole point, not
 * ceremony. Outlook Safe Links, corporate antivirus and mail-scanning proxies
 * fetch every URL in an email before a human sees it, so a link that consumed the
 * token on `GET` would be spent by a robot and the real user would be told their
 * link was invalid. `GET` is safe to prefetch because it changes nothing.
 *
 * ⚑ No JavaScript, deliberately. The global CSP is `default-src 'none'`, and a page
 * that needs a script needs an exception; a plain form needs none. It also means
 * the page works in a text browser and in whatever a mail client's preview pane is
 * doing.
 */

import type { FastifyInstance, FastifyReply } from 'fastify';
import { AuthError, isAuthError, verifyEmail } from '@auth/core';
import { requestContext } from '../lib/present.js';

/**
 * ⚑ Overrides the global policy for these two routes only. The API-wide CSP sets
 * `form-action 'none'`, which would block the button below — correct for JSON
 * routes, wrong for the one page that has a form.
 */
const PAGE_CSP = [
  "default-src 'none'",
  "style-src 'unsafe-inline'",
  "form-action 'self'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join('; ');

const STYLE = `
  /*
   * Deliberately self-contained: no stylesheet, no font file, no image. This page
   * is reached from an email, often on a phone, sometimes through a corporate
   * proxy that strips half of everything — every request it needs is a request
   * that can fail in front of someone who is only trying to confirm an address.
   *
   * The palette matches the web app's brand (#0744c6, sampled from the mark), so
   * the two do not look like different products when someone meets this fallback.
   */
  :root {
    color-scheme: light dark;
    --canvas: #f9fafb;
    --surface: #fff;
    --content: #171a20;
    --muted: #5c6371;
    --subtle: #8a90a0;
    --line: #e6e8ec;
    --brand: #0744c6;
    --brand-hover: #05379e;
    --brand-subtle: #eef2ff;
    --ok: #2f7d4f;
    --ok-subtle: #e8f6ee;
    --bad: #c0392b;
    --bad-subtle: #fdeceb;
    --shadow: 0 1px 3px rgb(23 26 32 / 0.07), 0 8px 24px rgb(23 26 32 / 0.06);
  }

  @media (prefers-color-scheme: dark) {
    :root {
      --canvas: #101216;
      --surface: #171a20;
      --content: #eceef2;
      --muted: #9aa1b0;
      --subtle: #6d7484;
      --line: #262a33;
      /* ⚑ A step lighter in the dark. The same blue that reads as confident on
         white reads as muddy on near-black — equal hex is not equal contrast. */
      --brand: #5b7cf5;
      --brand-hover: #7a94f8;
      --brand-subtle: #1b2140;
      --ok: #57b97e;
      --ok-subtle: #16281e;
      --bad: #f0715f;
      --bad-subtle: #2a1715;
      --shadow: 0 1px 3px rgb(0 0 0 / 0.4), 0 8px 24px rgb(0 0 0 / 0.35);
    }
  }

  * { box-sizing: border-box; }

  body {
    margin: 0;
    min-height: 100dvh;
    display: grid;
    place-items: center;
    padding: 2rem 1.25rem;
    background: var(--canvas);
    color: var(--content);
    font: 15px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    -webkit-font-smoothing: antialiased;
  }

  .card {
    width: 100%;
    max-width: 27rem;
    background: var(--surface);
    border-radius: 14px;
    box-shadow: var(--shadow);
    padding: 2rem;
    text-align: center;
  }

  .mark {
    display: inline-flex;
    align-items: center;
    gap: .55rem;
    margin-bottom: 1.75rem;
    font-weight: 600;
    letter-spacing: .09em;
    text-transform: uppercase;
    font-size: .8125rem;
    color: var(--content);
  }
  .mark span.dot {
    width: 22px; height: 22px; border-radius: 6px;
    background: var(--brand);
    display: inline-block;
  }

  .badge {
    width: 44px; height: 44px; border-radius: 12px;
    display: grid; place-items: center;
    margin: 0 auto 1.25rem;
    font-size: 20px; line-height: 1;
  }
  .badge.ok  { background: var(--ok-subtle);  color: var(--ok); }
  .badge.bad { background: var(--bad-subtle); color: var(--bad); }

  h1 {
    font-size: 1.375rem;
    line-height: 1.3;
    letter-spacing: -.02em;
    margin: 0 0 .5rem;
    font-weight: 600;
  }
  p { margin: 0; color: var(--muted); }
  p + p { margin-top: .75rem; }

  form { margin-top: 1.75rem; }

  button, .link {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    height: 42px;
    padding: 0 1.25rem;
    border: 0;
    border-radius: 8px;
    font: inherit;
    font-weight: 500;
    cursor: pointer;
    text-decoration: none;
    background: var(--brand);
    color: #fff;
    transition: background-color .12s ease;
  }
  button:hover, .link:hover { background: var(--brand-hover); }
  /* ⚑ Never removed. A focus ring is the only thing a keyboard user has. */
  button:focus-visible, .link:focus-visible {
    outline: 2px solid var(--brand);
    outline-offset: 2px;
  }

  .foot {
    margin-top: 1.5rem;
    font-size: .8125rem;
    color: var(--subtle);
  }

  @media (prefers-reduced-motion: reduce) {
    * { transition-duration: .01ms !important; }
  }
`;

function page(
  reply: FastifyReply,
  status: number,
  title: string,
  body: string,
  appName: string,
): FastifyReply {
  return reply
    .code(status)
    .header('content-type', 'text/html; charset=utf-8')
    .header('content-security-policy', PAGE_CSP)
    .send(
      `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
        `<meta name="viewport" content="width=device-width,initial-scale=1">` +
        // ⚑ Mail clients and scanners follow links; nothing here should be indexed
        // or kept in a shared cache, since the URL carries a live token.
        `<meta name="robots" content="noindex,nofollow">` +
        `<meta name="color-scheme" content="light dark">` +
        `<title>${escape(title)} · ${escape(appName)}</title>` +
        `<style>${STYLE}</style></head><body><main class="card">` +
        `<p class="mark"><span class="dot"></span>${escape(appName)}</p>` +
        `${body}</main></body></html>`,
    );
}

const escape = (value: string): string =>
  value.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!,
  );

export async function pageRoutes(app: FastifyInstance): Promise<void> {
  // Scoped to this encapsulated plugin, so the JSON API keeps rejecting anything
  // that is not `application/json`.
  app.addContentTypeParser(
    'application/x-www-form-urlencoded',
    { parseAs: 'string' },
    (_request, body, done) => {
      done(null, Object.fromEntries(new URLSearchParams(body as string)));
    },
  );

  const verifyPath = app.auth.config.urls.verifyPath;
  const appName = app.auth.config.appName;

  /**
   * Where to send someone afterwards.
   *
   * ⚑ `appOrigin` is where the front end lives — the same value every emailed
   * link is built from. When it points elsewhere (the normal case once a front
   * end exists) "sign in" should take people there rather than leaving them on an
   * API page with nowhere to go.
   */
  const signInUrl = `${app.auth.config.urls.appOrigin}/login`;

  app.get(
    verifyPath,
    // Not part of the API contract — a page, not an endpoint.
    { schema: { hide: true } },
    async (request, reply) => {
      const { token } = request.query as { token?: string };

      if (!token) {
        return page(
          reply,
          400,
          'Link incomplete',
          `<div class="badge bad">!</div>` +
            `<h1>That link is incomplete</h1>` +
            `<p>It is missing its confirmation code. Copy the whole link out of the ` +
            `email — some mail clients cut long links in half.</p>` +
            `<p class="foot"><a class="link" href="${escape(signInUrl)}">Go to sign in</a></p>`,
          appName,
        );
      }

      return page(
        reply,
        200,
        'Confirm your email',
        `<h1>Confirm your email address</h1>` +
          `<p>One more step to finish setting up your ${escape(appName)} account.</p>` +
          `<form method="post" action="${escape(verifyPath)}">` +
          `<input type="hidden" name="token" value="${escape(token)}">` +
          `<button type="submit">Confirm my email</button>` +
          `</form>` +
          `<p class="foot">This link expires 24 hours after it was sent, and works once.</p>`,
        appName,
      );
    },
  );

  app.post(
    verifyPath,
    {
      config: { rateLimit: { max: 20, timeWindow: '1 hour' } },
      schema: { hide: true },
    },
    async (request, reply) => {
      const { token } = (request.body ?? {}) as { token?: string };
      if (!token) throw new AuthError('VALIDATION_FAILED', 'Missing token');

      try {
        await verifyEmail(app.auth, app.authDeps, { token, ...requestContext(request) });
      } catch (error) {
        // One page for expired, already-used and never-existed — the same three
        // cases the JSON endpoint refuses to distinguish, for the same reason.
        if (isAuthError(error) && error.status < 500) {
          return page(
            reply,
            error.status,
            'Link no longer valid',
            `<div class="badge bad">!</div>` +
              `<h1>That link is no longer valid</h1>` +
              `<p>Confirmation links expire after 24 hours and work only once. ` +
              `Ask for a new one from the sign-in screen.</p>` +
              `<p class="foot"><a class="link" href="${escape(signInUrl)}">Go to sign in</a></p>`,
            appName,
          );
        }
        throw error;
      }

      return page(
        reply,
        200,
        'Email confirmed',
        `<div class="badge ok">✓</div>` +
          `<h1>Email confirmed</h1>` +
          `<p>Your account is active. Sign in to finish setting up your organization.</p>` +
          `<p class="foot"><a class="link" href="${escape(signInUrl)}">Go to sign in</a></p>`,
        appName,
      );
    },
  );
}
