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
  :root { color-scheme: light dark; }
  body {
    font: 16px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif;
    max-width: 34rem; margin: 12vh auto; padding: 0 1.5rem;
  }
  h1 { font-size: 1.4rem; margin: 0 0 .5rem; }
  p { margin: 0 0 1rem; color: #555; }
  @media (prefers-color-scheme: dark) { body { background: #16181d; color: #e8eaed; } p { color: #a8adb8; } }
  button {
    font: inherit; padding: .7rem 1.4rem; border: 0; border-radius: .4rem;
    background: #2f6feb; color: #fff; cursor: pointer;
  }
  .bad { color: #c0392b; }
  @media (prefers-color-scheme: dark) { .bad { color: #ff6b5a; } }
`;

function page(reply: FastifyReply, status: number, title: string, body: string): FastifyReply {
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
        `<title>${title}</title><style>${STYLE}</style></head><body>${body}</body></html>`,
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
          `<h1 class="bad">That link is incomplete</h1>` +
            `<p>It is missing its confirmation code. Copy the whole link out of the ` +
            `email — some mail clients cut long links in half.</p>`,
        );
      }

      return page(
        reply,
        200,
        'Confirm your email',
        `<h1>Confirm your email address</h1>` +
          `<p>One more step to finish setting up your ${escape(app.auth.config.appName)} account.</p>` +
          `<form method="post" action="${escape(verifyPath)}">` +
          `<input type="hidden" name="token" value="${escape(token)}">` +
          `<button type="submit">Confirm my email</button>` +
          `</form>`,
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
            `<h1 class="bad">That link is no longer valid</h1>` +
              `<p>Confirmation links expire after 24 hours and work only once. ` +
              `Ask for a new one from the sign-in screen.</p>`,
          );
        }
        throw error;
      }

      return page(
        reply,
        200,
        'Email confirmed',
        `<h1>Email confirmed</h1>` +
          `<p>Your account is active. You can close this tab and sign in.</p>`,
      );
    },
  );
}
