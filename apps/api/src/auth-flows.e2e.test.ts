/**
 * The Phase 1 flows, driven through HTTP exactly as a browser drives them.
 *
 * `app.e2e.test.ts` covers the cross-cutting surface — headers, envelopes, the
 * OpenAPI contract. This file covers the flows themselves: sign up, follow the
 * link out of a real mailbox, log in, rotate, read yourself, sign out.
 *
 * ⚑ These are the tests that would catch a mistake the unit suite cannot see,
 * because every one of them is a *transport* mistake: a cookie set at the wrong
 * `Path`, a CSRF hook in the wrong order, a token returned in a body it should
 * never appear in. The decisions are already proven in `@auth/core`.
 *
 *   pnpm up && pnpm db:migrate && pnpm test:e2e
 */

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest';
import type { FastifyInstance, InjectOptions } from 'fastify';
import { sql } from '@auth/db';
import { createTotpService } from '@auth/crypto';
import { loadEnv } from './env.js';
import { buildApp } from './app.js';

const MAILPIT_API = process.env['MAILPIT_API_URL'] ?? 'http://localhost:8025';

let app: FastifyInstance;

/**
 * ⚑ Its own Redis namespace, distinct from the other e2e file's. Registration is
 * capped at 5/hour per IP and every injected request shares 127.0.0.1, so two
 * suites in one namespace would spend each other's budget and fail as 429s that
 * look like broken handlers.
 */
beforeAll(async () => {
  app = await buildApp(
    loadEnv({
      ...process.env,
      NODE_ENV: 'test',
      // ⚑ Pinned, not inherited. `vitest.config.ts` loads `.env` into process.env
      // and this object spreads it, so a developer setting COOKIE_MODE=both to make
      // Swagger convenient silently changed what these tests assert. Anything the
      // suite makes claims about has to be stated here.
      COOKIE_MODE: 'cookie',
      HTTPS_ENABLED: 'false',
      // ⚑ The throwaway database, when one is configured. e2e does not truncate,
      // but it does create accounts on every run, and they have no business
      // accumulating in the database someone is developing against.
      ...(process.env['TEST_DATABASE_URL'] ? { DATABASE_URL: process.env['TEST_DATABASE_URL'] } : {}),
    // ⚑ The throwaway database, when one is configured. e2e does not truncate,
    // but it does create accounts on every run, and they have no business
    // accumulating in the database someone is developing against.
    ...(process.env['TEST_DATABASE_URL'] ? { DATABASE_URL: process.env['TEST_DATABASE_URL'] } : {}),
      LOG_LEVEL: 'silent',
      SWAGGER_ENABLED: 'false',
      REDIS_KEY_PREFIX: `e2e-flows-${Date.now()}:`,
      // Exercised by the 2FA block below; off by default everywhere else.
      MFA_TRUSTED_DEVICES: 'true',
      MFA_ENFORCE: 'optional',
      MAX_EVENT_LOOP_DELAY_MS: '60000',
      MAX_HEAP_USED_BYTES: String(8 * 1024 ** 3),
      MAX_RSS_BYTES: String(8 * 1024 ** 3),
      DB_CONNECT_TIMEOUT_MS: '30000',
      REDIS_COMMAND_TIMEOUT_MS: '10000',
    } as NodeJS.ProcessEnv),
  );

  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    const response = await app.inject({ method: 'GET', url: '/health/ready' });
    if (response.statusCode === 200) break;
    await new Promise((resolve) => setTimeout(resolve, 1_100));
  }
});

afterAll(async () => {
  await app?.close();
});

// ── helpers ────────────────────────────────────────────────────────────────

const json = <T>(response: { payload: string }): T => JSON.parse(response.payload) as T;

/** A distinct address per test, so one run never depends on another's leftovers. */
let seq = 0;
const freshEmail = () => `flow-${Date.now()}-${(seq += 1)}@example.test`;
/**
 * ⚑ Not `correct horse battery staple` — that one is in the HIBP corpus and the
 * breach check rejects it, which is the subject of its own test below.
 */
const PASSWORD = 'quilted-lantern-parade-7731-vestibule';

/**
 * ⚑ A distinct client address per test.
 *
 * Rate limits key off `request.ip`, and `app.inject()` reports 127.0.0.1 for
 * everything — so on one address the whole suite shares a single
 * five-registrations-per-hour bucket and fails as 429s that look like broken
 * handlers. Separate addresses are also the more honest model: these *are*
 * different clients.
 */
let clientIp = '10.0.0.1';
let ipSeq = 0;

beforeEach(() => {
  ipSeq += 1;
  clientIp = `10.${Math.floor(ipSeq / 65_025) % 255}.${Math.floor(ipSeq / 255) % 255}.${ipSeq % 255}`;
});

const call = (options: InjectOptions) => app.inject({ remoteAddress: clientIp, ...options });

/**
 * ⚑ Read from config, never hardcoded. The names change with `cookies.secure` —
 * `__Host-` is only legal alongside `Secure`, so over plain HTTP the prefix is
 * dropped. Hardcoding `__Host-at` made these tests assert a name the browser would
 * have rejected, which is how the bug survived 93 of them.
 */
const NAMES = () => app.auth.config.cookies.names;

interface Jar {
  [name: string]: string;
}

/** Collects Set-Cookie the way a browser would, including deletions. */
function absorb(jar: Jar, response: { headers: Record<string, unknown> }): Jar {
  const raw = response.headers['set-cookie'];
  const all = Array.isArray(raw) ? raw : raw ? [String(raw)] : [];
  for (const line of all) {
    const [pair] = line.split(';');
    const index = pair?.indexOf('=') ?? -1;
    if (index < 1) continue;
    const name = pair!.slice(0, index);
    const value = pair!.slice(index + 1);
    // `Max-Age=0` / empty value is a deletion; model it as one or a "logged out"
    // assertion would pass while the cookie was still being sent.
    if (value === '' || /max-age=0/i.test(line)) delete jar[name];
    else jar[name] = value;
  }
  return jar;
}

const cookieHeader = (jar: Jar): string =>
  Object.entries(jar)
    .map(([name, value]) => `${name}=${value}`)
    .join('; ');

/** Cookie header plus the CSRF echo, which every state-changing call needs. */
function authHeaders(jar: Jar): Record<string, string> {
  return {
    cookie: cookieHeader(jar),
    ...(jar[NAMES().csrf] ? { 'x-csrf-token': jar[NAMES().csrf]! } : {}),
  };
}

async function mailpitFind(recipient: string, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const search = await fetch(
      `${MAILPIT_API}/api/v1/search?query=${encodeURIComponent(recipient)}`,
    );
    if (search.ok) {
      const body = (await search.json()) as { messages?: Array<{ ID: string }> };
      const found = body.messages?.[0];
      if (found) {
        const message = await fetch(`${MAILPIT_API}/api/v1/message/${found.ID}`);
        return (await message.json()) as { Text: string; Subject: string };
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`no mail for ${recipient} within ${timeoutMs}ms`);
}

/** Signs up and follows the emailed link, exactly as a person would. */
async function signUpAndVerify(email = freshEmail()): Promise<string> {
  const registered = await call({
    method: 'POST',
    url: '/auth/register',
    payload: { email, password: PASSWORD, name: 'Ada' },
  });
  expect(registered.statusCode, registered.payload).toBe(202);

  const mail = await mailpitFind(email);
  const token = mail.Text.match(/token=([^\s&]+)/)?.[1];
  expect(token, `no verification token in: ${mail.Text}`).toBeTruthy();

  const verified = await call({
    method: 'POST',
    url: '/auth/verify-email',
    payload: { token },
  });
  expect(verified.statusCode, verified.payload).toBe(200);
  return email;
}

/** Logs in and returns the resulting cookie jar. */
async function signIn(email: string, password = PASSWORD): Promise<Jar> {
  const response = await call({
    method: 'POST',
    url: '/auth/login',
    payload: { email, password },
  });
  expect(response.statusCode, response.payload).toBe(200);
  return absorb({}, response);
}

// ───────────────────────────────────────────────────────────────────────────
describe('signing up', () => {
  it('creates a pending account and mails a link', async () => {
    const email = freshEmail();
    const response = await call({
      method: 'POST',
      url: '/auth/register',
      payload: { email, password: PASSWORD, name: 'Ada' },
    });

    expect(response.statusCode).toBe(202);
    expect(json<{ status: string }>(response).status).toBe('verification_sent');
    // ⚑ No session. Registering must not authenticate anyone.
    expect(response.headers['set-cookie']).toBeUndefined();

    const mail = await mailpitFind(email);
    expect(mail.Subject).toMatch(/confirm/i);
    expect(mail.Text).toContain('/verify?token=');
  });

  it('⚑ answers a taken address identically', async () => {
    const email = freshEmail();
    const first = await call({
      method: 'POST',
      url: '/auth/register',
      payload: { email, password: PASSWORD },
    });
    const second = await call({
      method: 'POST',
      url: '/auth/register',
      payload: { email, password: PASSWORD },
    });

    expect(second.statusCode).toBe(first.statusCode);
    expect(second.payload).toBe(first.payload);
  });

  it('refuses a password below the minimum length', async () => {
    const response = await call({
      method: 'POST',
      url: '/auth/register',
      payload: { email: freshEmail(), password: 'short' },
    });
    // Rejected by the schema before the use-case ever runs — the 400/422 split is
    // "malformed request" versus "well-formed but unacceptable".
    expect([400, 422]).toContain(response.statusCode);
  });

  it('refuses a long but breached passphrase', async () => {
    const response = await call({
      method: 'POST',
      url: '/auth/register',
      payload: { email: freshEmail(), password: 'correct horse battery staple' },
    });

    // ⚑ 28 characters, passes every length rule, and is in the HIBP corpus. This
    // is the case the breach check exists for — and the one that caught the
    // checker not being wired at all.
    //
    // The check fails open by design, so a network outage turns this into a 202.
    // The assertion accepts that rather than being flaky, and
    // `packages/crypto/src/breach.int.test.ts` proves the checker itself works.
    if (response.statusCode === 202) {
      expect(
        process.env['CI'],
        'breach check let a corpus password through — HIBP unreachable, or the checker is unwired',
      ).toBeUndefined();
      return;
    }
    expect(response.statusCode).toBe(422);
    expect(json<{ error: { code: string } }>(response).error.code).toBe('PASSWORD_BREACHED');
  });

  it('activates the account when the link is followed, and only once', async () => {
    const email = freshEmail();
    await call({
      method: 'POST',
      url: '/auth/register',
      payload: { email, password: PASSWORD },
    });
    const token = (await mailpitFind(email)).Text.match(/token=([^\s&]+)/)?.[1];

    const first = await call({ method: 'POST', url: '/auth/verify-email', payload: { token } });
    expect(first.statusCode).toBe(200);
    // ⚑ Still no session — verifying proves a mailbox, not a password.
    expect(first.headers['set-cookie']).toBeUndefined();

    const second = await call({ method: 'POST', url: '/auth/verify-email', payload: { token } });
    expect(second.statusCode).toBe(410);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('logging in', () => {
  it('sets three cookies and returns no tokens in the body', async () => {
    const email = await signUpAndVerify();
    const response = await call({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: PASSWORD },
    });

    expect(response.statusCode).toBe(200);
    const body = json<{ status: string; session: Record<string, unknown> }>(response);
    expect(body.status).toBe('authenticated');
    // ⚑ Cookie mode. A token in the body would end up in logs, caches and
    // devtools screenshots — the exact exposure httpOnly cookies prevent.
    expect(body.session['accessToken']).toBeUndefined();
    expect(body.session['refreshToken']).toBeUndefined();

    const jar = absorb({}, response);
    expect(Object.keys(jar).sort()).toEqual(
      [NAMES().access, NAMES().refresh, NAMES().csrf].sort(),
    );
  });

  it('⚑ scopes the refresh cookie to the refresh endpoint only', async () => {
    const email = await signUpAndVerify();
    const response = await call({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: PASSWORD },
    });

    const lines = ([] as string[]).concat(response.headers['set-cookie'] as string[]);
    const refresh = lines.find((line) => line.startsWith(`${NAMES().refresh}=`));
    const access = lines.find((line) => line.startsWith(`${NAMES().access}=`));

    // The long-lived credential must not ride along on every ordinary API call.
    expect(refresh).toContain('Path=/auth/token');
    expect(refresh).toContain('HttpOnly');
    expect(access).toContain('Path=/');
  });

  it('⚑ never claims a cookie prefix its attributes cannot back', async () => {
    const email = await signUpAndVerify();
    const response = await call({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: PASSWORD },
    });

    // The rule browsers enforce, restated here because breaking it is silent:
    // a cookie whose name claims more than its attributes deliver is *discarded*,
    // so login succeeds, sets nothing, and the next call is anonymous.
    for (const line of ([] as string[]).concat(response.headers['set-cookie'] as string[])) {
      const name = line.slice(0, line.indexOf('='));
      const attributes = line.toLowerCase();

      if (name.startsWith('__Host-')) {
        expect(attributes, `${name} lacks Secure`).toContain('secure');
        expect(attributes, `${name} is not Path=/`).toMatch(/path=\/(;|$)/);
        expect(attributes, `${name} sets a Domain`).not.toContain('domain=');
      }
      if (name.startsWith('__Secure-')) {
        expect(attributes, `${name} lacks Secure`).toContain('secure');
      }
    }
  });

  it('leaves the CSRF cookie readable, because that is the mechanism', async () => {
    const email = await signUpAndVerify();
    const response = await call({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: PASSWORD },
    });

    const csrf = ([] as string[])
      .concat(response.headers['set-cookie'] as string[])
      .find((line) => line.startsWith('csrf='));
    // The client must be able to read it to echo it in a header; an attacker on
    // another origin can cause it to be sent but cannot read it.
    expect(csrf).not.toContain('HttpOnly');
  });

  it('⚑ answers an unknown address and a wrong password identically', async () => {
    const email = await signUpAndVerify();

    const unknown = await call({
      method: 'POST',
      url: '/auth/login',
      payload: { email: freshEmail(), password: PASSWORD },
    });
    const wrong = await call({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: 'not the password' },
    });

    expect(unknown.statusCode).toBe(401);
    expect(wrong.statusCode).toBe(401);

    // Everything except `traceId`, which is per-request by design and is the one
    // field a client is meant to see differ.
    const shape = (response: { payload: string }) => {
      const { traceId, ...rest } = json<{ error: Record<string, unknown> }>(response).error;
      void traceId;
      return rest;
    };
    expect(shape(unknown)).toEqual(shape(wrong));
    expect(unknown.headers['set-cookie']).toBeUndefined();
  });

  it('refuses an unverified account with its own code', async () => {
    const email = freshEmail();
    await call({
      method: 'POST',
      url: '/auth/register',
      payload: { email, password: PASSWORD },
    });

    const response = await call({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: PASSWORD },
    });
    expect(response.statusCode).toBe(403);
    expect(json<{ error: { code: string } }>(response).error.code).toBe('EMAIL_NOT_VERIFIED');
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('the authenticated surface', () => {
  it('answers /auth/me for a live session', async () => {
    const email = await signUpAndVerify();
    const jar = await signIn(email);

    const response = await call({
      method: 'GET',
      url: '/auth/me',
      headers: { cookie: cookieHeader(jar) },
    });

    expect(response.statusCode).toBe(200);
    const body = json<{ user: { email: string; emailVerified: boolean }; amr: string[] }>(response);
    expect(body.user.email).toBe(email);
    expect(body.user.emailVerified).toBe(true);
    expect(body.amr).toEqual(['pwd']);
  });

  it('refuses without a token, and says nothing about why', async () => {
    const response = await call({ method: 'GET', url: '/auth/me' });
    expect(response.statusCode).toBe(401);
    expect(json<{ error: { code: string } }>(response).error.code).toBe('TOKEN_INVALID');
  });

  it('gives one answer for a tampered token and an unsigned one', async () => {
    const garbage = await call({
      method: 'GET',
      url: '/auth/me',
      headers: { cookie: `${NAMES().access}=not.a.token` },
    });
    const missing = await call({ method: 'GET', url: '/auth/me' });

    // Expired, tampered, wrong audience, signed by a key we no longer hold — the
    // client's move is identical in every case.
    expect(garbage.statusCode).toBe(missing.statusCode);
    expect(json<{ error: { code: string } }>(garbage).error.code).toBe('TOKEN_INVALID');
  });

  it('lists the signed-in devices with the current one marked', async () => {
    const email = await signUpAndVerify();
    const first = await signIn(email);
    await signIn(email);

    const response = await call({
      method: 'GET',
      url: '/auth/sessions',
      headers: { cookie: cookieHeader(first) },
    });

    expect(response.statusCode).toBe(200);
    const { sessions } = json<{ sessions: Array<{ current: boolean }> }>(response);
    expect(sessions.length).toBeGreaterThanOrEqual(2);
    expect(sessions.filter((s) => s.current)).toHaveLength(1);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('CSRF', () => {
  it('⚑ refuses a write that carries cookies but no echoed token', async () => {
    const email = await signUpAndVerify();
    const jar = await signIn(email);

    // Exactly the shape of a cross-origin form post: the browser attaches the
    // cookies, the attacker cannot read them to build the header.
    const response = await call({
      method: 'POST',
      url: '/auth/logout-all',
      headers: { cookie: cookieHeader(jar) },
    });

    expect(response.statusCode).toBe(403);
    expect(json<{ error: { code: string } }>(response).error.code).toBe('CSRF_FAILED');
  });

  it('refuses a mismatched token', async () => {
    const email = await signUpAndVerify();
    const jar = await signIn(email);

    const response = await call({
      method: 'POST',
      url: '/auth/logout-all',
      headers: { cookie: cookieHeader(jar), 'x-csrf-token': 'csrf_something-else' },
    });
    expect(response.statusCode).toBe(403);
  });

  it('accepts the matching pair', async () => {
    const email = await signUpAndVerify();
    const jar = await signIn(email);

    const response = await call({
      method: 'POST',
      url: '/auth/logout-all',
      headers: authHeaders(jar),
    });
    expect(response.statusCode).toBe(200);
  });

  it('⚑ does not gate a bearer-authenticated write, even with cookies present', async () => {
    // Its own instance: this suite runs in `cookie` mode, and the case only exists
    // in a deployment that also accepts bearer.
    const instance = await buildApp(
      loadEnv({
        ...process.env,
        NODE_ENV: 'test',
        COOKIE_MODE: 'both',
        HTTPS_ENABLED: 'false',
        LOG_LEVEL: 'silent',
        SWAGGER_ENABLED: 'false',
        REDIS_KEY_PREFIX: `e2e-bearer-${Date.now()}:`,
        MAX_EVENT_LOOP_DELAY_MS: '60000',
        MAX_HEAP_USED_BYTES: String(8 * 1024 ** 3),
        MAX_RSS_BYTES: String(8 * 1024 ** 3),
        DB_CONNECT_TIMEOUT_MS: '30000',
        REDIS_COMMAND_TIMEOUT_MS: '10000',
        ...(process.env['TEST_DATABASE_URL']
          ? { DATABASE_URL: process.env['TEST_DATABASE_URL'] }
          : {}),
      } as NodeJS.ProcessEnv),
    );

    try {
      const email = freshEmail();
      await instance.inject({
        method: 'POST',
        remoteAddress: clientIp,
        url: '/auth/register',
        payload: { email, password: PASSWORD },
      });
      const verifyToken = (await mailpitFind(email)).Text.match(/token=([^\s&]+)/)?.[1];
      await instance.inject({
        method: 'POST',
        remoteAddress: clientIp,
        url: '/auth/verify-email',
        payload: { token: verifyToken },
      });

      const login = await instance.inject({
        method: 'POST',
        remoteAddress: clientIp,
        url: '/auth/login',
        payload: { email, password: PASSWORD },
      });
      const jar = absorb({}, login);
      const token = json<{ session: { accessToken: string } }>(login).session.accessToken;

      // Exactly what Swagger UI's Authorize button produces: a bearer token doing
      // the work, and the browser attaching the session cookies anyway. An
      // `Authorization` header is not ambient — a cross-site attacker cannot set
      // one — so there is nothing here for CSRF to defend. Demanding the echo
      // header made every authenticated write fail with CSRF_FAILED.
      const response = await instance.inject({
        method: 'POST',
        remoteAddress: clientIp,
        url: '/auth/logout-all',
        headers: { cookie: cookieHeader(jar), authorization: `Bearer ${token}` },
      });

      expect(response.statusCode, response.payload).toBe(200);
    } finally {
      await instance.close();
    }
  }, 30_000);

  it('⚑ still gates a cookie-authenticated write when a bearer header is absent', async () => {
    const email = await signUpAndVerify();
    const jar = await signIn(email);

    // The exemption is about the *header*, not about being authenticated. Remove
    // it and the ambient path is protected exactly as before.
    const response = await call({
      method: 'POST',
      url: '/auth/logout-all',
      headers: { cookie: cookieHeader(jar) },
    });
    expect(response.statusCode).toBe(403);
  });

  it('never gates a read', async () => {
    const email = await signUpAndVerify();
    const jar = await signIn(email);

    // GET cannot change state, so demanding a token there only breaks clients.
    const response = await call({
      method: 'GET',
      url: '/auth/me',
      headers: { cookie: cookieHeader(jar) },
    });
    expect(response.statusCode).toBe(200);
  });

  it('does not gate login, which has no cookie to echo yet', async () => {
    const email = await signUpAndVerify();
    const response = await call({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: PASSWORD },
    });
    expect(response.statusCode).toBe(200);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('refresh', () => {
  it('rotates and re-sets both cookies', async () => {
    const email = await signUpAndVerify();
    const jar = await signIn(email);
    const before = { ...jar };

    const response = await call({
      method: 'POST',
      url: '/auth/token/refresh',
      headers: authHeaders(jar),
      payload: {},
    });

    expect(response.statusCode, response.payload).toBe(200);
    const after = absorb({ ...jar }, response);
    // ⚑ A new refresh token every time. Reusing it would make theft undetectable.
    expect(after[NAMES().refresh]).not.toBe(before[NAMES().refresh]);
    expect(after[NAMES().access]).not.toBe(before[NAMES().access]);
    // Cookie mode returns no tokens in the body.
    expect(response.payload).not.toContain('refreshToken');
  });

  it('the rotated access token works', async () => {
    const email = await signUpAndVerify();
    const jar = await signIn(email);

    const rotated = await call({
      method: 'POST',
      url: '/auth/token/refresh',
      headers: authHeaders(jar),
      payload: {},
    });
    const after = absorb({ ...jar }, rotated);

    const me = await call({
      method: 'GET',
      url: '/auth/me',
      headers: { cookie: cookieHeader(after) },
    });
    expect(me.statusCode).toBe(200);
  });

  it('⚑ a replayed refresh token kills the session and clears the cookies', async () => {
    const email = await signUpAndVerify();
    const jar = await signIn(email);
    const stolen = jar[NAMES().refresh]!;

    await call({
      method: 'POST',
      url: '/auth/token/refresh',
      headers: authHeaders(jar),
      payload: {},
    });

    // Presented again *later* — inside the in-flight window this is a multi-tab
    // race, not theft (ADR-0009), so the wait is the test, not a delay.
    await new Promise((resolve) => setTimeout(resolve, 2_100));

    const replay = await call({
      method: 'POST',
      url: '/auth/token/refresh',
      headers: {
        cookie: `${NAMES().refresh}=${stolen}; ${NAMES().csrf}=${jar[NAMES().csrf]}`,
        'x-csrf-token': jar[NAMES().csrf]!,
      },
      payload: {},
    });

    expect(replay.statusCode).toBe(401);
    // A bare 401 that never explains itself.
    expect(replay.payload).not.toMatch(/reuse|theft|detect/i);

    const cleared = absorb({ ...jar }, replay);
    expect(cleared[NAMES().refresh]).toBeUndefined();
  }, 15_000);

  it('⚑ keeps the cookies on a 409, because the client is about to retry', async () => {
    const email = await signUpAndVerify();
    const jar = await signIn(email);
    const first = jar[NAMES().refresh]!;

    await call({
      method: 'POST',
      url: '/auth/token/refresh',
      headers: authHeaders(jar),
      payload: {},
    });

    // Immediately again: the same token, inside the in-flight window.
    const race = await call({
      method: 'POST',
      url: '/auth/token/refresh',
      headers: {
        cookie: `${NAMES().refresh}=${first}; ${NAMES().csrf}=${jar[NAMES().csrf]}`,
        'x-csrf-token': jar[NAMES().csrf]!,
      },
      payload: {},
    });

    expect(race.statusCode).toBe(409);
    // Clearing here would sign out a user for opening a second tab.
    expect(race.headers['set-cookie']).toBeUndefined();
  });

  it('refuses a request with no refresh token at all', async () => {
    const response = await call({
      method: 'POST',
      url: '/auth/token/refresh',
      payload: {},
    });
    expect(response.statusCode).toBe(401);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('logging out', () => {
  it('clears every cookie and kills the session', async () => {
    const email = await signUpAndVerify();
    const jar = await signIn(email);

    const response = await call({
      method: 'POST',
      url: '/auth/logout',
      headers: authHeaders(jar),
    });
    expect(response.statusCode).toBe(204);

    const after = absorb({ ...jar }, response);
    // ⚑ All three, at the paths they were set with. Clearing the refresh cookie at `/`
    // would leave the real one at `/auth/token` alive and log nobody out.
    expect(after[NAMES().access]).toBeUndefined();
    expect(after[NAMES().refresh]).toBeUndefined();
    expect(after[NAMES().csrf]).toBeUndefined();

    const refresh = await call({
      method: 'POST',
      url: '/auth/token/refresh',
      headers: authHeaders(jar),
      payload: {},
    });
    expect(refresh.statusCode).toBe(401);
  });

  it('⚑ succeeds without a valid session, so a client can always clear itself', async () => {
    const response = await call({ method: 'POST', url: '/auth/logout' });
    // A 401 here would strand a client whose token lapsed while the tab was
    // backgrounded — with cookies it cannot delete itself.
    expect(response.statusCode).toBe(204);
  });

  it('signs out everywhere, and the other sessions really are dead', async () => {
    const email = await signUpAndVerify();
    const one = await signIn(email);
    const two = await signIn(email);

    const response = await call({
      method: 'POST',
      url: '/auth/logout-all',
      headers: authHeaders(one),
    });
    expect(response.statusCode).toBe(200);
    expect(json<{ revokedSessions: number }>(response).revokedSessions).toBeGreaterThanOrEqual(2);

    const stillIn = await call({
      method: 'GET',
      url: '/auth/me',
      headers: { cookie: cookieHeader(two) },
    });
    // The access token is still cryptographically valid, so the session lookup is
    // what has to catch this — which is exactly what /auth/me does.
    expect(stillIn.statusCode).toBe(401);
  });

  it('revokes one device by id', async () => {
    const email = await signUpAndVerify();
    const mine = await signIn(email);
    const other = await signIn(email);

    const listed = await call({
      method: 'GET',
      url: '/auth/sessions',
      headers: { cookie: cookieHeader(mine) },
    });
    const target = json<{ sessions: Array<{ id: string; current: boolean }> }>(listed).sessions.find(
      (s) => !s.current,
    );

    const response = await call({
      method: 'DELETE',
      url: `/auth/sessions/${target!.id}`,
      headers: authHeaders(mine),
    });
    expect(response.statusCode).toBe(204);

    const dead = await call({
      method: 'GET',
      url: '/auth/me',
      headers: { cookie: cookieHeader(other) },
    });
    expect(dead.statusCode).toBe(401);
  });

  it('⚑ answers NOT_FOUND for a session belonging to someone else', async () => {
    const mineEmail = await signUpAndVerify();
    const theirsEmail = await signUpAndVerify();
    const mine = await signIn(mineEmail);
    const theirs = await signIn(theirsEmail);

    const listed = await call({
      method: 'GET',
      url: '/auth/sessions',
      headers: { cookie: cookieHeader(theirs) },
    });
    const target = json<{ sessions: Array<{ id: string }> }>(listed).sessions[0]!;

    const response = await call({
      method: 'DELETE',
      url: `/auth/sessions/${target.id}`,
      headers: authHeaders(mine),
    });
    // 403 for "exists but not yours" versus 404 for "no such id" would let anyone
    // enumerate session ids.
    expect(response.statusCode).toBe(404);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('two-factor authentication', () => {
  const totp = createTotpService({ digits: 6, period: 30, window: 1 });

  /** Enrols a real TOTP factor through the API and returns what an app would hold. */
  async function enrol(jar: Jar): Promise<{ secret: string; recoveryCodes: string[] }> {
    const setup = await call({
      method: 'POST',
      url: '/auth/mfa/totp/setup',
      headers: authHeaders(jar),
    });
    expect(setup.statusCode, setup.payload).toBe(200);
    const { factorId, secret, recoveryCodes } = json<{
      factorId: string;
      secret: string;
      provisioningUri: string;
      recoveryCodes: string[];
    }>(setup);

    // ⚑ Nothing usable before confirmation — recovery codes handed out here would
    // be a working bypass behind an enrolment the user then abandoned.
    expect(recoveryCodes).toEqual([]);

    const confirmed = await call({
      method: 'POST',
      url: '/auth/mfa/totp/confirm',
      headers: authHeaders(jar),
      payload: { factorId, code: totp.generate({ base32: secret }) },
    });
    expect(confirmed.statusCode, confirmed.payload).toBe(200);

    return { secret, recoveryCodes: json<{ recoveryCodes: string[] }>(confirmed).recoveryCodes };
  }

  /**
   * The code an authenticator would show one timestep from now.
   *
   * ⚑ Not the current code. Confirming an enrolment burns the timestep it used,
   * so the very next login cannot reuse it — that is the replay guard working, and
   * a real user simply waits for the display to tick over. Computed from the step
   * boundary rather than `now + 30s`, which would land two steps out when the call
   * happens near the end of a window and fall outside the ±1 drift tolerance.
   */
  const nextCode = (secret: string): string =>
    totp.generate({ base32: secret }, new Date((totp.timestepAt() + 1) * 30_000));

  const startChallenge = async (email: string): Promise<string> => {
    const response = await call({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: PASSWORD },
    });
    return json<{ mfaToken: string }>(response).mfaToken;
  };

  it('enrols, confirms, and hands over recovery codes once', async () => {
    const email = await signUpAndVerify();
    const jar = await signIn(email);

    const { recoveryCodes } = await enrol(jar);
    expect(recoveryCodes).toHaveLength(10);
    expect(new Set(recoveryCodes).size).toBe(10);

    const state = json<{ enrolled: boolean; recoveryCodesRemaining: number }>(
      await call({ method: 'GET', url: '/auth/mfa', headers: { cookie: cookieHeader(jar) } }),
    );
    expect(state.enrolled).toBe(true);
    expect(state.recoveryCodesRemaining).toBe(10);
  });

  it('⚑ turns the next login into a challenge that carries no session', async () => {
    const email = await signUpAndVerify();
    await enrol(await signIn(email));

    const response = await call({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: PASSWORD },
    });

    expect(response.statusCode).toBe(200);
    const body = json<{ status: string; availableMethods: string[] }>(response);
    expect(body.status).toBe('mfa_required');
    expect(body.availableMethods).toContain('totp');
    // The first factor passed; the login has not. A cookie here would make the
    // second factor optional for anyone who ignores the response body.
    expect(response.headers['set-cookie']).toBeUndefined();
  });

  it('completes the challenge with a TOTP code and records both factors', async () => {
    const email = await signUpAndVerify();
    const { secret } = await enrol(await signIn(email));

    const verified = await call({
      method: 'POST',
      url: '/auth/mfa/verify',
      payload: {
        mfaToken: await startChallenge(email),
        method: 'totp',
        code: nextCode(secret),
      },
    });

    expect(verified.statusCode, verified.payload).toBe(200);
    const jar = absorb({}, verified);
    expect(jar[NAMES().access]).toBeTruthy();

    const me = json<{ amr: string[]; mfaSatisfiedAt: string | null }>(
      await call({ method: 'GET', url: '/auth/me', headers: { cookie: cookieHeader(jar) } }),
    );
    expect(me.amr).toEqual(['pwd', 'totp']);
    expect(me.mfaSatisfiedAt).not.toBeNull();
  });

  it('⚑ refuses the same code twice', async () => {
    const email = await signUpAndVerify();
    const { secret } = await enrol(await signIn(email));
    const code = nextCode(secret);

    const first = await call({
      method: 'POST',
      url: '/auth/mfa/verify',
      payload: { mfaToken: await startChallenge(email), method: 'totp', code },
    });
    expect(first.statusCode, first.payload).toBe(200);

    // Still inside its own drift window, so still cryptographically valid — which
    // is exactly the window someone who watched it being typed is working in.
    const replay = await call({
      method: 'POST',
      url: '/auth/mfa/verify',
      payload: { mfaToken: await startChallenge(email), method: 'totp', code },
    });
    expect(replay.statusCode).toBe(401);
  });

  it('⚑ destroys the challenge after five wrong codes', async () => {
    const email = await signUpAndVerify();
    const { secret } = await enrol(await signIn(email));
    const mfaToken = await startChallenge(email);

    for (let i = 0; i < 5; i += 1) {
      const wrong = await call({
        method: 'POST',
        url: '/auth/mfa/verify',
        payload: { mfaToken, method: 'totp', code: '000000' },
      });
      expect(wrong.statusCode).toBe(401);
    }

    // Six digits is ~20 bits; the cap is the only thing making that safe, so the
    // challenge itself has to die rather than just the attempt.
    const correct = await call({
      method: 'POST',
      url: '/auth/mfa/verify',
      payload: { mfaToken, method: 'totp', code: nextCode(secret) },
    });
    expect(correct.statusCode).toBe(429);
  });

  it('accepts a recovery code, once', async () => {
    const email = await signUpAndVerify();
    const { recoveryCodes } = await enrol(await signIn(email));

    const useCode = async (code: string) =>
      call({
        method: 'POST',
        url: '/auth/mfa/verify',
        payload: { mfaToken: await startChallenge(email), method: 'recovery', code },
      });

    expect((await useCode(recoveryCodes[0]!)).statusCode).toBe(200);
    expect((await useCode(recoveryCodes[0]!)).statusCode).toBe(401);
    expect((await useCode(recoveryCodes[1]!)).statusCode).toBe(200);
  });

  it('remembers a device and skips the challenge next time', async () => {
    const email = await signUpAndVerify();
    const { secret } = await enrol(await signIn(email));

    const verified = await call({
      method: 'POST',
      url: '/auth/mfa/verify',
      payload: {
        mfaToken: await startChallenge(email),
        method: 'totp',
        code: nextCode(secret),
        rememberDevice: true,
      },
    });
    const trustToken = absorb({}, verified)[NAMES().trustedDevice];
    expect(trustToken).toBeTruthy();

    const next = await call({
      method: 'POST',
      url: '/auth/login',
      headers: { cookie: `${NAMES().trustedDevice}=${trustToken}` },
      payload: { email, password: PASSWORD },
    });
    expect(json<{ status: string }>(next).status).toBe('authenticated');

    const me = json<{ amr: string[]; mfaSatisfiedAt: string | null }>(
      await call({
        method: 'GET',
        url: '/auth/me',
        headers: { cookie: cookieHeader(absorb({}, next)) },
      }),
    );
    expect(me.amr).toEqual(['pwd', 'device']);
    // ⚑ Trust skips the prompt; it does not count as having presented a factor.
    expect(me.mfaSatisfiedAt).toBeNull();
  });

  it('⚑ refuses step-up on a session that only used a trusted device', async () => {
    const email = await signUpAndVerify();
    const { secret } = await enrol(await signIn(email));

    const verified = await call({
      method: 'POST',
      url: '/auth/mfa/verify',
      payload: {
        mfaToken: await startChallenge(email),
        method: 'totp',
        code: nextCode(secret),
        rememberDevice: true,
      },
    });
    const trustToken = absorb({}, verified)[NAMES().trustedDevice];

    const trusted = absorb(
      {},
      await call({
        method: 'POST',
        url: '/auth/login',
        headers: { cookie: `${NAMES().trustedDevice}=${trustToken}` },
        payload: { email, password: PASSWORD },
      }),
    );

    // A stolen laptop can read the account; it must not be able to change what
    // protects it (§5.4.5).
    const attempt = await call({
      method: 'POST',
      url: '/auth/mfa/recovery-codes',
      headers: authHeaders(trusted),
    });
    expect(attempt.statusCode).toBe(403);
    expect(json<{ error: { code: string } }>(attempt).error.code).toBe('REAUTH_REQUIRED');
  });

  it('lists and revokes remembered devices', async () => {
    const email = await signUpAndVerify();
    const { secret } = await enrol(await signIn(email));

    const jar = absorb(
      {},
      await call({
        method: 'POST',
        url: '/auth/mfa/verify',
        payload: {
          mfaToken: await startChallenge(email),
          method: 'totp',
          code: nextCode(secret),
          rememberDevice: true,
        },
      }),
    );

    const listed = json<{ devices: Array<{ id: string }> }>(
      await call({
        method: 'GET',
        url: '/auth/trusted-devices',
        headers: { cookie: cookieHeader(jar) },
      }),
    );
    expect(listed.devices).toHaveLength(1);

    const revoked = await call({
      method: 'DELETE',
      url: `/auth/trusted-devices/${listed.devices[0]!.id}`,
      headers: authHeaders(jar),
    });
    expect(revoked.statusCode).toBe(204);
  });

  it('⚑ revokes the other sessions when 2FA is switched on', async () => {
    const email = await signUpAndVerify();
    const stale = await signIn(email);
    const current = await signIn(email);

    await enrol(current);

    // Whoever was already signed in is exactly who the new factor excludes.
    const check = await call({
      method: 'GET',
      url: '/auth/me',
      headers: { cookie: cookieHeader(stale) },
    });
    expect(check.statusCode).toBe(401);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('organizations', () => {
  /** A fresh instance for each test: `first-user` is a once-per-database rule. */
  async function freshInstance(selfService = 'first-user') {
    const instance = await buildApp(
      loadEnv({
        ...process.env,
        NODE_ENV: 'test',
        COOKIE_MODE: 'both',
        HTTPS_ENABLED: 'false',
        LOG_LEVEL: 'silent',
        SWAGGER_ENABLED: 'false',
        ORG_SELF_SERVICE: selfService,
        REDIS_KEY_PREFIX: `e2e-org-${Date.now()}-${Math.random()}:`,
        MAX_EVENT_LOOP_DELAY_MS: '60000',
        MAX_HEAP_USED_BYTES: String(8 * 1024 ** 3),
        MAX_RSS_BYTES: String(8 * 1024 ** 3),
        DB_CONNECT_TIMEOUT_MS: '30000',
        REDIS_COMMAND_TIMEOUT_MS: '10000',
        ...(process.env['TEST_DATABASE_URL']
          ? { DATABASE_URL: process.env['TEST_DATABASE_URL'] }
          : {}),
      } as NodeJS.ProcessEnv),
    );
    // ⚑ Wipe first. `first-user` asks "does any org exist", and the answer is
    // whatever previous tests left behind — the rule is about the database, not
    // about the process.
    await instance.dbHandle.db.execute(
      sql`TRUNCATE TABLE auth_orgs, auth_memberships, auth_roles, auth_users CASCADE`,
    );
    return instance;
  }

  /** Registers, verifies and signs in against a specific app instance. */
  async function onboard(instance: FastifyInstance, email = freshEmail()) {
    const reg = await instance.inject({
      method: 'POST',
      remoteAddress: clientIp,
      url: '/auth/register',
      payload: { email, password: PASSWORD },
    });
    expect(reg.statusCode, reg.payload).toBe(202);

    const token = (await mailpitFind(email)).Text.match(/token=([^\s&]+)/)?.[1];
    await instance.inject({
      method: 'POST',
      remoteAddress: clientIp,
      url: '/auth/verify-email',
      payload: { token },
    });

    const login = await instance.inject({
      method: 'POST',
      remoteAddress: clientIp,
      url: '/auth/login',
      payload: { email, password: PASSWORD },
    });
    expect(login.statusCode, login.payload).toBe(200);
    const body = json<{ session: { accessToken: string } }>(login);
    return { email, bearer: { authorization: `Bearer ${body.session.accessToken}` } };
  }

  it('⚑ reports the organization immediately, and flags the stale token', async () => {
    const instance = await freshInstance();
    try {
      const first = await onboard(instance);

      // Deliberately keeping the *login* token — the one minted before the
      // organization existed.
      await instance.inject({
        method: 'POST',
        url: '/auth/orgs',
        headers: first.bearer,
        payload: { name: 'Acme Billing' },
      });

      const me = json<{
        org: { role: string } | null;
        permissions: string[];
        staleToken: boolean;
      }>(await instance.inject({ method: 'GET', url: '/auth/me', headers: first.bearer }));

      // Live truth: you own an organization, whatever your token believes. An
      // earlier version read the claims and answered `org: null, permissions: []`
      // seconds after a successful creation, which is correct about the credential
      // and useless to anyone reading it.
      expect(me.org).toMatchObject({ role: 'owner' });
      expect(me.permissions).toEqual(['*']);
      // ⚑ And the flag that says why the API will still refuse those permissions.
      expect(me.staleToken).toBe(true);
    } finally {
      await instance.close();
    }
  });

  it('clears staleToken once the token catches up', async () => {
    const instance = await freshInstance();
    try {
      const first = await onboard(instance);
      const created = await instance.inject({
        method: 'POST',
        url: '/auth/orgs',
        headers: first.bearer,
        payload: { name: 'Acme Billing' },
      });
      const fresh = json<{ accessToken: string }>(created).accessToken;

      const me = json<{ staleToken: boolean; permissions: string[] }>(
        await instance.inject({
          method: 'GET',
          url: '/auth/me',
          headers: { authorization: `Bearer ${fresh}` },
        }),
      );

      // The create response hands back a token that already knows, so a client
      // that uses it never sees the stale state at all.
      expect(me.staleToken).toBe(false);
      expect(me.permissions).toEqual(['*']);
    } finally {
      await instance.close();
    }
  });

  it('⚑ makes the first user the owner of the organization they create', async () => {
    const instance = await freshInstance();
    try {
      const first = await onboard(instance);

      const created = await instance.inject({
        method: 'POST',
        url: '/auth/orgs',
        headers: first.bearer,
        payload: { name: 'Acme Billing' },
      });

      expect(created.statusCode, created.payload).toBe(201);
      const body = json<{ org: { id: string; slug: string }; role: string; accessToken: string }>(
        created,
      );
      expect(body.role).toBe('owner');
      expect(body.org.slug).toBe('acme-billing');

      // The response carries a token that already knows about the new org, so a
      // client never has to guess when its permissions became real.
      const me = json<{ org: { name: string; role: string } | null; permissions: string[] }>(
        await instance.inject({
          method: 'GET',
          url: '/auth/me',
          headers: { authorization: `Bearer ${body.accessToken}` },
        }),
      );
      expect(me.org).toMatchObject({ name: 'Acme Billing', role: 'owner' });
      expect(me.permissions).toEqual(['*']);
    } finally {
      await instance.close();
    }
  });

  it('⚑ shuts the door behind the first user', async () => {
    const instance = await freshInstance();
    try {
      const first = await onboard(instance);
      await instance.inject({
        method: 'POST',
        url: '/auth/orgs',
        headers: first.bearer,
        payload: { name: 'Acme Billing' },
      });

      const second = await onboard(instance);
      const attempt = await instance.inject({
        method: 'POST',
        url: '/auth/orgs',
        headers: second.bearer,
        payload: { name: 'Not Yours' },
      });

      // Everyone after the first joins by invitation.
      expect(attempt.statusCode).toBe(403);
    } finally {
      await instance.close();
    }
  });

  it('a user with no organization is authenticated, not rejected', async () => {
    const instance = await freshInstance();
    try {
      const user = await onboard(instance);

      const me = json<{ org: null; permissions: string[] }>(
        await instance.inject({ method: 'GET', url: '/auth/me', headers: user.bearer }),
      );
      expect(me.org).toBeNull();
      expect(me.permissions).toEqual([]);

      // ⚑ Authenticated but tenant-less. Anything org-scoped refuses, and the
      // client's move is to offer to create one — not to send them back to login.
      const members = await instance.inject({
        method: 'GET',
        url: '/auth/orgs/current/members',
        headers: user.bearer,
      });
      expect(members.statusCode).toBe(403);
    } finally {
      await instance.close();
    }
  });

  it('invites a member, who joins with the granted role', async () => {
    const instance = await freshInstance();
    try {
      const ownerUser = await onboard(instance);
      await instance.inject({
        method: 'POST',
        url: '/auth/orgs',
        headers: ownerUser.bearer,
        payload: { name: 'Acme Billing' },
      });
      // The owner's bearer is stale now; take the fresh one.
      const refreshed = await onboard(instance, ownerUser.email);

      const inviteeEmail = freshEmail();
      const invited = await instance.inject({
        method: 'POST',
        url: '/auth/orgs/current/invites',
        headers: refreshed.bearer,
        payload: { email: inviteeEmail, role: 'member' },
      });
      expect(invited.statusCode, invited.payload).toBe(202);

      const inviteToken = (await mailpitFind(inviteeEmail)).Text.match(/token=([^\s&]+)/)?.[1];
      const invitee = await onboard(instance, inviteeEmail);

      const accepted = await instance.inject({
        method: 'POST',
        url: '/auth/invites/accept',
        headers: invitee.bearer,
        payload: { token: inviteToken },
      });
      expect(accepted.statusCode, accepted.payload).toBe(200);
      expect(json<{ role: string }>(accepted).role).toBe('member');

      const members = json<{ members: Array<{ role: string }> }>(
        await instance.inject({
          method: 'GET',
          url: '/auth/orgs/current/members',
          headers: refreshed.bearer,
        }),
      );
      expect(members.members).toHaveLength(2);
    } finally {
      await instance.close();
    }
  });

  it('⚑ refuses a member the permissions of an admin', async () => {
    const instance = await freshInstance();
    try {
      const ownerUser = await onboard(instance);
      await instance.inject({
        method: 'POST',
        url: '/auth/orgs',
        headers: ownerUser.bearer,
        payload: { name: 'Acme Billing' },
      });
      const owner = await onboard(instance, ownerUser.email);

      const inviteeEmail = freshEmail();
      await instance.inject({
        method: 'POST',
        url: '/auth/orgs/current/invites',
        headers: owner.bearer,
        payload: { email: inviteeEmail, role: 'member' },
      });
      const inviteToken = (await mailpitFind(inviteeEmail)).Text.match(/token=([^\s&]+)/)?.[1];
      const invitee = await onboard(instance, inviteeEmail);
      await instance.inject({
        method: 'POST',
        url: '/auth/invites/accept',
        headers: invitee.bearer,
        payload: { token: inviteToken },
      });

      // Fresh token, now carrying `member`.
      const asMember = await onboard(instance, inviteeEmail);
      const attempt = await instance.inject({
        method: 'POST',
        url: '/auth/orgs/current/invites',
        headers: asMember.bearer,
        payload: { email: freshEmail(), role: 'member' },
      });

      // `member` holds org:read and member:read, and nothing else.
      expect(attempt.statusCode).toBe(403);
      expect(json<{ error: { code: string } }>(attempt).error.code).toBe('PERMISSION_DENIED');
    } finally {
      await instance.close();
    }
  });

  it('⚑ refuses to remove the only owner', async () => {
    const instance = await freshInstance();
    try {
      const ownerUser = await onboard(instance);
      await instance.inject({
        method: 'POST',
        url: '/auth/orgs',
        headers: ownerUser.bearer,
        payload: { name: 'Acme Billing' },
      });
      const owner = await onboard(instance, ownerUser.email);

      const members = json<{ members: Array<{ membershipId: string; role: string }> }>(
        await instance.inject({
          method: 'GET',
          url: '/auth/orgs/current/members',
          headers: owner.bearer,
        }),
      );
      const ownerMembership = members.members.find((m) => m.role === 'owner')!;

      const attempt = await instance.inject({
        method: 'DELETE',
        url: `/auth/orgs/current/members/${ownerMembership.membershipId}`,
        headers: owner.bearer,
      });

      // No permission repairs an ownerless org, so this is a refusal.
      expect(attempt.statusCode).toBe(409);
    } finally {
      await instance.close();
    }
  });
});
