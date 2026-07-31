/**
 * Session issuance and teardown (AUTH-MODULE-PLAN.md §5.5.2, §5.6).
 *
 * `issueSession` is the only place a session is created, so the properties tested
 * here — the absolute cap, the first refresh token, the amr recorded — hold for
 * password login, OTP login and MFA completion alike.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  FakeClock,
  createFakeHasher,
  createFakeTokenService,
  createInMemoryRepos,
  createRecordingEventBus,
  createRecordingMailer,
  createSequentialRandom,
  createTestCryptoDeps,
  silentLogger,
  type InMemoryRepos,
} from '@auth/testing';
import { defineAuthConfig, type AuthConfig, type AuthConfigInput } from '../config.js';
import type { AuthContext } from '../context.js';
import { isAuthError, type AuthErrorCode } from '../errors.js';
import type { User } from '../ports.js';
import type { CryptoDeps } from './deps.js';
import { issueSession, listSessions, logout, logoutAll, revokeSession } from './session.js';

let repos: InMemoryRepos;
let clock: FakeClock;
let events: ReturnType<typeof createRecordingEventBus>;
let deps: CryptoDeps;
let ctx: AuthContext;
let user: User;

const config = (overrides: Partial<AuthConfigInput> = {}): AuthConfig =>
  defineAuthConfig({
    appName: 'Acme Billing',
    urls: { appOrigin: 'https://app.acme.test' },
    tokens: { issuer: 'https://auth.acme.test', audience: ['api.acme.test'] },
    email: { fromAddress: 'no-reply@acme.test' },
    ...overrides,
  });

function buildContext(cfg: AuthConfig): AuthContext {
  return {
    config: cfg,
    repos,
    clock,
    random: createSequentialRandom(),
    hasher: createFakeHasher(),
    tokens: createFakeTokenService(),
    mailer: createRecordingMailer(),
    events,
    logger: silentLogger,
  };
}

const request = { ip: '203.0.113.7', userAgent: 'vitest' };

const issue = (ctxOverride = ctx) =>
  issueSession(ctxOverride, deps, { user, amr: ['pwd'], ...request });

async function expectAuthError(promise: Promise<unknown>, code: AuthErrorCode): Promise<void> {
  await expect(promise).rejects.toSatisfy((error: unknown) => {
    if (!isAuthError(error)) throw new Error(`expected AuthError, got ${String(error)}`);
    if (error.code !== code) throw new Error(`expected ${code}, got ${error.code}`);
    return true;
  });
}

beforeEach(async () => {
  clock = new FakeClock();
  repos = createInMemoryRepos(clock);
  events = createRecordingEventBus();
  deps = createTestCryptoDeps();
  ctx = buildContext(config());
  user = await repos.users.create({ email: 'ada@example.test', status: 'active' });
});

// ───────────────────────────────────────────────────────────────────────────
describe('issuing a session', () => {
  it('returns a token pair and persists the session', async () => {
    const issued = await issue();

    expect(issued.accessToken).toBeTruthy();
    expect(issued.refreshToken).toBeTruthy();
    expect(issued.expiresIn).toBeGreaterThan(0);
    expect(repos.sessions.all()).toHaveLength(1);
    expect(repos.refreshTokens.all()).toHaveLength(1);
  });

  it('sets both windows from the same instant', async () => {
    const now = clock.now();
    const { session } = await issue();

    expect(session.idleExpiresAt).toEqual(new Date(now.getTime() + 30 * 86_400_000));
    expect(session.absoluteExpiresAt).toEqual(new Date(now.getTime() + 90 * 86_400_000));
  });

  it('never lets the idle window outlive the absolute cap', async () => {
    // A deployment that configures idle > absolute has said something incoherent;
    // clamping is the only reading that does not silently extend the hard cap.
    const odd = buildContext(
      config({
        tokens: {
          issuer: 'https://auth.acme.test',
          audience: ['api.acme.test'],
          refresh: { idleTtl: '90d', absoluteTtl: '7d' },
        },
      }),
    );
    const { session } = await issue(odd);

    expect(session.idleExpiresAt).toEqual(session.absoluteExpiresAt);
  });

  it('stores the refresh token as a hash, not the secret', async () => {
    const issued = await issue();
    const [row] = repos.refreshTokens.all();

    expect(row?.hash).toBe(deps.hex(deps.sha256(issued.refreshToken)));
    expect(JSON.stringify(row)).not.toContain(issued.refreshToken);
  });

  it('records the factors that were actually used', async () => {
    const issued = await issueSession(ctx, deps, {
      user,
      amr: ['pwd', 'totp'],
      mfaSatisfiedAt: clock.now(),
      ...request,
    });

    expect(issued.session.amr).toEqual(['pwd', 'totp']);
    expect(issued.session.mfaSatisfiedAt).toEqual(clock.now());
  });

  it('stamps lastLoginAt', async () => {
    await issue();
    expect((await repos.users.findById(user.id))?.lastLoginAt).toEqual(clock.now());
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('logout', () => {
  it('revokes the session and its refresh chain', async () => {
    const { session } = await issue();

    await logout(ctx, { sessionId: session.id, ...request });

    expect((await repos.sessions.findById(session.id))?.revokedAt).not.toBeNull();
    expect(repos.refreshTokens.all().every((t) => t.revokedAt !== null)).toBe(true);
  });

  it('⚑ is idempotent and silent about an unknown session', async () => {
    // A retried logout, or one for a session already killed by reuse detection,
    // must look exactly like the happy path.
    await expect(
      logout(ctx, { sessionId: 'never-existed', ...request }),
    ).resolves.toBeUndefined();
    expect(repos.audit.eventsOfType('auth.logout')).toHaveLength(0);
  });

  it('audits and emits once', async () => {
    const { session } = await issue();
    await logout(ctx, { sessionId: session.id, ...request });

    expect(repos.audit.eventsOfType('auth.logout')).toHaveLength(1);
    expect(events.published.map((e) => e.type)).toContain('user.logged_out');
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('logout everywhere', () => {
  it('revokes every session and every chain', async () => {
    await issue();
    await issue();
    await issue();

    const { revokedSessions } = await logoutAll(ctx, { userId: user.id, ...request });

    expect(revokedSessions).toBe(3);
    expect(repos.sessions.all().every((s) => s.revokedAt !== null)).toBe(true);
    expect(repos.refreshTokens.all().every((t) => t.revokedAt !== null)).toBe(true);
  });

  it('can keep the caller signed in — "sign out my other devices"', async () => {
    const mine = await issue();
    await issue();

    await logoutAll(ctx, { userId: user.id, exceptSessionId: mine.session.id, ...request });

    expect((await repos.sessions.findById(mine.session.id))?.revokedAt).toBeNull();
    expect(await repos.sessions.listActive(user.id)).toHaveLength(1);
  });

  it('⚑ also revokes trusted devices', async () => {
    await issue();
    await repos.trustedDevices.create({
      userId: user.id,
      hash: deps.sha256('device-token'),
      label: 'Laptop',
      expiresAt: new Date(clock.now().getTime() + 30 * 86_400_000),
      mfaSatisfiedAt: clock.now(),
    });

    await logoutAll(ctx, { userId: user.id, ...request });

    // Leaving a device that skips 2FA would make "sign out everywhere" a good deal
    // less final than it reads (§5.4.5).
    expect(await repos.trustedDevices.listForUser(user.id)).toHaveLength(0);
  });

  it('leaves other users alone', async () => {
    const other = await repos.users.create({ email: 'bob@example.test', status: 'active' });
    await issue();
    await issueSession(ctx, deps, { user: other, amr: ['pwd'], ...request });

    await logoutAll(ctx, { userId: user.id, ...request });

    expect(await repos.sessions.listActive(other.id)).toHaveLength(1);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('the device list', () => {
  it('marks which one the caller is using', async () => {
    const mine = await issue();
    await issue();

    const listed = await listSessions(ctx, user.id, mine.session.id);

    expect(listed).toHaveLength(2);
    expect(listed.filter((s) => s.current)).toHaveLength(1);
    expect(listed.find((s) => s.current)?.id).toBe(mine.session.id);
  });

  it('hides revoked sessions', async () => {
    const first = await issue();
    await issue();
    await logout(ctx, { sessionId: first.session.id, ...request });

    expect(await listSessions(ctx, user.id, null)).toHaveLength(1);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('revoking one session by id', () => {
  it('revokes the caller\'s own session', async () => {
    const target = await issue();

    await revokeSession(ctx, { userId: user.id, sessionId: target.session.id, ...request });

    expect((await repos.sessions.findById(target.session.id))?.revokedAt).not.toBeNull();
    expect(repos.audit.eventsOfType('session.revoked_by_admin')).toHaveLength(1);
  });

  it('⚑ answers NOT_FOUND for someone else\'s session, not FORBIDDEN', async () => {
    const other = await repos.users.create({ email: 'bob@example.test', status: 'active' });
    const theirs = await issueSession(ctx, deps, { user: other, amr: ['pwd'], ...request });

    // Ownership is checked before existence is admitted. A 403 for "exists but not
    // yours" versus a 404 for "no such id" would let anyone enumerate session ids.
    await expectAuthError(
      revokeSession(ctx, { userId: user.id, sessionId: theirs.session.id, ...request }),
      'NOT_FOUND',
    );
    expect((await repos.sessions.findById(theirs.session.id))?.revokedAt).toBeNull();
  });

  it('answers identically for an id that never existed', async () => {
    await expectAuthError(
      revokeSession(ctx, { userId: user.id, sessionId: 'never-existed', ...request }),
      'NOT_FOUND',
    );
  });
});
