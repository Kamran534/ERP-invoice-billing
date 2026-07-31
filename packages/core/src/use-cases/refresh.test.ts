/**
 * Refresh rotation (AUTH-MODULE-PLAN.md §5.5).
 *
 * The most consequential logic in the system, and the place where getting it
 * subtly wrong logs real users out or leaves a thief signed in. Run entirely on
 * in-memory ports with a fake clock — no database, no containers.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createHash } from 'node:crypto';
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
import { defineAuthConfig, type AuthConfig } from '../config.js';
import type { AuthContext } from '../context.js';
import { isAuthError } from '../errors.js';
import { rotateRefreshToken, type RefreshDeps } from './refresh.js';

const sha256 = (input: string): Uint8Array =>
  new Uint8Array(createHash('sha256').update(input).digest());

let repos: InMemoryRepos;
let clock: FakeClock;
let mailer: ReturnType<typeof createRecordingMailer>;
let events: ReturnType<typeof createRecordingEventBus>;
let ctx: AuthContext;

// Rebuilt per test so the secret counter restarts — a failure message naming
// `secret_2` should mean the same thing in every test.
let deps: RefreshDeps;

const baseConfig = (overrides: Partial<AuthConfig['tokens']['refresh']> = {}): AuthConfig =>
  defineAuthConfig({
    appName: 'Acme Billing',
    urls: { appOrigin: 'https://app.acme.test' },
    tokens: {
      issuer: 'https://auth.acme.test',
      audience: ['api.acme.test'],
      refresh: overrides,
    },
  });

function buildContext(config: AuthConfig): AuthContext {
  return {
    config,
    repos,
    clock,
    random: createSequentialRandom(),
    hasher: createFakeHasher(),
    tokens: createFakeTokenService(),
    mailer,
    events,
    logger: silentLogger,
  };
}

/** A live session with one unused refresh token, as login would leave it. */
async function signIn(options: { passwordUpdatedAt?: Date } = {}) {
  const user = await repos.users.create({
    email: 'ada@example.test',
    status: 'active',
    passwordHash: 'fake:pw',
    passwordAlgo: 'argon2id',
  });
  if (options.passwordUpdatedAt) {
    await repos.users.update(user.id, { passwordUpdatedAt: options.passwordUpdatedAt });
  }

  const now = clock.now();
  const session = await repos.sessions.create({
    id: '',
    userId: user.id,
    orgId: null,
    idleExpiresAt: new Date(now.getTime() + 30 * 86_400_000),
    absoluteExpiresAt: new Date(now.getTime() + 90 * 86_400_000),
    amr: ['pwd'],
    mfaSatisfiedAt: null,
    impersonatedBy: null,
  });

  const secret = deps.newSecret();
  await repos.refreshTokens.issue(
    session.id,
    sha256(secret),
    new Date(now.getTime() + 30 * 86_400_000),
  );
  return { user, session, secret };
}

const rotate = (secret: string, ctxOverride = ctx) =>
  rotateRefreshToken(ctxOverride, deps, {
    presentedSecret: secret,
    ip: '203.0.113.7',
    userAgent: 'vitest',
  });

/** The default `inFlightWindowMs`. */
const IN_FLIGHT_MS = 2_000;

/**
 * Presenting a spent token *after* the in-flight window — which is what a replay
 * actually looks like. Inside the window the same call is a multi-tab race, so a
 * theft test that does not move the clock is testing the wrong rule.
 */
const replay = (secret: string, ctxOverride = ctx) => {
  clock.advance(IN_FLIGHT_MS + 1);
  return rotate(secret, ctxOverride);
};

async function expectAuthError(promise: Promise<unknown>, code: string): Promise<void> {
  await expect(promise).rejects.toSatisfy((error: unknown) => {
    if (!isAuthError(error)) throw new Error(`expected AuthError, got ${String(error)}`);
    if (error.code !== code) throw new Error(`expected ${code}, got ${error.code}`);
    return true;
  });
}

beforeEach(() => {
  clock = new FakeClock();
  // ⚑ The doubles must share the fake clock, or every expiry is judged against
  // wall-clock and each test fails for a reason unrelated to the code.
  repos = createInMemoryRepos(clock);
  mailer = createRecordingMailer();
  events = createRecordingEventBus();
  deps = createTestCryptoDeps();
  ctx = buildContext(baseConfig());
});

// ───────────────────────────────────────────────────────────────────────────
describe('the happy path', () => {
  it('returns a new access token and a new refresh token', async () => {
    const { secret } = await signIn();
    const result = await rotate(secret);

    expect(result.accessToken).toBeTruthy();
    expect(result.refreshToken).toBeTruthy();
    expect(result.expiresIn).toBe(600);
    // ⚑ The successor must differ, or nothing has rotated.
    expect(result.refreshToken).not.toBe(secret);
  });

  it('kills the presented token, so it cannot be used twice', async () => {
    const { secret } = await signIn();
    await rotate(secret);
    // Second presentation is reuse, which returns a deliberately bare 401.
    await expectAuthError(replay(secret), 'INVALID_REFRESH_TOKEN');
  });

  it('links predecessor to successor so the chain can be walked', async () => {
    const { secret } = await signIn();
    await rotate(secret);
    const tokens = repos.refreshTokens.all();
    const [first, second] = tokens;
    expect(first?.replacedById).toBe(second?.id);
  });

  it('rotates repeatedly, each token valid exactly once', async () => {
    const { secret } = await signIn();
    let current = secret;
    for (let i = 0; i < 20; i += 1) {
      current = (await rotate(current)).refreshToken;
    }
    await expect(rotate(current)).resolves.toBeTruthy();
  });

  it('slides the idle expiry without moving the absolute cap', async () => {
    const { session, secret } = await signIn();
    const absoluteBefore = session.absoluteExpiresAt.getTime();

    clock.advance(86_400_000);
    const result = await rotate(secret);

    expect(result.session.idleExpiresAt.getTime()).toBeGreaterThan(
      session.idleExpiresAt.getTime(),
    );
    expect(result.session.absoluteExpiresAt.getTime()).toBe(absoluteBefore);
  });

  it('never slides the idle window past the absolute cap', async () => {
    const { user } = await signIn();
    const now = clock.now();
    // A session with only an hour of absolute life left.
    const session = await repos.sessions.create({
      id: '',
      userId: user.id,
      orgId: null,
      idleExpiresAt: new Date(now.getTime() + 30 * 86_400_000),
      absoluteExpiresAt: new Date(now.getTime() + 3_600_000),
      amr: ['pwd'],
      mfaSatisfiedAt: null,
      impersonatedBy: null,
    });
    const secret = deps.newSecret();
    await repos.refreshTokens.issue(session.id, sha256(secret), new Date(now.getTime() + 86_400_000));

    const result = await rotate(secret);
    // Otherwise the idle window would quietly outlive the hard cap.
    expect(result.session.idleExpiresAt.getTime()).toBe(session.absoluteExpiresAt.getTime());
  });

  it('records the rotation in the audit log', async () => {
    const { secret } = await signIn();
    await rotate(secret);
    expect(repos.audit.eventsOfType('auth.refresh_rotated')).toHaveLength(1);
  });

  it('re-reads the session on every rotation, which is how revocation lands', async () => {
    const { secret } = await signIn();
    const tokens = ctx.tokens as ReturnType<typeof createFakeTokenService>;
    await rotate(secret);
    // Claims are rebuilt from the database each time rather than copied forward.
    expect(tokens.minted).toHaveLength(1);
    expect(tokens.minted[0]?.sid).toBeTruthy();
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('reuse is treated as theft', () => {
  it('destroys the whole session, not just the replayed token', async () => {
    const { session, secret } = await signIn();
    const successor = (await rotate(secret)).refreshToken;

    await expectAuthError(replay(secret), 'INVALID_REFRESH_TOKEN');

    // ⚑ The successor must die too. Revoking only the replayed token would leave
    // the thief's copy working, which is the whole failure this prevents.
    const dead = await repos.sessions.findById(session.id);
    expect(dead?.revokedAt).not.toBeNull();
    expect(dead?.revokedReason).toBe('reuse_detected');
    await expectAuthError(rotate(successor), 'SESSION_REVOKED');
  });

  it('says nothing about why', async () => {
    const { secret } = await signIn();
    await rotate(secret);

    // Identical to an unknown token. Telling an attacker the alarm exists tells
    // them which token tripped it.
    const unknownMessage = await rotate('rt_never_issued').catch((e: Error) => e.message);
    const reuseMessage = await replay(secret).catch((e: Error) => e.message);
    expect(reuseMessage).toBe(unknownMessage);
    expect(reuseMessage).not.toMatch(/reuse|theft|detect/i);
  });

  it('audits at high severity and emits a security event', async () => {
    const { secret } = await signIn();
    await rotate(secret);
    await replay(secret).catch(() => undefined);

    const [entry] = repos.audit.eventsOfType('auth.refresh_reuse_detected');
    expect(entry).toBeTruthy();
    expect(entry?.outcome).toBe('failure');
    expect(entry?.metadata?.['severity']).toBe('high');
    expect(events.published.map((e) => e.type)).toContain('security.refresh_reuse_detected');
  });

  it('emails the user out of band', async () => {
    const { secret } = await signIn();
    await rotate(secret);
    await replay(secret).catch(() => undefined);

    expect(mailer.sent).toHaveLength(1);
    expect(mailer.sent[0]?.to).toBe('ada@example.test');
    expect(mailer.sent[0]?.text).toMatch(/signed that session out/i);
  });

  it('leaves other sessions alone by default', async () => {
    const { user, secret } = await signIn();
    const other = await repos.sessions.create({
      id: '',
      userId: user.id,
      orgId: null,
      idleExpiresAt: new Date(clock.now().getTime() + 86_400_000),
      absoluteExpiresAt: new Date(clock.now().getTime() + 86_400_000),
      amr: ['pwd'],
      mfaSatisfiedAt: null,
      impersonatedBy: null,
    });

    await rotate(secret);
    await replay(secret).catch(() => undefined);

    // Signing the user out everywhere is available but not the default: one
    // compromised device should not necessarily end every session.
    expect((await repos.sessions.findById(other.id))?.revokedAt).toBeNull();
  });

  it('kills every session when reuseRevokesAllSessions is on', async () => {
    ctx = buildContext(baseConfig({ reuseRevokesAllSessions: true }));
    const { user, secret } = await signIn();
    const other = await repos.sessions.create({
      id: '',
      userId: user.id,
      orgId: null,
      idleExpiresAt: new Date(clock.now().getTime() + 86_400_000),
      absoluteExpiresAt: new Date(clock.now().getTime() + 86_400_000),
      amr: ['pwd'],
      mfaSatisfiedAt: null,
      impersonatedBy: null,
    });

    await rotate(secret);
    await replay(secret).catch(() => undefined);

    expect((await repos.sessions.findById(other.id))?.revokedAt).not.toBeNull();
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('the in-flight window', () => {
  it('⚑ treats a second presentation of the same token as a race, not theft', async () => {
    const { session, secret } = await signIn();
    await rotate(secret);

    // This is the case CI caught. `claim` reports `reuse` for any already-spent
    // row, including a sibling request that arrived a moment after the winner
    // committed — and calling that theft signs a user out for opening a tab.
    await expectAuthError(rotate(secret), 'REFRESH_IN_PROGRESS');
    expect((await repos.sessions.findById(session.id))?.revokedAt).toBeNull();
  });

  it('gives the loser a 409 and nothing else', async () => {
    const { secret } = await signIn();
    await rotate(secret);
    const error = await rotate(secret).catch((e) => e);

    // A thief inside the window gains a retry, not a token — which is why the
    // window costs so little.
    expect(error.status).toBe(409);
    expect(error.details).toBeUndefined();
  });

  it('becomes theft once the window closes', async () => {
    const { session, secret } = await signIn();
    await rotate(secret);

    clock.advance(IN_FLIGHT_MS + 1);
    await expectAuthError(rotate(secret), 'INVALID_REFRESH_TOKEN');
    expect((await repos.sessions.findById(session.id))?.revokedReason).toBe('reuse_detected');
  });

  it('records the race without raising a security event', async () => {
    const { secret } = await signIn();
    await rotate(secret);
    await rotate(secret).catch(() => undefined);

    const [entry] = repos.audit.eventsOfType('auth.refresh_concurrent');
    expect(entry?.metadata).toMatchObject({ inFlight: true });
    expect(repos.audit.eventsOfType('auth.refresh_reuse_detected')).toHaveLength(0);
    expect(events.published.map((e) => e.type)).not.toContain('security.refresh_reuse_detected');
    expect(mailer.sent).toHaveLength(0);
  });

  it('can be switched off, at the cost of the multi-tab race', async () => {
    ctx = buildContext(baseConfig({ inFlightWindowMs: 0 }));
    const { secret } = await signIn();
    await rotate(secret);

    await expectAuthError(rotate(secret), 'INVALID_REFRESH_TOKEN');
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('the grace window', () => {
  // Pinned to 0 throughout, so these exercise the predecessor rule rather than
  // being forgiven by the in-flight window a step earlier.
  const graceConfig = (reuseGraceMs: number) =>
    buildContext(baseConfig({ reuseGraceMs, inFlightWindowMs: 0 }));

  it('is off by default, so a re-presented predecessor is theft', async () => {
    ctx = buildContext(baseConfig({ inFlightWindowMs: 0 }));
    const { secret } = await signIn();
    await rotate(secret);
    await expectAuthError(rotate(secret), 'INVALID_REFRESH_TOKEN');
  });

  it('forgives the immediate predecessor inside the window', async () => {
    ctx = graceConfig(5_000);
    const { secret } = await signIn();
    await rotate(secret);

    clock.advance(1_000);
    // 409, not theft: the client retries and picks up the successor.
    await expectAuthError(rotate(secret), 'REFRESH_IN_PROGRESS');
  });

  it('stops forgiving once the window closes', async () => {
    ctx = graceConfig(5_000);
    const { secret } = await signIn();
    await rotate(secret);

    clock.advance(6_000);
    await expectAuthError(rotate(secret), 'INVALID_REFRESH_TOKEN');
  });

  it('stops forgiving once the successor has itself been used', async () => {
    // ⚑ Grace applies only while the chain has not moved on. Once the successor is
    // spent, a re-presented predecessor is indistinguishable from a replay.
    ctx = graceConfig(10_000);
    const { secret } = await signIn();
    const successor = (await rotate(secret)).refreshToken;
    await rotate(successor);

    await expectAuthError(rotate(secret), 'INVALID_REFRESH_TOKEN');
  });

  it('never forgives deeper than one step', async () => {
    ctx = graceConfig(10_000);
    const { secret } = await signIn();
    const second = (await rotate(secret)).refreshToken;
    await rotate(second);

    // The grandparent is not the immediate predecessor of the live token.
    await expectAuthError(rotate(secret), 'INVALID_REFRESH_TOKEN');
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('rejections that are not theft', () => {
  it('rejects a token that was never issued', async () => {
    await signIn();
    await expectAuthError(rotate('rt_never_issued'), 'INVALID_REFRESH_TOKEN');
    expect(repos.audit.eventsOfType('auth.refresh_unknown')).toHaveLength(1);
  });

  it('rejects an expired refresh token', async () => {
    const { user } = await signIn();
    const now = clock.now();
    // A live session holding a token that has already expired. Advancing the clock
    // instead would trip the session's idle window first and test the wrong branch.
    const session = await repos.sessions.create({
      id: '',
      userId: user.id,
      orgId: null,
      idleExpiresAt: new Date(now.getTime() + 30 * 86_400_000),
      absoluteExpiresAt: new Date(now.getTime() + 90 * 86_400_000),
      amr: ['pwd'],
      mfaSatisfiedAt: null,
      impersonatedBy: null,
    });
    const secret = deps.newSecret();
    await repos.refreshTokens.issue(session.id, sha256(secret), new Date(now.getTime() - 1_000));

    await expectAuthError(rotate(secret), 'REFRESH_EXPIRED');
  });

  it('rejects a revoked session and does not raise theft', async () => {
    const { session, secret } = await signIn();
    await repos.sessions.revoke(session.id, 'logout');
    await repos.refreshTokens.revokeChain(session.id, 'logout');

    await expectAuthError(rotate(secret), 'SESSION_REVOKED');
    expect(repos.audit.eventsOfType('auth.refresh_reuse_detected')).toHaveLength(0);
  });

  it('rejects and revokes once the absolute cap passes', async () => {
    const { user } = await signIn();
    const now = clock.now();
    // The token must outlive the session, or the token-expiry check fires first
    // and we would be asserting on the wrong rejection. That ordering is correct —
    // a spent token is not worth a session lookup — so the test works around it.
    const session = await repos.sessions.create({
      id: '',
      userId: user.id,
      orgId: null,
      idleExpiresAt: new Date(now.getTime() + 90 * 86_400_000),
      absoluteExpiresAt: new Date(now.getTime() + 3_600_000),
      amr: ['pwd'],
      mfaSatisfiedAt: null,
      impersonatedBy: null,
    });
    const secret = deps.newSecret();
    await repos.refreshTokens.issue(
      session.id,
      sha256(secret),
      new Date(now.getTime() + 90 * 86_400_000),
    );

    clock.advance(2 * 3_600_000);
    await expectAuthError(rotate(secret), 'SESSION_EXPIRED');
    expect((await repos.sessions.findById(session.id))?.revokedReason).toBe('absolute_timeout');
  });

  it('rejects and revokes after the idle window', async () => {
    const { user } = await signIn();
    const now = clock.now();
    const session = await repos.sessions.create({
      id: '',
      userId: user.id,
      orgId: null,
      idleExpiresAt: new Date(now.getTime() + 60_000),
      absoluteExpiresAt: new Date(now.getTime() + 90 * 86_400_000),
      amr: ['pwd'],
      mfaSatisfiedAt: null,
      impersonatedBy: null,
    });
    const secret = deps.newSecret();
    await repos.refreshTokens.issue(session.id, sha256(secret), new Date(now.getTime() + 86_400_000));

    clock.advance(120_000);
    await expectAuthError(rotate(secret), 'SESSION_IDLE_TIMEOUT');
    expect((await repos.sessions.findById(session.id))?.revokedReason).toBe('idle_timeout');
  });

  it('rejects a suspended user mid-session', async () => {
    const { user, session, secret } = await signIn();
    await repos.users.update(user.id, { status: 'suspended' });

    await expectAuthError(rotate(secret), 'ACCOUNT_INACTIVE');
    expect((await repos.sessions.findById(session.id))?.revokedReason).toBe('suspended');
  });

  it('rejects a session that predates a password change', async () => {
    // ⚑ Whoever holds this session may be exactly who the password change was
    // defending against.
    const { user, session, secret } = await signIn();
    clock.advance(1_000);
    await repos.users.update(user.id, { passwordUpdatedAt: new Date(clock.now()) });

    await expectAuthError(rotate(secret), 'CREDENTIALS_CHANGED');
    expect((await repos.sessions.findById(session.id))?.revokedReason).toBe('password_change');
  });

  it('accepts a session created after the last password change', async () => {
    const { secret } = await signIn({ passwordUpdatedAt: new Date('2025-01-01T00:00:00Z') });
    await expect(rotate(secret)).resolves.toBeTruthy();
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('failures are contained', () => {
  it('still revokes when the notification email cannot be sent', async () => {
    // Mail is fail-soft, but containment must have happened regardless.
    const failing = {
      ...ctx,
      mailer: {
        async send() {
          throw new Error('smtp down');
        },
      },
    };
    const { session, secret } = await signIn();
    await rotate(secret, failing as AuthContext);
    await replay(secret, failing as AuthContext).catch(() => undefined);

    expect((await repos.sessions.findById(session.id))?.revokedReason).toBe('reuse_detected');
  });

  it('does not let an event subscriber break the flow', async () => {
    const exploding = {
      ...ctx,
      events: {
        async publish() {
          throw new Error('subscriber exploded');
        },
      },
    };
    const { session, secret } = await signIn();
    await rotate(secret, exploding as AuthContext);
    await replay(secret, exploding as AuthContext).catch(() => undefined);

    expect((await repos.sessions.findById(session.id))?.revokedReason).toBe('reuse_detected');
  });
});
