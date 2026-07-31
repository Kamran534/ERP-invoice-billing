/**
 * Password login (AUTH-MODULE-PLAN.md §5.3) and the branch into 2FA (§5.4).
 *
 * The tests that matter most here are the boring-looking ones: that four quite
 * different failure conditions all produce the identical response, and that the
 * expensive work happens on the paths where skipping it would be a timing oracle.
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
import { login, type LoginResult } from './login.js';
import type { CryptoDeps } from './deps.js';

let repos: InMemoryRepos;
let clock: FakeClock;
let hasher: ReturnType<typeof createFakeHasher>;
let events: ReturnType<typeof createRecordingEventBus>;
let deps: CryptoDeps;
let ctx: AuthContext;

const config = (overrides: Partial<AuthConfigInput> = {}): AuthConfig =>
  defineAuthConfig({
    appName: 'Acme Billing',
    urls: { appOrigin: 'https://app.acme.test' },
    tokens: { issuer: 'https://auth.acme.test', audience: ['api.acme.test'] },
    email: { fromAddress: 'no-reply@acme.test', requireVerification: false },
    mfa: { enforce: 'optional' },
    ...overrides,
  });

function buildContext(cfg: AuthConfig): AuthContext {
  return {
    config: cfg,
    repos,
    clock,
    random: createSequentialRandom(),
    hasher,
    tokens: createFakeTokenService(),
    mailer: createRecordingMailer(),
    events,
    logger: silentLogger,
  };
}

/** An ordinary active account with a current-generation password hash. */
async function seedUser(patch: Parameters<InMemoryRepos['users']['update']>[1] = {}) {
  const user = await repos.users.create({
    email: 'ada@example.test',
    status: 'active',
    emailVerifiedAt: clock.now(),
    passwordHash: 'fake:correct-horse',
    passwordAlgo: 'argon2id',
  });
  return Object.keys(patch).length ? repos.users.update(user.id, patch) : user;
}

const attempt = (
  overrides: { email?: string; password?: string; trustedDeviceToken?: string } = {},
  ctxOverride = ctx,
): Promise<LoginResult> =>
  login(ctxOverride, deps, {
    email: overrides.email ?? 'ada@example.test',
    password: overrides.password ?? 'correct-horse',
    trustedDeviceToken: overrides.trustedDeviceToken ?? null,
    ip: '203.0.113.7',
    userAgent: 'vitest',
  });

async function expectAuthError(promise: Promise<unknown>, code: AuthErrorCode): Promise<void> {
  await expect(promise).rejects.toSatisfy((error: unknown) => {
    if (!isAuthError(error)) throw new Error(`expected AuthError, got ${String(error)}`);
    if (error.code !== code) throw new Error(`expected ${code}, got ${error.code}`);
    return true;
  });
}

beforeEach(() => {
  clock = new FakeClock();
  repos = createInMemoryRepos(clock);
  hasher = createFakeHasher();
  events = createRecordingEventBus();
  deps = createTestCryptoDeps();
  ctx = buildContext(config());
});

// ───────────────────────────────────────────────────────────────────────────
describe('the happy path', () => {
  it('returns a session with a token pair', async () => {
    await seedUser();
    const result = await attempt();

    expect(result.status).toBe('authenticated');
    if (result.status !== 'authenticated') return;
    expect(result.session.accessToken).toBeTruthy();
    expect(result.session.refreshToken).toBeTruthy();
    expect(result.session.session.amr).toEqual(['pwd']);
    expect(result.mfaEnrollmentRequired).toBe(false);
  });

  it('is case-insensitive and trims the address, like the citext column', async () => {
    await seedUser();
    const result = await attempt({ email: '  Ada@Example.TEST  ' });
    expect(result.status).toBe('authenticated');
  });

  it('clears the failure counter, so yesterday\'s typos do not accumulate', async () => {
    const user = await seedUser();
    await repos.users.registerFailedLogin(user.id, 10, 900_000);
    await repos.users.registerFailedLogin(user.id, 10, 900_000);

    await attempt();

    expect((await repos.users.findById(user.id))?.failedLoginCount).toBe(0);
  });

  it('records the login and emits an event', async () => {
    await seedUser();
    await attempt();

    expect(repos.audit.eventsOfType('auth.login_succeeded')).toHaveLength(1);
    expect(events.published.map((e) => e.type)).toContain('user.logged_in');
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('enumeration resistance', () => {
  it('answers identically for an unknown address and a wrong password', async () => {
    await seedUser();

    const unknown = await attempt({ email: 'nobody@example.test' }).catch((e) => e);
    const wrong = await attempt({ password: 'wrong' }).catch((e) => e);

    expect(unknown.code).toBe('INVALID_CREDENTIALS');
    expect(wrong.code).toBe('INVALID_CREDENTIALS');
    expect(unknown.message).toBe(wrong.message);
    expect(unknown.status).toBe(wrong.status);
    // Nothing in `details` may differentiate them either — it is serialized out.
    expect(unknown.details).toEqual(wrong.details);
  });

  it('⚑ spends a full verify on the unknown-address path', async () => {
    await attempt({ email: 'nobody@example.test' }).catch(() => {});
    // Without this the unknown path returns in microseconds and the difference is
    // measurable across the internet — see §5.3 step 2.
    expect(hasher.dummyVerifies).toBe(1);
  });

  it('⚑ spends a full verify when the account exists but has no password', async () => {
    await seedUser({ passwordHash: null, passwordAlgo: null });

    await expectAuthError(attempt(), 'INVALID_CREDENTIALS');
    // A passkey-only account must not be detectable by being cheaper to reject.
    expect(hasher.dummyVerifies).toBe(1);
  });

  it('⚑ answers a deleted account exactly like a nonexistent one', async () => {
    await seedUser({ status: 'deleted' });

    await expectAuthError(attempt(), 'INVALID_CREDENTIALS');
    expect(hasher.dummyVerifies).toBe(1);
  });

  it('⚑ withholds EMAIL_NOT_VERIFIED until the password is proven', async () => {
    const ctxStrict = buildContext(
      config({ email: { fromAddress: 'no-reply@acme.test', requireVerification: true } }),
    );
    await seedUser({ emailVerifiedAt: null });

    // Wrong password on an unverified account looks like any other bad password.
    // Otherwise this endpoint enumerates half-built accounts, which are the ones
    // most worth attacking.
    await expectAuthError(attempt({ password: 'wrong' }, ctxStrict), 'INVALID_CREDENTIALS');
    await expectAuthError(attempt({}, ctxStrict), 'EMAIL_NOT_VERIFIED');
  });

  it('records why a login failed without returning it', async () => {
    await seedUser({ status: 'deleted' });
    await attempt().catch(() => {});

    const [event] = repos.audit.eventsOfType('auth.login_failed');
    expect(event?.metadata).toMatchObject({ reason: 'deleted' });
    expect(event?.outcome).toBe('failure');
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('account state', () => {
  it('refuses a suspended account with its own code', async () => {
    await seedUser({ status: 'suspended' });
    // Distinct on purpose: a suspended user needs to know to contact support, and
    // the state is one an administrator deliberately made visible.
    await expectAuthError(attempt(), 'ACCOUNT_SUSPENDED');
  });

  it('refuses while locked, even with the right password', async () => {
    await seedUser({ lockedUntil: new Date(clock.now().getTime() + 60_000) });
    await expectAuthError(attempt(), 'ACCOUNT_LOCKED');
  });

  it('⚑ does not spend a verify while locked', async () => {
    await seedUser({ lockedUntil: new Date(clock.now().getTime() + 60_000) });
    await attempt().catch(() => {});

    // The 423 already admits the account exists, so there is no timing signal left
    // to protect — and refusing early keeps a lockout from being a way to hold the
    // Argon2 semaphore open (§8.5).
    expect(hasher.dummyVerifies).toBe(0);
  });

  it('lets a lapsed lock expire', async () => {
    await seedUser({ lockedUntil: new Date(clock.now().getTime() + 60_000) });
    clock.advance(60_001);

    expect((await attempt()).status).toBe('authenticated');
  });

  it('carries Retry-After on the lockout', async () => {
    await seedUser({ lockedUntil: new Date(clock.now().getTime() + 60_000) });
    const error = await attempt().catch((e) => e);
    expect(error.retryAfter).toBeGreaterThan(0);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('lockout', () => {
  it('locks on the configured failure count', async () => {
    const strict = buildContext(config({ lockout: { maxFailures: 3, lockFor: '15m' } }));
    const user = await seedUser();

    await expectAuthError(attempt({ password: 'no' }, strict), 'INVALID_CREDENTIALS');
    await expectAuthError(attempt({ password: 'no' }, strict), 'INVALID_CREDENTIALS');
    // The third failure both fails and locks — the user is told, because they are
    // the one who has to wait.
    await expectAuthError(attempt({ password: 'no' }, strict), 'ACCOUNT_LOCKED');

    expect((await repos.users.findById(user.id))?.lockedUntil).not.toBeNull();
  });

  it('emits user.locked so an alert can fire', async () => {
    // 3 is the schema floor: a lower threshold locks people out for ordinary typos.
    const strict = buildContext(config({ lockout: { maxFailures: 3, lockFor: '15m' } }));
    await seedUser();
    for (let i = 0; i < 3; i += 1) await attempt({ password: 'no' }, strict).catch(() => {});

    expect(events.published.map((e) => e.type)).toContain('user.locked');
  });

  it('never locks an address that has no account', async () => {
    const strict = buildContext(config({ lockout: { maxFailures: 3, lockFor: '15m' } }));
    // Nothing to lock, and creating a record would make the endpoint an oracle
    // as well as a way to deny service to addresses that do not exist yet.
    for (let i = 0; i < 4; i += 1) {
      await expectAuthError(
        attempt({ email: 'nobody@example.test' }, strict),
        'INVALID_CREDENTIALS',
      );
    }
    // Still INVALID_CREDENTIALS on the fourth try, never ACCOUNT_LOCKED — which
    // would otherwise confirm the address by the shape of the refusal.
    expect(repos.users.all()).toHaveLength(0);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('lazy rehash', () => {
  it('upgrades a legacy hash while the plaintext is in hand', async () => {
    const user = await seedUser({ passwordHash: 'bcrypt:correct-horse', passwordAlgo: 'bcrypt' });
    // The fake hasher accepts `fake:` only, so teach it this one round trip.
    hasher.verify = async (plain, stored) =>
      stored === `bcrypt:${plain}` || stored === `fake:${plain}`;

    await attempt();

    const after = await repos.users.findById(user.id);
    expect(after?.passwordAlgo).toBe('argon2id');
    expect(after?.passwordHash).toBe('fake:correct-horse');
  });

  it('⚑ does not touch passwordUpdatedAt when rehashing', async () => {
    const user = await seedUser({ passwordHash: 'bcrypt:correct-horse', passwordAlgo: 'bcrypt' });
    hasher.verify = async (plain, stored) =>
      stored === `bcrypt:${plain}` || stored === `fake:${plain}`;
    const before = (await repos.users.findById(user.id))?.passwordUpdatedAt;

    clock.advance(60_000);
    await attempt();

    // Refresh (§5.5.3 step 10) kills every session predating passwordUpdatedAt.
    // Bumping it here would sign the user out of every other device for a change
    // they did not make.
    expect((await repos.users.findById(user.id))?.passwordUpdatedAt).toEqual(before);
  });

  it('still signs the user in when the rehash fails', async () => {
    await seedUser({ passwordHash: 'bcrypt:correct-horse', passwordAlgo: 'bcrypt' });
    hasher.verify = async (plain, stored) => stored === `bcrypt:${plain}`;
    hasher.hash = async () => {
      throw new Error('argon2 pool exhausted');
    };

    // The credential was already proven; a failed upgrade is an ops problem.
    expect((await attempt()).status).toBe('authenticated');
  });

  it('leaves a current hash alone', async () => {
    const user = await seedUser();
    await attempt();
    expect((await repos.users.findById(user.id))?.passwordHash).toBe('fake:correct-horse');
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('the branch into 2FA', () => {
  async function enrolTotp(userId: string) {
    const factor = await repos.mfa.addFactor({
      userId,
      type: 'totp',
      label: 'Phone',
      secretEnc: new Uint8Array([1, 2, 3]),
    });
    await repos.mfa.confirmFactor(factor.id, clock.now());
    return factor;
  }

  it('returns a challenge instead of a session', async () => {
    const user = await seedUser();
    await enrolTotp(user.id);

    const result = await attempt();

    expect(result.status).toBe('mfa_required');
    if (result.status !== 'mfa_required') return;
    expect(result.mfaToken).toBeTruthy();
    expect(result.availableMethods).toContain('totp');
    // ⚑ No session exists yet. The first factor passed; the login has not.
    expect(repos.sessions.all()).toHaveLength(0);
    expect(repos.refreshTokens.all()).toHaveLength(0);
  });

  it('⚑ never satisfies a challenge with an unconfirmed factor', async () => {
    const user = await seedUser();
    await repos.mfa.addFactor({ userId: user.id, type: 'totp', label: null, secretEnc: null });

    // A half-finished enrolment must not become a permanent bypass — but it must
    // not lock the user out either, so login proceeds as if it were not there.
    expect((await attempt()).status).toBe('authenticated');
  });

  it('binds the challenge to the client that started the login', async () => {
    const user = await seedUser();
    await enrolTotp(user.id);
    const result = await attempt();
    if (result.status !== 'mfa_required') throw new Error('expected a challenge');

    const consumed = await repos.oneTimeTokens.consume(
      deps.sha256(result.mfaToken),
      'mfa_challenge',
    );
    expect(consumed?.payload.binding).toBe(
      deps.hex(deps.clientBinding({ userAgent: 'vitest', ip: '203.0.113.7' })),
    );
    expect(consumed?.payload.amr).toEqual(['pwd']);
  });

  it('offers recovery codes only once some exist', async () => {
    const user = await seedUser();
    await enrolTotp(user.id);

    const before = await attempt();
    if (before.status !== 'mfa_required') throw new Error('expected a challenge');
    expect(before.availableMethods).not.toContain('recovery');

    await repos.mfa.replaceRecoveryCodes(user.id, [deps.sha256('code-1')]);
    const after = await attempt();
    if (after.status !== 'mfa_required') throw new Error('expected a challenge');
    expect(after.availableMethods).toContain('recovery');
  });

  it('does not offer email OTP to an unverified address', async () => {
    const ctxLoose = buildContext(
      config({ email: { fromAddress: 'x@acme.test', requireVerification: false } }),
    );
    const user = await seedUser({ emailVerifiedAt: null });
    await enrolTotp(user.id);

    const result = await attempt({}, ctxLoose);
    if (result.status !== 'mfa_required') throw new Error('expected a challenge');
    // Sending a second factor to an address nobody has proven they control turns
    // 2FA into one factor plus a guess.
    expect(result.availableMethods).not.toContain('email_otp');
  });

  it('skips 2FA entirely when the feature is off', async () => {
    const off = buildContext(config({ mfa: { enabled: false } }));
    const user = await seedUser();
    await enrolTotp(user.id);

    expect((await attempt({}, off)).status).toBe('authenticated');
  });

  it('audits the challenge', async () => {
    const user = await seedUser();
    await enrolTotp(user.id);
    await attempt();

    expect(repos.audit.eventsOfType('auth.mfa_challenged')).toHaveLength(1);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('trusted devices', () => {
  const cfg = () =>
    config({ mfa: { enforce: 'optional', trustedDevices: { enabled: true, ttl: '30d' } } });

  async function seedTrustedUser() {
    const user = await seedUser();
    const factor = await repos.mfa.addFactor({
      userId: user.id,
      type: 'totp',
      label: null,
      secretEnc: new Uint8Array([1]),
    });
    await repos.mfa.confirmFactor(factor.id, clock.now());
    return user;
  }

  it('short-circuits the challenge and records amr pwd+device', async () => {
    const trusting = buildContext(cfg());
    const user = await seedTrustedUser();
    await repos.trustedDevices.create({
      userId: user.id,
      hash: deps.sha256('device-token'),
      label: 'Laptop',
      expiresAt: new Date(clock.now().getTime() + 30 * 86_400_000),
      mfaSatisfiedAt: clock.now(),
    });

    const result = await attempt({ trustedDeviceToken: 'device-token' }, trusting);

    expect(result.status).toBe('authenticated');
    if (result.status !== 'authenticated') return;
    expect(result.session.session.amr).toEqual(['pwd', 'device']);
  });

  it('⚑ leaves mfaSatisfiedAt null, so step-up still asks', async () => {
    const trusting = buildContext(cfg());
    const user = await seedTrustedUser();
    await repos.trustedDevices.create({
      userId: user.id,
      hash: deps.sha256('device-token'),
      label: null,
      expiresAt: new Date(clock.now().getTime() + 30 * 86_400_000),
      mfaSatisfiedAt: clock.now(),
    });

    const result = await attempt({ trustedDeviceToken: 'device-token' }, trusting);
    if (result.status !== 'authenticated') throw new Error('expected a session');
    // A stolen laptop skips the login prompt; it must not also be able to change
    // the password or export data (§5.4.5).
    expect(result.session.session.mfaSatisfiedAt).toBeNull();
  });

  it('⚑ refuses a device trusted by a different user', async () => {
    const trusting = buildContext(cfg());
    await seedTrustedUser();
    const other = await repos.users.create({ email: 'bob@example.test', status: 'active' });
    await repos.trustedDevices.create({
      userId: other.id,
      hash: deps.sha256('device-token'),
      label: null,
      expiresAt: new Date(clock.now().getTime() + 30 * 86_400_000),
      mfaSatisfiedAt: clock.now(),
    });

    // Trust is scoped to (user, device). Without that check one cookie would skip
    // 2FA for every account sharing the browser.
    expect((await attempt({ trustedDeviceToken: 'device-token' }, trusting)).status).toBe(
      'mfa_required',
    );
  });

  it('ignores the cookie when the feature is disabled', async () => {
    const user = await seedTrustedUser();
    await repos.trustedDevices.create({
      userId: user.id,
      hash: deps.sha256('device-token'),
      label: null,
      expiresAt: new Date(clock.now().getTime() + 30 * 86_400_000),
      mfaSatisfiedAt: clock.now(),
    });

    expect((await attempt({ trustedDeviceToken: 'device-token' })).status).toBe('mfa_required');
  });

  it('ignores an expired device without sliding its expiry', async () => {
    const trusting = buildContext(cfg());
    const user = await seedTrustedUser();
    const { id } = await repos.trustedDevices.create({
      userId: user.id,
      hash: deps.sha256('device-token'),
      label: null,
      expiresAt: new Date(clock.now().getTime() + 1_000),
      mfaSatisfiedAt: clock.now(),
    });

    clock.advance(2_000);
    expect((await attempt({ trustedDeviceToken: 'device-token' }, trusting)).status).toBe(
      'mfa_required',
    );
    const [device] = await repos.trustedDevices.listForUser(user.id);
    expect(device?.id).toBe(id);
  });

  it('records use without extending the 30-day cap', async () => {
    const trusting = buildContext(cfg());
    const user = await seedTrustedUser();
    const expiresAt = new Date(clock.now().getTime() + 30 * 86_400_000);
    await repos.trustedDevices.create({
      userId: user.id,
      hash: deps.sha256('device-token'),
      label: null,
      expiresAt,
      mfaSatisfiedAt: clock.now(),
    });

    clock.advance(86_400_000);
    await attempt({ trustedDeviceToken: 'device-token' }, trusting);

    const [device] = await repos.trustedDevices.listForUser(user.id);
    expect(device?.lastUsedAt).toEqual(clock.now());
    // ⚑ Sliding this on use turns a 30-day cap into a permanent exemption for any
    // device that signs in monthly.
    expect(device?.expiresAt).toEqual(expiresAt);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('the enrollment quarantine', () => {
  const enforced = () => buildContext(config({ mfa: { enforce: 'all', gracePeriod: '7d' } }));

  it('⚑ succeeds rather than refusing', async () => {
    await seedUser();
    const result = await attempt({}, enforced());

    // The obvious implementation refuses, which locks the user out of the very
    // screen that would satisfy the policy (§5.4.6).
    expect(result.status).toBe('authenticated');
    if (result.status !== 'authenticated') return;
    expect(result.mfaEnrollmentRequired).toBe(true);
    expect(result.session.session.amr).toEqual(['pwd']);
    expect(result.session.session.mfaSatisfiedAt).toBeNull();
  });

  it('stamps mfaRequiredAt once and dates the grace period from it', async () => {
    const ctxEnforced = enforced();
    const user = await seedUser();

    const first = await attempt({}, ctxEnforced);
    const stampedAt = (await repos.users.findById(user.id))?.mfaRequiredAt;

    clock.advance(86_400_000);
    const second = await attempt({}, ctxEnforced);

    expect((await repos.users.findById(user.id))?.mfaRequiredAt).toEqual(stampedAt);
    if (first.status !== 'authenticated' || second.status !== 'authenticated') return;
    // Dating it from each login would let anyone postpone the deadline forever by
    // simply signing in.
    expect(second.mfaGraceEndsAt).toEqual(first.mfaGraceEndsAt);
  });

  it('does not quarantine once a factor is confirmed', async () => {
    const ctxEnforced = enforced();
    const user = await seedUser();
    const factor = await repos.mfa.addFactor({
      userId: user.id,
      type: 'totp',
      label: null,
      secretEnc: new Uint8Array([1]),
    });
    await repos.mfa.confirmFactor(factor.id, clock.now());

    expect((await attempt({}, ctxEnforced)).status).toBe('mfa_required');
  });

  it('honours the per-user marker under enforce=admins', async () => {
    // 'admins' needs the role table (§10); until then mfaRequiredAt is the signal.
    const ctxAdmins = buildContext(config({ mfa: { enforce: 'admins' } }));
    await seedUser({ mfaRequiredAt: clock.now() });

    const result = await attempt({}, ctxAdmins);
    if (result.status !== 'authenticated') throw new Error('expected a session');
    expect(result.mfaEnrollmentRequired).toBe(true);
  });

  it('leaves an ordinary user alone under enforce=admins', async () => {
    const ctxAdmins = buildContext(config({ mfa: { enforce: 'admins' } }));
    await seedUser();

    const result = await attempt({}, ctxAdmins);
    if (result.status !== 'authenticated') throw new Error('expected a session');
    expect(result.mfaEnrollmentRequired).toBe(false);
  });
});
