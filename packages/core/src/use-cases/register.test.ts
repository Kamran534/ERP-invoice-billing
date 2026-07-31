/**
 * Registration and email verification (AUTH-MODULE-PLAN.md §5.1, §5.2).
 *
 * Almost every test here is about the same thing from a different angle: signup is
 * an unauthenticated endpoint that answers a question ("does this address have an
 * account?") nobody is entitled to ask.
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
import type { BreachChecker } from '../ports.js';
import type { CryptoDeps } from './deps.js';
import { register, resendVerification, verifyEmail } from './register.js';

let repos: InMemoryRepos;
let clock: FakeClock;
let mailer: ReturnType<typeof createRecordingMailer>;
let events: ReturnType<typeof createRecordingEventBus>;
let deps: CryptoDeps;
let ctx: AuthContext;

const config = (overrides: Partial<AuthConfigInput> = {}): AuthConfig =>
  defineAuthConfig({
    appName: 'Acme Billing',
    urls: { appOrigin: 'https://app.acme.test', verifyPath: '/verify' },
    tokens: { issuer: 'https://auth.acme.test', audience: ['api.acme.test'] },
    email: { fromAddress: 'no-reply@acme.test' },
    password: { checkBreached: false },
    ...overrides,
  });

function buildContext(cfg: AuthConfig, breachChecker?: BreachChecker): AuthContext {
  return {
    config: cfg,
    repos,
    clock,
    random: createSequentialRandom(),
    hasher: createFakeHasher(),
    tokens: createFakeTokenService(),
    mailer,
    breachChecker,
    events,
    logger: silentLogger,
  };
}

const signUp = (
  overrides: { email?: string; password?: string; name?: string } = {},
  ctxOverride = ctx,
) =>
  register(ctxOverride, deps, {
    email: overrides.email ?? 'ada@example.test',
    password: overrides.password ?? 'correct-horse-battery',
    name: overrides.name ?? 'Ada',
    ip: '203.0.113.7',
    userAgent: 'vitest',
  });

/** Pulls the token out of the link we just mailed, the way a user's click would. */
function tokenFromLastMail(): string {
  const last = mailer.sent.at(-1);
  const match = last?.text.match(/token=([^\s]+)/);
  if (!match?.[1]) throw new Error(`no verification token in: ${last?.text}`);
  return match[1];
}

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
  mailer = createRecordingMailer();
  events = createRecordingEventBus();
  deps = createTestCryptoDeps();
  ctx = buildContext(config());
});

// ───────────────────────────────────────────────────────────────────────────
describe('registering', () => {
  it('creates a pending user and mails a link', async () => {
    const result = await signUp();

    expect(result.status).toBe('verification_sent');
    const [user] = repos.users.all();
    expect(user?.status).toBe('pending');
    expect(user?.emailVerifiedAt).toBeNull();
    expect(mailer.sent).toHaveLength(1);
  });

  it('stores what the hasher returned, and records the algorithm', async () => {
    // The fake hasher is reversible by design, so "does not contain the password"
    // would be testing the double. What this use-case owes us is that the value it
    // persists came from the hasher at all, and is labelled — `passwordAlgo` is
    // what drives the lazy rehash on the next login (§5.3 step 5).
    await signUp({ password: 'correct-horse-battery' });
    const [user] = repos.users.all();

    const expected = await ctx.hasher.hash('correct-horse-battery');
    expect(user?.passwordHash).toBe(expected.hash);
    expect(user?.passwordHash).not.toBe('correct-horse-battery');
    expect(user?.passwordAlgo).toBe('argon2id');
  });

  it('⚑ builds the link from the configured origin, not a request header', async () => {
    await signUp();
    // Host-header-controlled links are how reset poisoning works (§5.7). There is
    // no request header in this call at all, which is the point.
    expect(mailer.sent[0]?.text).toContain('https://app.acme.test/verify?token=');
  });

  it('audits and emits', async () => {
    await signUp();
    expect(repos.audit.eventsOfType('user.registered')).toHaveLength(1);
    expect(repos.audit.eventsOfType('email.verification_sent')).toHaveLength(1);
    expect(events.published.map((e) => e.type)).toContain('user.registered');
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('an address that is already taken', () => {
  it('⚑ returns exactly the same result', async () => {
    const first = await signUp();
    const second = await signUp();

    expect(second).toEqual(first);
    expect(repos.users.all()).toHaveLength(1);
  });

  it('⚑ hashes on the taken path too', async () => {
    // If hashing only happened when the address was free, "already registered"
    // would be reliably faster to detect — a timing oracle that costs nothing to
    // exploit. The hasher here is instant, so the assertion is structural: the
    // taken branch must not short-circuit before the hash.
    const slow = createFakeHasher();
    let hashCalls = 0;
    const wrapped = { ...slow, hash: async (p: string) => (hashCalls += 1, slow.hash(p)) };
    const ctxCounting: AuthContext = { ...buildContext(config()), hasher: wrapped };

    await signUp({}, ctxCounting);
    await signUp({}, ctxCounting);

    expect(hashCalls).toBe(2);
  });

  it('tells the real owner instead of the caller', async () => {
    await signUp();
    mailer.sent.length = 0;
    await signUp();

    // The caller learns nothing; the account holder learns someone tried.
    expect(mailer.sent).toHaveLength(1);
    expect(mailer.sent[0]?.subject).toContain('Someone tried to register');
    expect(mailer.sent[0]?.to).toBe('ada@example.test');
  });

  it('records the collision for operators', async () => {
    await signUp();
    await signUp();

    const events = repos.audit.eventsOfType('user.registered');
    expect(events).toHaveLength(2);
    expect(events[1]).toMatchObject({ outcome: 'failure', metadata: { reason: 'email_taken' } });
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('password policy', () => {
  it('rejects a password below the minimum', async () => {
    await expectAuthError(signUp({ password: 'short' }), 'WEAK_PASSWORD');
    expect(repos.users.all()).toHaveLength(0);
  });

  it('⚑ rejects an absurdly long one', async () => {
    // Not about strength: a megabyte of input becomes a memory-hard hash big
    // enough to take the process down.
    await expectAuthError(signUp({ password: 'a'.repeat(5_000) }), 'WEAK_PASSWORD');
  });

  it('imposes no composition rules', async () => {
    // NIST 800-63B. "Must contain a symbol" reliably produces `Password1!`.
    const result = await signUp({ password: 'all lowercase words please' });
    expect(result.status).toBe('verification_sent');
  });

  it('rejects a breached password when the checker says so', async () => {
    const ctxChecked = buildContext(config({ password: { checkBreached: true } }), {
      isBreached: async () => true,
    });
    await expectAuthError(signUp({}, ctxChecked), 'PASSWORD_BREACHED');
  });

  it('⚑ fails open when the breach service is down, but says so', async () => {
    let warned = false;
    const ctxBroken: AuthContext = {
      ...buildContext(config({ password: { checkBreached: true } }), {
        isBreached: async () => {
          throw new Error('HIBP unreachable');
        },
      }),
      logger: { ...silentLogger, warn: () => (warned = true) },
    };

    // A third-party outage must not stop people signing up; a silent one must not
    // quietly disable the control either.
    expect((await signUp({}, ctxBroken)).status).toBe('verification_sent');
    expect(warned).toBe(true);
  });

  it('treats a missing checker as the control being unavailable', async () => {
    const ctxNoChecker = buildContext(config({ password: { checkBreached: true } }));
    expect((await signUp({}, ctxNoChecker)).status).toBe('verification_sent');
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('verifying the address', () => {
  it('promotes a pending account to active', async () => {
    await signUp();
    const token = tokenFromLastMail();

    const { userId } = await verifyEmail(ctx, deps, { token, ip: null, userAgent: null });

    const user = await repos.users.findById(userId);
    expect(user?.status).toBe('active');
    expect(user?.emailVerifiedAt).toEqual(clock.now());
    expect(events.published.map((e) => e.type)).toContain('user.verified');
  });

  it('⚑ consumes the token, so the link works exactly once', async () => {
    await signUp();
    const token = tokenFromLastMail();
    await verifyEmail(ctx, deps, { token, ip: null, userAgent: null });

    await expectAuthError(
      verifyEmail(ctx, deps, { token, ip: null, userAgent: null }),
      'CODE_EXPIRED',
    );
  });

  it('gives one answer for unknown, used and expired', async () => {
    // The client offers a resend in every case, so distinguishing them buys
    // nothing and leaks a little.
    await expectAuthError(
      verifyEmail(ctx, deps, { token: 'never-issued', ip: null, userAgent: null }),
      'CODE_EXPIRED',
    );
  });

  it('expires the link after 24 hours', async () => {
    await signUp();
    const token = tokenFromLastMail();
    clock.advance(24 * 3_600_000 + 1);

    await expectAuthError(
      verifyEmail(ctx, deps, { token, ip: null, userAgent: null }),
      'CODE_EXPIRED',
    );
  });

  it('⚑ never un-suspends an account', async () => {
    await signUp();
    const token = tokenFromLastMail();
    const [user] = repos.users.all();
    await repos.users.update(user!.id, { status: 'suspended' });

    await verifyEmail(ctx, deps, { token, ip: null, userAgent: null });

    // Verification confirms an address. If it also cleared a suspension it would
    // be a way to undo moderation.
    expect((await repos.users.findById(user!.id))?.status).toBe('suspended');
    expect((await repos.users.findById(user!.id))?.emailVerifiedAt).not.toBeNull();
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('resending the verification', () => {
  it('⚑ reports success for an address with no account', async () => {
    const result = await resendVerification(ctx, deps, {
      email: 'nobody@example.test',
      ip: null,
      userAgent: null,
    });

    expect(result.status).toBe('verification_sent');
    expect(mailer.sent).toHaveLength(0);
  });

  it('⚑ invalidates the previous link', async () => {
    await signUp();
    const first = tokenFromLastMail();

    await resendVerification(ctx, deps, {
      email: 'ada@example.test',
      ip: null,
      userAgent: null,
    });
    const second = tokenFromLastMail();
    expect(second).not.toBe(first);

    // Only the newest link works — otherwise every resend leaves another valid
    // token sitting in a mailbox.
    await expectAuthError(
      verifyEmail(ctx, deps, { token: first, ip: null, userAgent: null }),
      'CODE_EXPIRED',
    );
    await expect(
      verifyEmail(ctx, deps, { token: second, ip: null, userAgent: null }),
    ).resolves.toBeDefined();
  });

  it('sends nothing to an already-verified address', async () => {
    await signUp();
    await verifyEmail(ctx, deps, { token: tokenFromLastMail(), ip: null, userAgent: null });
    mailer.sent.length = 0;

    const result = await resendVerification(ctx, deps, {
      email: 'ada@example.test',
      ip: null,
      userAgent: null,
    });

    expect(result.status).toBe('verification_sent');
    expect(mailer.sent).toHaveLength(0);
  });
});
