/**
 * Two-factor authentication (AUTH-MODULE-PLAN.md §5.4).
 *
 * The cases worth reading first are the ones where something *verifies* and is
 * still refused: a code replayed inside its own drift window, an unconfirmed
 * factor, a challenge redeemed from a different client. Each is a place where the
 * obvious implementation is wrong in a way that looks like it works.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  FakeClock,
  createFakeHasher,
  createFakeSecretBox,
  createFakeTokenService,
  createFakeTotp,
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
import type { TotpSecret, User } from '../ports.js';
import type { CryptoDeps } from './deps.js';
import { login } from './login.js';
import {
  confirmTotpEnrollment,
  getMfaState,
  listTrustedDevices,
  regenerateRecoveryCodes,
  removeFactor,
  revokeTrustedDevice,
  startTotpEnrollment,
  verifyMfaChallenge,
} from './mfa.js';

let repos: InMemoryRepos;
let clock: FakeClock;
let totp: ReturnType<typeof createFakeTotp>;
let mailer: ReturnType<typeof createRecordingMailer>;
let events: ReturnType<typeof createRecordingEventBus>;
let deps: CryptoDeps;
let ctx: AuthContext;
let user: User;

const PASSWORD = 'correct-horse';
const request = { ip: '203.0.113.7', userAgent: 'vitest' };

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
    hasher: createFakeHasher(),
    tokens: createFakeTokenService(),
    mailer,
    secrets: createFakeSecretBox(),
    totp,
    events,
    logger: silentLogger,
  };
}

async function expectAuthError(promise: Promise<unknown>, code: AuthErrorCode): Promise<void> {
  await expect(promise).rejects.toSatisfy((error: unknown) => {
    if (!isAuthError(error)) throw new Error(`expected AuthError, got ${String(error)}`);
    if (error.code !== code) throw new Error(`expected ${code}, got ${error.code}`);
    return true;
  });
}

/** Enrols and confirms a TOTP factor, returning what the authenticator holds. */
async function enrol(ctxOverride = ctx): Promise<{ factorId: string; secret: TotpSecret }> {
  const started = await startTotpEnrollment(ctxOverride, { userId: user.id, ...request });
  const secret = { base32: started.secret };
  await confirmTotpEnrollment(ctxOverride, deps, {
    userId: user.id,
    factorId: started.factorId,
    code: totp.codeFor(secret),
    ...request,
  });
  // The confirming code is burnt, so move past its timestep before logging in.
  clock.advance(31_000);
  return { factorId: started.factorId, secret };
}

/** Password login that stops at the challenge, returning the token. */
async function challengeToken(ctxOverride = ctx): Promise<string> {
  const result = await login(ctxOverride, deps, {
    email: user.email!,
    password: PASSWORD,
    ...request,
  });
  if (result.status !== 'mfa_required') throw new Error(`expected a challenge, got ${result.status}`);
  return result.mfaToken;
}

beforeEach(async () => {
  clock = new FakeClock();
  repos = createInMemoryRepos(clock);
  totp = createFakeTotp(clock);
  mailer = createRecordingMailer();
  events = createRecordingEventBus();
  deps = createTestCryptoDeps();
  ctx = buildContext(config());
  user = await repos.users.create({
    email: 'ada@example.test',
    status: 'active',
    emailVerifiedAt: clock.now(),
    passwordHash: `fake:${PASSWORD}`,
    passwordAlgo: 'argon2id',
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('enrolling a TOTP factor', () => {
  it('returns the secret once, with a provisioning URI', async () => {
    const started = await startTotpEnrollment(ctx, { userId: user.id, ...request });

    expect(started.secret).toBeTruthy();
    expect(started.provisioningUri).toContain('otpauth://totp/');
    expect(started.provisioningUri).toContain(encodeURIComponent('ada@example.test'));
  });

  it('⚑ stores the secret encrypted, bound to its purpose', async () => {
    const started = await startTotpEnrollment(ctx, { userId: user.id, ...request });
    const factor = await repos.mfa.findFactor(started.factorId);

    expect(factor?.secretEnc).toBeTruthy();
    // Sealed for 'totp-secret'; opening it as a signing key must fail, or a
    // ciphertext could be moved between uses.
    expect(() => ctx.secrets!.decrypt(factor!.secretEnc!, 'signing-key')).toThrow();
    expect(ctx.secrets!.decrypt(factor!.secretEnc!, 'totp-secret')).toBe(started.secret);
  });

  it('⚑ leaves the factor unconfirmed, so it satisfies nothing yet', async () => {
    await startTotpEnrollment(ctx, { userId: user.id, ...request });

    expect(await repos.mfa.listConfirmedFactors(user.id)).toHaveLength(0);
    // A half-finished enrolment must not become a permanent unverified bypass —
    // and must not lock the user out either.
    const result = await login(ctx, deps, { email: user.email!, password: PASSWORD, ...request });
    expect(result.status).toBe('authenticated');
  });

  it('sweeps abandoned enrolments older than fifteen minutes', async () => {
    await startTotpEnrollment(ctx, { userId: user.id, ...request });
    clock.advance(16 * 60_000);
    await startTotpEnrollment(ctx, { userId: user.id, ...request });

    expect(await repos.mfa.listAllFactors(user.id)).toHaveLength(1);
  });

  it('refuses a wrong confirmation code', async () => {
    const started = await startTotpEnrollment(ctx, { userId: user.id, ...request });

    await expectAuthError(
      confirmTotpEnrollment(ctx, deps, {
        userId: user.id,
        factorId: started.factorId,
        code: '000000',
        ...request,
      }),
      'INVALID_CODE',
    );
    expect(await repos.mfa.listConfirmedFactors(user.id)).toHaveLength(0);
  });

  it('⚑ answers NOT_FOUND for someone else\'s factor', async () => {
    const other = await repos.users.create({ email: 'bob@example.test', status: 'active' });
    const started = await startTotpEnrollment(ctx, { userId: other.id, ...request });

    // Ownership before existence, so factor ids cannot be probed.
    await expectAuthError(
      confirmTotpEnrollment(ctx, deps, {
        userId: user.id,
        factorId: started.factorId,
        code: '000000',
        ...request,
      }),
      'NOT_FOUND',
    );
  });

  it('hands over recovery codes on confirmation, and only then', async () => {
    const started = await startTotpEnrollment(ctx, { userId: user.id, ...request });
    expect(await repos.mfa.countUnusedRecoveryCodes(user.id)).toBe(0);

    const { recoveryCodes } = await confirmTotpEnrollment(ctx, deps, {
      userId: user.id,
      factorId: started.factorId,
      code: totp.codeFor({ base32: started.secret }),
      ...request,
    });

    expect(recoveryCodes).toHaveLength(10);
    expect(recoveryCodes[0]).toMatch(/^[A-Z2-9]{5}(-[A-Z2-9]{5}){3}$/);
    // ⚑ Ten codes, not one code ten times. This assertion exists because the
    // random double used to return the same buffer on every call, and without it
    // "a code works exactly once" passed while nine identical spares remained.
    expect(new Set(recoveryCodes).size).toBe(10);
    expect(await repos.mfa.countUnusedRecoveryCodes(user.id)).toBe(10);
  });

  it('⚑ revokes other sessions and emails the owner', async () => {
    const other = await login(ctx, deps, { email: user.email!, password: PASSWORD, ...request });
    if (other.status !== 'authenticated') throw new Error('expected a session');

    await enrol();

    // Whoever was already signed in is exactly who the new factor is meant to
    // exclude.
    expect((await repos.sessions.findById(other.session.session.id))?.revokedReason).toBe(
      'mfa_change',
    );
    expect(mailer.sent.some((mail) => /two-factor/i.test(mail.subject))).toBe(true);
  });

  it('refuses to confirm twice', async () => {
    const started = await startTotpEnrollment(ctx, { userId: user.id, ...request });
    const code = totp.codeFor({ base32: started.secret });
    await confirmTotpEnrollment(ctx, deps, {
      userId: user.id,
      factorId: started.factorId,
      code,
      ...request,
    });

    await expectAuthError(
      confirmTotpEnrollment(ctx, deps, {
        userId: user.id,
        factorId: started.factorId,
        code,
        ...request,
      }),
      'CONFLICT',
    );
  });

  it('refuses when no key store is wired', async () => {
    const unconfigured: AuthContext = { ...ctx, secrets: undefined };
    // ⚑ Refuse rather than degrade: enrolling a secret we cannot read back is
    // worse than not offering 2FA at all.
    await expectAuthError(
      startTotpEnrollment(unconfigured, { userId: user.id, ...request }),
      'SERVICE_UNAVAILABLE',
    );
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('completing a challenge', () => {
  it('issues a session with both factors recorded', async () => {
    const { secret } = await enrol();
    const mfaToken = await challengeToken();

    const result = await verifyMfaChallenge(ctx, deps, {
      mfaToken,
      method: 'totp',
      code: totp.codeFor(secret),
      ...request,
    });

    expect(result.session.session.amr).toEqual(['pwd', 'totp']);
    expect(result.session.session.mfaSatisfiedAt).toEqual(clock.now());
    expect(result.session.accessToken).toBeTruthy();
  });

  it('⚑ refuses the same code twice, inside its own drift window', async () => {
    const { secret } = await enrol();
    const code = totp.codeFor(secret);

    await verifyMfaChallenge(ctx, deps, {
      mfaToken: await challengeToken(),
      method: 'totp',
      code,
      ...request,
    });

    // Still cryptographically valid — ±1 step of drift is what makes TOTP usable —
    // and that is exactly the window someone who watched it being typed is in.
    const second = await challengeToken();
    await expectAuthError(
      verifyMfaChallenge(ctx, deps, { mfaToken: second, method: 'totp', code, ...request }),
      'INVALID_CODE',
    );
  });

  it('accepts the next code once the clock has moved on', async () => {
    const { secret } = await enrol();
    await verifyMfaChallenge(ctx, deps, {
      mfaToken: await challengeToken(),
      method: 'totp',
      code: totp.codeFor(secret),
      ...request,
    });

    clock.advance(31_000);
    const result = await verifyMfaChallenge(ctx, deps, {
      mfaToken: await challengeToken(),
      method: 'totp',
      code: totp.codeFor(secret),
      ...request,
    });
    expect(result.session.session.amr).toEqual(['pwd', 'totp']);
  });

  it('⚑ destroys the challenge after five wrong guesses, not just the attempt', async () => {
    const { secret } = await enrol();
    const mfaToken = await challengeToken();

    for (let i = 0; i < 5; i += 1) {
      await expectAuthError(
        verifyMfaChallenge(ctx, deps, { mfaToken, method: 'totp', code: '000000', ...request }),
        'INVALID_CODE',
      );
    }

    // Six digits is ~20 bits. The cap is the only thing making that safe, so the
    // *challenge* has to die — capping the attempt alone would let an attacker
    // start a fresh one and keep grinding.
    await expectAuthError(
      verifyMfaChallenge(ctx, deps, {
        mfaToken,
        method: 'totp',
        code: totp.codeFor(secret),
        ...request,
      }),
      'CHALLENGE_EXHAUSTED',
    );
  });

  it('counts down the remaining attempts for the UI', async () => {
    await enrol();
    const mfaToken = await challengeToken();

    const first = await verifyMfaChallenge(ctx, deps, {
      mfaToken,
      method: 'totp',
      code: '000000',
      ...request,
    }).catch((e) => e);
    expect(first.details).toMatchObject({ attemptsRemaining: 4 });
  });

  it('⚑ refuses a challenge redeemed from a different client', async () => {
    const { secret } = await enrol();
    const mfaToken = await challengeToken();

    // A token read out of a URL, a log, or a shoulder-surfed screen is useless
    // from anywhere else.
    await expectAuthError(
      verifyMfaChallenge(ctx, deps, {
        mfaToken,
        method: 'totp',
        code: totp.codeFor(secret),
        ip: '198.51.100.9',
        userAgent: 'someone else',
      }),
      'CHALLENGE_EXHAUSTED',
    );
  });

  it('⚑ does not consume the challenge on a wrong code', async () => {
    const { secret } = await enrol();
    const mfaToken = await challengeToken();

    await expectAuthError(
      verifyMfaChallenge(ctx, deps, { mfaToken, method: 'totp', code: '000000', ...request }),
      'INVALID_CODE',
    );
    // Otherwise one typo would mean restarting the whole login.
    const result = await verifyMfaChallenge(ctx, deps, {
      mfaToken,
      method: 'totp',
      code: totp.codeFor(secret),
      ...request,
    });
    expect(result.session.accessToken).toBeTruthy();
  });

  it('consumes the challenge on success, so it cannot be replayed', async () => {
    const { secret } = await enrol();
    const mfaToken = await challengeToken();
    const code = totp.codeFor(secret);
    await verifyMfaChallenge(ctx, deps, { mfaToken, method: 'totp', code, ...request });

    clock.advance(31_000);
    await expectAuthError(
      verifyMfaChallenge(ctx, deps, {
        mfaToken,
        method: 'totp',
        code: totp.codeFor(secret),
        ...request,
      }),
      'CHALLENGE_EXHAUSTED',
    );
  });

  it('expires the challenge after its TTL', async () => {
    const { secret } = await enrol();
    const mfaToken = await challengeToken();

    clock.advance(5 * 60_000 + 1);
    await expectAuthError(
      verifyMfaChallenge(ctx, deps, {
        mfaToken,
        method: 'totp',
        code: totp.codeFor(secret),
        ...request,
      }),
      'CHALLENGE_EXHAUSTED',
    );
  });

  it('audits success and failure with the method', async () => {
    const { secret } = await enrol();
    const mfaToken = await challengeToken();
    await verifyMfaChallenge(ctx, deps, {
      mfaToken,
      method: 'totp',
      code: '000000',
      ...request,
    }).catch(() => undefined);
    await verifyMfaChallenge(ctx, deps, {
      mfaToken,
      method: 'totp',
      code: totp.codeFor(secret),
      ...request,
    });

    expect(repos.audit.eventsOfType('auth.mfa_failed')).toHaveLength(1);
    expect(repos.audit.eventsOfType('auth.mfa_succeeded')).toHaveLength(1);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('recovery codes', () => {
  async function enrolWithCodes() {
    const started = await startTotpEnrollment(ctx, { userId: user.id, ...request });
    const { recoveryCodes } = await confirmTotpEnrollment(ctx, deps, {
      userId: user.id,
      factorId: started.factorId,
      code: totp.codeFor({ base32: started.secret }),
      ...request,
    });
    clock.advance(31_000);
    return recoveryCodes;
  }

  it('completes a challenge, recorded as otp rather than totp', async () => {
    const codes = await enrolWithCodes();
    const result = await verifyMfaChallenge(ctx, deps, {
      mfaToken: await challengeToken(),
      method: 'recovery',
      code: codes[0]!,
      ...request,
    });

    // ⚑ A recovery code is a bearer secret, not a device. Step-up is entitled to
    // know the difference.
    expect(result.session.session.amr).toEqual(['pwd', 'otp']);
  });

  it('⚑ works exactly once', async () => {
    const codes = await enrolWithCodes();
    await verifyMfaChallenge(ctx, deps, {
      mfaToken: await challengeToken(),
      method: 'recovery',
      code: codes[0]!,
      ...request,
    });

    await expectAuthError(
      verifyMfaChallenge(ctx, deps, {
        mfaToken: await challengeToken(),
        method: 'recovery',
        code: codes[0]!,
        ...request,
      }),
      'INVALID_CODE',
    );
    expect(await repos.mfa.countUnusedRecoveryCodes(user.id)).toBe(9);
  });

  it('accepts a code typed without its dashes', async () => {
    const codes = await enrolWithCodes();
    const result = await verifyMfaChallenge(ctx, deps, {
      mfaToken: await challengeToken(),
      method: 'recovery',
      // These get typed off paper by someone who has just lost their phone.
      code: codes[0]!.replace(/-/g, '').toLowerCase(),
      ...request,
    });
    expect(result.session.accessToken).toBeTruthy();
  });

  it('emails on use, and warns when few remain', async () => {
    const codes = await enrolWithCodes();
    await repos.mfa.replaceRecoveryCodes(user.id, [deps.sha256(codes[0]!.replace(/-/g, ''))]);
    mailer.sent.length = 0;

    await verifyMfaChallenge(ctx, deps, {
      mfaToken: await challengeToken(),
      method: 'recovery',
      code: codes[0]!,
      ...request,
    });

    expect(mailer.sent).toHaveLength(1);
    expect(mailer.sent[0]?.text).toMatch(/0 left/);
  });

  it('⚑ regenerating invalidates every previous code', async () => {
    const codes = await enrolWithCodes();
    await regenerateRecoveryCodes(ctx, deps, { userId: user.id, ...request });

    // Replacing the set, not appending to it — otherwise codes the user believes
    // they have just invalidated keep working.
    await expectAuthError(
      verifyMfaChallenge(ctx, deps, {
        mfaToken: await challengeToken(),
        method: 'recovery',
        code: codes[0]!,
        ...request,
      }),
      'INVALID_CODE',
    );
    expect(await repos.mfa.countUnusedRecoveryCodes(user.id)).toBe(10);
  });

  it('does not accept another user\'s code', async () => {
    const codes = await enrolWithCodes();
    const other = await repos.users.create({ email: 'bob@example.test', status: 'active' });
    await repos.mfa.replaceRecoveryCodes(other.id, [deps.sha256('SOMETHINGELSE')]);

    await expectAuthError(
      verifyMfaChallenge(ctx, deps, {
        mfaToken: await challengeToken(),
        method: 'recovery',
        code: 'SOMETHINGELSE',
        ...request,
      }),
      'INVALID_CODE',
    );
    expect(codes).toHaveLength(10);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('trusted devices', () => {
  const trusting = () =>
    buildContext(
      config({ mfa: { enforce: 'optional', trustedDevices: { enabled: true, ttl: '30d', max: 2 } } }),
    );

  it('mints a token only when both the deployment and the user ask', async () => {
    const ctxTrusting = trusting();
    const { secret } = await enrol(ctxTrusting);

    const withoutAsking = await verifyMfaChallenge(ctxTrusting, deps, {
      mfaToken: await challengeToken(ctxTrusting),
      method: 'totp',
      code: totp.codeFor(secret),
      ...request,
    });
    expect(withoutAsking.trustedDeviceToken).toBeNull();

    clock.advance(31_000);
    const asking = await verifyMfaChallenge(ctxTrusting, deps, {
      mfaToken: await challengeToken(ctxTrusting),
      method: 'totp',
      code: totp.codeFor(secret),
      rememberDevice: true,
      ...request,
    });
    expect(asking.trustedDeviceToken).toBeTruthy();
  });

  it('ignores the request when the deployment has it off', async () => {
    const { secret } = await enrol();
    const result = await verifyMfaChallenge(ctx, deps, {
      mfaToken: await challengeToken(),
      method: 'totp',
      code: totp.codeFor(secret),
      rememberDevice: true,
      ...request,
    });

    // ⚑ Off by default, and a client cannot turn it on by asking.
    expect(result.trustedDeviceToken).toBeNull();
  });

  it('lets the token skip the challenge on the next login', async () => {
    const ctxTrusting = trusting();
    const { secret } = await enrol(ctxTrusting);
    const remembered = await verifyMfaChallenge(ctxTrusting, deps, {
      mfaToken: await challengeToken(ctxTrusting),
      method: 'totp',
      code: totp.codeFor(secret),
      rememberDevice: true,
      ...request,
    });

    const next = await login(ctxTrusting, deps, {
      email: user.email!,
      password: PASSWORD,
      trustedDeviceToken: remembered.trustedDeviceToken,
      ...request,
    });

    expect(next.status).toBe('authenticated');
    if (next.status !== 'authenticated') return;
    expect(next.session.session.amr).toEqual(['pwd', 'device']);
    // ⚑ Still null: trust skips the prompt, it does not count as a factor.
    expect(next.session.session.mfaSatisfiedAt).toBeNull();
  });

  it('evicts the least recently used past the cap', async () => {
    const ctxTrusting = trusting();
    const { secret } = await enrol(ctxTrusting);

    for (let i = 0; i < 3; i += 1) {
      clock.advance(31_000);
      await verifyMfaChallenge(ctxTrusting, deps, {
        mfaToken: await challengeToken(ctxTrusting),
        method: 'totp',
        code: totp.codeFor(secret),
        rememberDevice: true,
        ...request,
      });
    }

    // The cap is what stops a user accumulating an unbounded set of things that
    // skip their second factor.
    expect(await listTrustedDevices(ctxTrusting, user.id)).toHaveLength(2);
  });

  it('revokes one by id, and refuses someone else\'s', async () => {
    const ctxTrusting = trusting();
    const { secret } = await enrol(ctxTrusting);
    await verifyMfaChallenge(ctxTrusting, deps, {
      mfaToken: await challengeToken(ctxTrusting),
      method: 'totp',
      code: totp.codeFor(secret),
      rememberDevice: true,
      ...request,
    });
    const [device] = await listTrustedDevices(ctxTrusting, user.id);

    const other = await repos.users.create({ email: 'bob@example.test', status: 'active' });
    await expectAuthError(
      revokeTrustedDevice(ctxTrusting, { userId: other.id, deviceId: device!.id, ...request }),
      'NOT_FOUND',
    );

    await revokeTrustedDevice(ctxTrusting, { userId: user.id, deviceId: device!.id, ...request });
    expect(await listTrustedDevices(ctxTrusting, user.id)).toHaveLength(0);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('managing factors', () => {
  it('reports the state a settings screen needs', async () => {
    await enrol();
    const state = await getMfaState(ctx, user.id);

    expect(state.enrolled).toBe(true);
    expect(state.factors).toHaveLength(1);
    expect(state.factors[0]?.confirmed).toBe(true);
    expect(state.recoveryCodesRemaining).toBe(10);
  });

  it('removes a factor and drops every trusted device with it', async () => {
    const ctxTrusting = buildContext(
      config({ mfa: { enforce: 'optional', trustedDevices: { enabled: true, ttl: '30d' } } }),
    );
    const { factorId, secret } = await enrol(ctxTrusting);
    await verifyMfaChallenge(ctxTrusting, deps, {
      mfaToken: await challengeToken(ctxTrusting),
      method: 'totp',
      code: totp.codeFor(secret),
      rememberDevice: true,
      ...request,
    });

    await removeFactor(ctxTrusting, { userId: user.id, factorId, ...request });

    expect(await repos.mfa.listConfirmedFactors(user.id)).toHaveLength(0);
    // ⚑ Trust was earned by a factor that no longer exists.
    expect(await listTrustedDevices(ctxTrusting, user.id)).toHaveLength(0);
  });

  it('⚑ refuses to remove the last factor when policy mandates one', async () => {
    const enforced = buildContext(config({ mfa: { enforce: 'all' } }));
    const { factorId } = await enrol(enforced);

    // Refused outright rather than quietly quarantining: this is a request to
    // disable a control, and the honest answer is no.
    await expectAuthError(
      removeFactor(enforced, { userId: user.id, factorId, ...request }),
      'MFA_REQUIRED_BY_POLICY',
    );
    expect(await repos.mfa.listConfirmedFactors(user.id)).toHaveLength(1);
  });

  it('allows removing one of several even under a mandate', async () => {
    const enforced = buildContext(config({ mfa: { enforce: 'all' } }));
    const first = await enrol(enforced);
    const second = await startTotpEnrollment(enforced, { userId: user.id, ...request });
    await confirmTotpEnrollment(enforced, deps, {
      userId: user.id,
      factorId: second.factorId,
      code: totp.codeFor({ base32: second.secret }),
      ...request,
    });

    await removeFactor(enforced, { userId: user.id, factorId: first.factorId, ...request });
    expect(await repos.mfa.listConfirmedFactors(user.id)).toHaveLength(1);
  });

  it('emails when the last factor goes', async () => {
    const { factorId } = await enrol();
    mailer.sent.length = 0;

    await removeFactor(ctx, { userId: user.id, factorId, ...request });

    expect(mailer.sent.some((mail) => /turned off/i.test(mail.text))).toBe(true);
    expect(events.published.map((e) => e.type)).toContain('mfa.disabled');
  });
});
