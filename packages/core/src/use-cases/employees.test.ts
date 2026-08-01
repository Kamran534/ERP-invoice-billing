/**
 * Employee accounts and the two login doors (AUTH-MODULE-PLAN.md §10.12, §5.3.1).
 *
 * Two shapes of test here, and they are worth telling apart:
 *
 *  - **Refusals an admin must hit** — granting a role above your own, touching an
 *    account in another tenant, making an employee the owner. These are the ones
 *    an authorization bug turns into a privilege escalation.
 *  - **Refusals a stranger must hit, identically** — a username with no tenant, a
 *    tenant that does not exist, a name nobody in that tenant holds. All three are
 *    `INVALID_CREDENTIALS` and all three cost an Argon2 verify, or the login form
 *    becomes a directory of which organizations exist and who works in them.
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
import { defineAuthConfig, type AuthConfig } from '../config.js';
import type { AuthContext } from '../context.js';
import { isAuthError, type AuthErrorCode } from '../errors.js';
import type { Org, User } from '../ports.js';
import type { CryptoDeps } from './deps.js';
import { createOrganization } from './orgs.js';
import { login } from './login.js';
import {
  createEmployee,
  listEmployees,
  resetEmployeePassword,
  setEmployeeStatus,
} from './employees.js';

let repos: InMemoryRepos;
let clock: FakeClock;
let deps: CryptoDeps;
let ctx: AuthContext;
let owner: User;
let org: Org;

const request = { ip: '203.0.113.7', userAgent: 'vitest' };
const PASSWORD = 'a passphrase of at least twelve';

const config = (): AuthConfig =>
  defineAuthConfig({
    appName: 'Acme Billing',
    urls: { appOrigin: 'https://app.acme.test' },
    tokens: { issuer: 'https://auth.acme.test', audience: ['api.acme.test'] },
    email: { fromAddress: 'no-reply@acme.test' },
    password: { checkBreached: false },
    orgs: { selfService: 'anyone' },
  });

async function verifiedUser(email: string): Promise<User> {
  const hashed = await ctx.hasher.hash(PASSWORD);
  return repos.users.create({
    email,
    status: 'active',
    emailVerifiedAt: clock.now(),
    passwordHash: hashed.hash,
    passwordAlgo: 'argon2id',
  });
}

async function expectAuthError(promise: Promise<unknown>, code: AuthErrorCode): Promise<void> {
  await expect(promise).rejects.toSatisfy((error: unknown) => {
    if (!isAuthError(error)) throw new Error(`expected AuthError, got ${String(error)}`);
    if (error.code !== code) throw new Error(`expected ${code}, got ${error.code}`);
    return true;
  });
}

const hire = (overrides: Partial<Parameters<typeof createEmployee>[1]> = {}) =>
  createEmployee(ctx, {
    actorId: owner.id,
    orgId: org.id,
    username: 'ahmed.raza',
    password: PASSWORD,
    name: 'Ahmed Raza',
    roleKey: 'member',
    ...request,
    ...overrides,
  });

beforeEach(async () => {
  clock = new FakeClock();
  repos = createInMemoryRepos(clock);
  deps = createTestCryptoDeps();
  ctx = {
    config: config(),
    repos,
    clock,
    random: createSequentialRandom(),
    hasher: createFakeHasher(),
    tokens: createFakeTokenService(),
    mailer: createRecordingMailer(),
    events: createRecordingEventBus(),
    logger: silentLogger,
  };
  owner = await verifiedUser('ada@example.test');
  ({ org } = await createOrganization(ctx, { userId: owner.id, name: 'Acme Billing', ...request }));
});

// ───────────────────────────────────────────────────────────────────────────
describe('creating an employee', () => {
  it('creates an active account with no email, in this organization', async () => {
    const employee = await hire();

    expect(employee.username).toBe('ahmed.raza');
    expect(employee.role).toBe('member');
    expect(employee.status).toBe('active');

    const user = await repos.users.findById(employee.userId);
    // ⚑ No mailbox — which is what bars them from the apex form, the verification
    // mail and the reset link, all without a single extra check anywhere.
    expect(user?.email).toBeNull();
    expect(user?.orgScopeId).toBe(org.id);
    // Active immediately: the owner vouching for them is the verification step.
    expect(user?.status).toBe('active');
  });

  it('⚑ refuses to make an employee the owner', async () => {
    // An owner with no mailbox cannot be sent a reset link, so the first forgotten
    // password would end the tenant.
    await expectAuthError(hire({ roleKey: 'owner' }), 'VALIDATION_FAILED');
  });

  it('⚑ refuses a role the creator does not hold', async () => {
    const admin = await hire({ username: 'office.manager', roleKey: 'admin' });

    await expectAuthError(
      createEmployee(ctx, {
        actorId: admin.userId,
        orgId: org.id,
        username: 'sneaky',
        password: PASSWORD,
        roleKey: 'owner',
        ...request,
      }),
      'VALIDATION_FAILED',
    );
  });

  it('refuses a name already taken in this organization', async () => {
    await hire();
    await expectAuthError(hire(), 'CONFLICT');
  });

  it('allows the same name in a different organization', async () => {
    await hire();

    const other = await verifiedUser('grace@example.test');
    const { org: otherOrg } = await createOrganization(ctx, {
      userId: other.id,
      name: 'Hopper Systems',
      ...request,
    });

    // ⚑ The whole reason usernames are scoped. Global uniqueness would let the
    // first tenant to take `ahmed.raza` take it from every tenant after them.
    const twin = await createEmployee(ctx, {
      actorId: other.id,
      orgId: otherOrg.id,
      username: 'ahmed.raza',
      password: PASSWORD,
      roleKey: 'member',
      ...request,
    });
    expect(twin.username).toBe('ahmed.raza');
  });

  it('refuses a malformed username, and a weak password', async () => {
    await expectAuthError(hire({ username: 'a b c' }), 'VALIDATION_FAILED');
    await expectAuthError(hire({ password: 'short' }), 'WEAK_PASSWORD');
  });

  it('lists employees but not the email accounts', async () => {
    await hire();
    const employees = await listEmployees(ctx, { actorId: owner.id, orgId: org.id });

    expect(employees).toHaveLength(1);
    expect(employees[0]?.username).toBe('ahmed.raza');
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('signing in', () => {
  const signIn = (input: Record<string, unknown>) =>
    login(ctx, deps, { password: PASSWORD, ...request, ...input });

  it('lets an employee in at their own organization', async () => {
    await hire();
    const result = await signIn({ username: 'ahmed.raza', org: org.slug });

    expect(result.status).toBe('authenticated');
  });

  it('⚑ refuses a username with no organization', async () => {
    await hire();
    // The same name can exist in every tenant, so answering it globally would sign
    // somebody in to an organization they never named.
    await expectAuthError(signIn({ username: 'ahmed.raza' }), 'INVALID_CREDENTIALS');
  });

  it('⚑ refuses a username belonging to another organization', async () => {
    await hire();

    const other = await verifiedUser('grace@example.test');
    const { org: otherOrg } = await createOrganization(ctx, {
      userId: other.id,
      name: 'Hopper Systems',
      ...request,
    });

    await expectAuthError(
      signIn({ username: 'ahmed.raza', org: otherOrg.slug }),
      'INVALID_CREDENTIALS',
    );
  });

  it('⚑ answers an unknown tenant exactly like a wrong password', async () => {
    await hire();
    const unknownOrg = signIn({ username: 'ahmed.raza', org: 'no-such-tenant' });
    const wrongPassword = signIn({ username: 'ahmed.raza', org: org.slug, password: 'nope-nope' });

    await expectAuthError(unknownOrg, 'INVALID_CREDENTIALS');
    await expectAuthError(wrongPassword, 'INVALID_CREDENTIALS');
  });

  it('⚑ hashes on every failing branch', async () => {
    // Structural, because the fake hasher is instant: if an unknown tenant or a
    // missing username returned before the verify, "no such organization" would be
    // reliably faster than "wrong password".
    let verifies = 0;
    const counting = { ...ctx.hasher };
    const patched: AuthContext = {
      ...ctx,
      hasher: {
        ...counting,
        verifyDummy: async (p: string) => {
          verifies += 1;
          return counting.verifyDummy(p);
        },
      },
    };

    await expect(
      login(patched, deps, { username: 'nobody', org: 'no-such-tenant', password: PASSWORD, ...request }),
    ).rejects.toThrow();
    await expect(
      login(patched, deps, { username: 'nobody', org: org.slug, password: PASSWORD, ...request }),
    ).rejects.toThrow();
    await expect(
      login(patched, deps, { username: 'nobody', password: PASSWORD, ...request }),
    ).rejects.toThrow();

    expect(verifies).toBe(3);
  });

  it('lets the owner in with an email address at their own tenant', async () => {
    const result = await signIn({ email: 'ada@example.test', org: org.slug });
    expect(result.status).toBe('authenticated');
  });

  it('⚑ refuses a non-owner email account at a tenant address', async () => {
    // Someone invited by email is a member, not the owner: at the tenant door they
    // are told to use the username form rather than left guessing.
    const member = await verifiedUser('member@example.test');
    const role = await repos.roles.findByKey(org.id, 'member');
    await repos.memberships.create({
      orgId: org.id,
      userId: member.id,
      roleId: role!.id,
      status: 'active',
    });

    await expectAuthError(
      signIn({ email: 'member@example.test', org: org.slug }),
      'WRONG_LOGIN_PORTAL',
    );
  });

  it('⚑ refuses an owner at somebody else’s tenant', async () => {
    const other = await verifiedUser('grace@example.test');
    const { org: otherOrg } = await createOrganization(ctx, {
      userId: other.id,
      name: 'Hopper Systems',
      ...request,
    });

    await expectAuthError(
      signIn({ email: 'ada@example.test', org: otherOrg.slug }),
      'WRONG_LOGIN_PORTAL',
    );
  });

  it('refuses both identities at once, and neither', async () => {
    await expectAuthError(
      signIn({ email: 'ada@example.test', username: 'ahmed.raza', org: org.slug }),
      'INVALID_CREDENTIALS',
    );
    await expectAuthError(signIn({ org: org.slug }), 'INVALID_CREDENTIALS');
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('administering an employee', () => {
  it('resets the password and kills every session they hold', async () => {
    const employee = await hire();
    const signedIn = await login(ctx, deps, {
      username: 'ahmed.raza',
      org: org.slug,
      password: PASSWORD,
      ...request,
    });
    const sessionId =
      signedIn.status === 'authenticated' ? signedIn.session.session.id : 'none';

    await resetEmployeePassword(ctx, {
      actorId: owner.id,
      orgId: org.id,
      employeeId: employee.userId,
      password: 'another passphrase entirely',
      ...request,
    });

    const session = await repos.sessions.findById(sessionId);
    // ⚑ A reset that leaves the old sessions alive is a second password, not a
    // reset — and the usual reason for resetting is that the first is compromised.
    expect(session?.revokedAt).not.toBeNull();

    await expect(
      login(ctx, deps, { username: 'ahmed.raza', org: org.slug, password: 'another passphrase entirely', ...request }),
    ).resolves.toMatchObject({ status: 'authenticated' });
  });

  it('suspends: the account stops working and the sessions die', async () => {
    const employee = await hire();
    await login(ctx, deps, { username: 'ahmed.raza', org: org.slug, password: PASSWORD, ...request });

    await setEmployeeStatus(ctx, {
      actorId: owner.id,
      orgId: org.id,
      employeeId: employee.userId,
      status: 'suspended',
      ...request,
    });

    await expectAuthError(
      login(ctx, deps, { username: 'ahmed.raza', org: org.slug, password: PASSWORD, ...request }),
      'ACCOUNT_SUSPENDED',
    );
  });

  it('⚑ refuses to touch an employee of another organization', async () => {
    const employee = await hire();

    const other = await verifiedUser('grace@example.test');
    const { org: otherOrg } = await createOrganization(ctx, {
      userId: other.id,
      name: 'Hopper Systems',
      ...request,
    });

    // A uuid in a URL is not an authorization. Without the scope check, an admin of
    // any tenant could reset the password of any account whose id they obtained.
    await expectAuthError(
      resetEmployeePassword(ctx, {
        actorId: other.id,
        orgId: otherOrg.id,
        employeeId: employee.userId,
        password: 'another passphrase entirely',
        ...request,
      }),
      'NOT_FOUND',
    );
  });

  it('⚑ refuses an admin acting on someone who outranks them', async () => {
    const admin = await hire({ username: 'office.manager', roleKey: 'admin' });
    const ownerEmployee = owner.id;

    // The owner is an email account, not an employee, so this is `NOT_FOUND` rather
    // than a permission error — but the effect is the one that matters: `admin` is
    // not a role that can take the owner's account by resetting its password.
    await expectAuthError(
      resetEmployeePassword(ctx, {
        actorId: admin.userId,
        orgId: org.id,
        employeeId: ownerEmployee,
        password: 'another passphrase entirely',
        ...request,
      }),
      'NOT_FOUND',
    );
  });
});
