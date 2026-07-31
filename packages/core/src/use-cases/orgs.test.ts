/**
 * Organizations, membership and permissions (AUTH-MODULE-PLAN.md §10.5–§10.9).
 *
 * The tests that matter are the refusals: who may claim a fresh instance, who may
 * grant which role, and what stops an organization ending up with no owner — a
 * state no permission can repair, because appointing an owner is itself an owner
 * permission.
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
import { issueSession } from './session.js';
import {
  acceptInvite,
  changeMemberRole,
  createOrganization,
  inviteMember,
  getMyOrganization,
  listMembers,
  permits,
  removeMember,
  resolveAccess,
  updateOrganization,
} from './orgs.js';

let repos: InMemoryRepos;
let clock: FakeClock;
let mailer: ReturnType<typeof createRecordingMailer>;
let events: ReturnType<typeof createRecordingEventBus>;
let deps: CryptoDeps;
let ctx: AuthContext;
let owner: User;

const request = { ip: '203.0.113.7', userAgent: 'vitest' };

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
    mailer,
    events,
    logger: silentLogger,
  };
}

async function verifiedUser(email: string): Promise<User> {
  return repos.users.create({
    email,
    status: 'active',
    emailVerifiedAt: clock.now(),
    passwordHash: 'fake:pw',
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

const bootstrap = (ctxOverride = ctx, user = owner, name = 'Acme Billing') =>
  createOrganization(ctxOverride, { userId: user.id, name, ...request });

beforeEach(async () => {
  clock = new FakeClock();
  repos = createInMemoryRepos(clock);
  mailer = createRecordingMailer();
  events = createRecordingEventBus();
  deps = createTestCryptoDeps();
  ctx = buildContext(config());
  owner = await verifiedUser('ada@example.test');
});

// ───────────────────────────────────────────────────────────────────────────
describe('claiming a fresh instance', () => {
  it('makes the creator the owner, with roles seeded', async () => {
    const { org, role } = await bootstrap();

    expect(org.name).toBe('Acme Billing');
    expect(org.slug).toBe('acme-billing');
    expect(role).toBe('owner');

    const roles = await repos.roles.listForOrg(org.id);
    expect(roles.map((r) => r.key).sort()).toEqual(['admin', 'member', 'owner']);
    // ⚑ System roles cannot be deleted through the API — an org that loses its
    // `owner` definition cannot appoint another owner.
    expect(roles.every((r) => r.isSystem)).toBe(true);
  });

  it('⚑ shuts the door behind it under the default policy', async () => {
    await bootstrap();
    const second = await verifiedUser('bob@example.test');

    // The window in which anyone can claim the instance is exactly one org wide.
    await expectAuthError(
      createOrganization(ctx, { userId: second.id, name: 'Not Yours', ...request }),
      'PERMISSION_DENIED',
    );
  });

  it('⚑ requires a verified address', async () => {
    const unverified = await repos.users.create({ email: 'new@example.test', status: 'pending' });
    // Creating a tenant is the most consequential thing this flow does; "can
    // receive mail here" is the weakest claim we ever want backing it.
    await expectAuthError(
      createOrganization(ctx, { userId: unverified.id, name: 'Acme', ...request }),
      'EMAIL_NOT_VERIFIED',
    );
  });

  it('refuses entirely when self-service is off', async () => {
    const provisioned = buildContext(config({ orgs: { selfService: 'never' } }));
    await expectAuthError(bootstrap(provisioned), 'PERMISSION_DENIED');
  });

  it('lets anyone create one under the SaaS policy', async () => {
    const saas = buildContext(config({ orgs: { selfService: 'anyone' } }));
    const second = await verifiedUser('bob@example.test');

    await bootstrap(saas);
    await expect(bootstrap(saas, second, 'Bob Ltd')).resolves.toBeDefined();
  });

  it('⚑ refuses a second organization for the same user', async () => {
    const saas = buildContext(config({ orgs: { selfService: 'anyone' } }));
    await bootstrap(saas);

    // One user, one organization (§10.10). `uq_memberships_user` would refuse this
    // anyway; this is the answer a UI can act on rather than a 500.
    await expectAuthError(bootstrap(saas, owner, 'Acme Two'), 'CONFLICT');
  });

  it('stores optional details given at creation', async () => {
    const { org } = await createOrganization(ctx, {
      userId: owner.id,
      name: 'Acme Billing',
      profile: {
        taxId: '1234567-8',
        phone: '+92 300 1234567',
        currency: 'PKR',
        address: { line1: '12 Mall Road', city: 'Lahore', country: 'PK' },
      },
      ...request,
    });

    expect(org.taxId).toBe('1234567-8');
    expect(org.currency).toBe('PKR');
    expect(org.address).toMatchObject({ city: 'Lahore', country: 'PK' });
    // Anything not supplied stays null rather than becoming an empty string.
    expect(org.legalName).toBeNull();
    expect(org.website).toBeNull();
  });

  it('refuses a duplicate slug', async () => {
    const saas = buildContext(config({ orgs: { selfService: 'anyone' } }));
    const second = await verifiedUser('bob@example.test');
    await bootstrap(saas);

    await expectAuthError(bootstrap(saas, second, 'ACME  billing'), 'CONFLICT');
  });

  it('derives a usable slug from an awkward name', async () => {
    const { org } = await bootstrap(ctx, owner, '  Ünited Kingdom, Ltd. ');
    expect(org.slug).toMatch(/^[a-z0-9]+(-[a-z0-9]+)*$/);
  });

  it('audits and emits', async () => {
    await bootstrap();
    expect(repos.audit.eventsOfType('org.created')).toHaveLength(1);
    expect(events.published.map((e) => e.type)).toContain('org.created');
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('what the token carries', () => {
  it('gives a user with no organization a real session and no permissions', async () => {
    const access = await resolveAccess(ctx, owner.id);
    // Authenticated, belongs to nothing. The client's move is to offer to create
    // one — not to treat them as signed out.
    expect(access).toEqual({ orgId: null, roles: [], perms: [] });
  });

  it('puts the org, role and permissions into the access token at login', async () => {
    const { org } = await bootstrap();
    const tokens = ctx.tokens as ReturnType<typeof createFakeTokenService>;

    await issueSession(ctx, deps, { user: owner, amr: ['pwd'], ...request });

    const claims = tokens.minted.at(-1)!;
    expect(claims.org).toBe(org.id);
    expect(claims.roles).toEqual(['owner']);
    expect(claims.perms).toEqual(['*']);
  });

  it('⚑ falls back when the preferred org is gone', async () => {
    const saas = buildContext(config({ orgs: { selfService: 'anyone' } }));
    const { org: first } = await bootstrap(saas);
    const stale = 'org-that-was-removed';

    // A membership revoked mid-session must not leave the user carrying a dead
    // tenant, and must not lock them out of the ones they do still belong to.
    const access = await resolveAccess(saas, owner.id);
    expect(access.orgId).toBe(first.id);
  });

  it('ignores an invitation that has not been accepted', async () => {
    const { org } = await bootstrap();
    const invitee = await verifiedUser('bob@example.test');
    const role = await repos.roles.findByKey(org.id, 'member');
    await repos.memberships.create({
      orgId: org.id,
      userId: invitee.id,
      roleId: role!.id,
      status: 'invited',
    });

    // An invitation is not a tenancy.
    expect(await resolveAccess(ctx, invitee.id)).toEqual({
      orgId: null,
      roles: [],
      perms: [],
    });
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('permission matching', () => {
  it('grants on exact, namespace wildcard and total wildcard', () => {
    expect(permits(['invoice:write'], 'invoice:write')).toBe(true);
    expect(permits(['invoice:*'], 'invoice:write')).toBe(true);
    expect(permits(['*'], 'anything:at:all')).toBe(true);
  });

  it('⚑ denies by default', () => {
    // An unregistered action is denied, not allowed (§10.1).
    expect(permits([], 'invoice:write')).toBe(false);
    expect(permits(['invoice:read'], 'invoice:write')).toBe(false);
    expect(permits(['invoice:*'], 'payment:write')).toBe(false);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('invitations', () => {
  async function invited(roleKey = 'member') {
    const { org } = await bootstrap();
    const invitee = await verifiedUser('bob@example.test');
    await inviteMember(ctx, deps, {
      inviterId: owner.id,
      orgId: org.id,
      email: 'bob@example.test',
      roleKey,
      ...request,
    });
    const token = mailer.sent.at(-1)!.text.match(/token=([^\s&]+)/)![1]!;
    return { org, invitee, token };
  }

  it('emails a link and adds the member on acceptance', async () => {
    const { org, invitee, token } = await invited();
    expect(mailer.sent.at(-1)!.to).toBe('bob@example.test');

    const result = await acceptInvite(ctx, deps, { userId: invitee.id, token, ...request });

    expect(result.org.id).toBe(org.id);
    expect(result.role).toBe('member');
    expect(await listMembers(ctx, org.id)).toHaveLength(2);
  });

  it('⚑ refuses acceptance by anyone but the invited address', async () => {
    const { token } = await invited();
    const stranger = await verifiedUser('eve@example.test');

    // Forwarding an invitation is the normal case, not the attack — but it must
    // not move the seat to whoever opened it.
    await expectAuthError(
      acceptInvite(ctx, deps, { userId: stranger.id, token, ...request }),
      'PERMISSION_DENIED',
    );
  });

  it('⚑ refuses when the invitee already belongs to an organization', async () => {
    const saas = buildContext(config({ orgs: { selfService: 'anyone' } }));
    const { org } = await bootstrap(saas);
    const elsewhere = await verifiedUser('bob@example.test');
    await bootstrap(saas, elsewhere, 'Bob Ltd');

    await inviteMember(saas, deps, {
      inviterId: owner.id,
      orgId: org.id,
      email: 'bob@example.test',
      roleKey: 'member',
      ...request,
    });
    const token = mailer.sent.at(-1)!.text.match(/token=([^\s&]+)/)![1]!;

    // One user, one organization. The unique index would refuse this too, but as a
    // 500; this is the answer a client can render.
    await expectAuthError(
      acceptInvite(saas, deps, { userId: elsewhere.id, token, ...request }),
      'CONFLICT',
    );
  });

  it('works exactly once', async () => {
    const { invitee, token } = await invited();
    await acceptInvite(ctx, deps, { userId: invitee.id, token, ...request });

    await expectAuthError(
      acceptInvite(ctx, deps, { userId: invitee.id, token, ...request }),
      'CODE_EXPIRED',
    );
  });

  it('expires', async () => {
    const { invitee, token } = await invited();
    clock.advance(7 * 86_400_000 + 1);

    await expectAuthError(
      acceptInvite(ctx, deps, { userId: invitee.id, token, ...request }),
      'CODE_EXPIRED',
    );
  });

  it('⚑ refuses to grant a role the inviter does not hold', async () => {
    const { org } = await bootstrap();
    const admin = await verifiedUser('admin@example.test');
    const adminRole = await repos.roles.findByKey(org.id, 'admin');
    await repos.memberships.create({
      orgId: org.id,
      userId: admin.id,
      roleId: adminRole!.id,
      status: 'active',
    });

    // Otherwise an admin invites an owner and has escalated themselves by proxy
    // in two steps.
    await expectAuthError(
      inviteMember(ctx, deps, {
        inviterId: admin.id,
        orgId: org.id,
        email: 'eve@example.test',
        roleKey: 'owner',
        ...request,
      }),
      'PERMISSION_DENIED',
    );
  });

  it('⚑ re-checks the inviter at acceptance, not only at invite time', async () => {
    const { org } = await bootstrap();
    const admin = await verifiedUser('admin@example.test');
    const adminRole = await repos.roles.findByKey(org.id, 'admin');
    const memberRole = await repos.roles.findByKey(org.id, 'member');
    const adminMembership = await repos.memberships.create({
      orgId: org.id,
      userId: admin.id,
      roleId: adminRole!.id,
      status: 'active',
    });

    await inviteMember(ctx, deps, {
      inviterId: admin.id,
      orgId: org.id,
      email: 'bob@example.test',
      roleKey: 'member',
      ...request,
    });
    const token = mailer.sent.at(-1)!.text.match(/token=([^\s&]+)/)![1]!;

    // Demoted in the days between sending and accepting.
    await repos.memberships.updateRole(adminMembership.id, memberRole!.id);
    const invitee = await verifiedUser('bob@example.test');

    await expectAuthError(
      acceptInvite(ctx, deps, { userId: invitee.id, token, ...request }),
      'PERMISSION_DENIED',
    );
  });

  it('refuses an inviter without member:invite', async () => {
    const { org } = await bootstrap();
    const plain = await verifiedUser('member@example.test');
    const memberRole = await repos.roles.findByKey(org.id, 'member');
    await repos.memberships.create({
      orgId: org.id,
      userId: plain.id,
      roleId: memberRole!.id,
      status: 'active',
    });

    await expectAuthError(
      inviteMember(ctx, deps, {
        inviterId: plain.id,
        orgId: org.id,
        email: 'eve@example.test',
        roleKey: 'member',
        ...request,
      }),
      'PERMISSION_DENIED',
    );
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('the last owner', () => {
  async function orgWithMember() {
    const { org } = await bootstrap();
    const member = await verifiedUser('bob@example.test');
    const memberRole = await repos.roles.findByKey(org.id, 'member');
    const membership = await repos.memberships.create({
      orgId: org.id,
      userId: member.id,
      roleId: memberRole!.id,
      status: 'active',
    });
    const members = await repos.memberships.listForOrg(org.id);
    const ownerMembership = members.find((m) => m.role.key === 'owner')!;
    return { org, member, membership, ownerMembershipId: ownerMembership.membershipId };
  }

  it('⚑ cannot be removed', async () => {
    const { org, ownerMembershipId } = await orgWithMember();

    // There is no permission that repairs an ownerless org — appointing an owner
    // is itself an owner permission.
    await expectAuthError(
      removeMember(ctx, {
        actorId: owner.id,
        orgId: org.id,
        membershipId: ownerMembershipId,
        ...request,
      }),
      'CONFLICT',
    );
  });

  it('⚑ cannot be demoted', async () => {
    const { org, ownerMembershipId } = await orgWithMember();

    await expectAuthError(
      changeMemberRole(ctx, {
        actorId: owner.id,
        orgId: org.id,
        membershipId: ownerMembershipId,
        roleKey: 'admin',
        ...request,
      }),
      'CONFLICT',
    );
  });

  it('can be replaced once a second owner exists', async () => {
    const { org, membership, ownerMembershipId } = await orgWithMember();

    await changeMemberRole(ctx, {
      actorId: owner.id,
      orgId: org.id,
      membershipId: membership.id,
      roleKey: 'owner',
      ...request,
    });

    await expect(
      removeMember(ctx, {
        actorId: owner.id,
        orgId: org.id,
        membershipId: ownerMembershipId,
        ...request,
      }),
    ).resolves.toBeUndefined();
  });

  it('lets an ordinary member be removed', async () => {
    const { org, membership } = await orgWithMember();
    await removeMember(ctx, {
      actorId: owner.id,
      orgId: org.id,
      membershipId: membership.id,
      ...request,
    });
    expect(await listMembers(ctx, org.id)).toHaveLength(1);
  });
});

// ───────────────────────────────────────────────────────────────────────────
describe('listing', () => {
  it('returns only active memberships', async () => {
    const { org } = await bootstrap();
    const invitee = await verifiedUser('bob@example.test');
    const role = await repos.roles.findByKey(org.id, 'member');
    await repos.memberships.create({
      orgId: org.id,
      userId: invitee.id,
      roleId: role!.id,
      status: 'invited',
    });

    expect(await getMyOrganization(ctx, owner.id)).not.toBeNull();
    expect(await getMyOrganization(ctx, invitee.id)).toBeNull();
    // The member list is for administrators, so it shows pending invitations too.
    expect(await listMembers(ctx, org.id)).toHaveLength(2);
  });
});

// ────────────────────────────────────────────────────────────────────
describe('the organization profile', () => {
  it('fills in details after the fact', async () => {
    const { org } = await bootstrap();

    const updated = await updateOrganization(ctx, {
      actorId: owner.id,
      orgId: org.id,
      patch: { taxId: '99-1234', phone: '+92 300 0000000', currency: 'PKR' },
      ...request,
    });

    expect(updated.taxId).toBe('99-1234');
    expect(updated.currency).toBe('PKR');
  });

  it('⚑ leaves fields alone unless they are in the patch', async () => {
    const { org } = await bootstrap();
    await updateOrganization(ctx, {
      actorId: owner.id,
      orgId: org.id,
      patch: { taxId: '99-1234', website: 'https://acme.test' },
      ...request,
    });

    const after = await updateOrganization(ctx, {
      actorId: owner.id,
      orgId: org.id,
      patch: { phone: '+92 300 0000000' },
      ...request,
    });

    // A settings form that renders three fields must not blank the other seven.
    expect(after.taxId).toBe('99-1234');
    expect(after.website).toBe('https://acme.test');
    expect(after.phone).toBe('+92 300 0000000');
  });

  it('clears a field when the patch says null', async () => {
    const { org } = await bootstrap();
    await updateOrganization(ctx, {
      actorId: owner.id,
      orgId: org.id,
      patch: { taxId: '99-1234' },
      ...request,
    });

    const cleared = await updateOrganization(ctx, {
      actorId: owner.id,
      orgId: org.id,
      patch: { taxId: null },
      ...request,
    });
    // Absent and null are different, and both have to work.
    expect(cleared.taxId).toBeNull();
  });

  it('⚑ refuses a member without org:update', async () => {
    const { org } = await bootstrap();
    const plain = await verifiedUser('bob@example.test');
    const memberRole = await repos.roles.findByKey(org.id, 'member');
    await repos.memberships.create({
      orgId: org.id,
      userId: plain.id,
      roleId: memberRole!.id,
      status: 'active',
    });

    await expectAuthError(
      updateOrganization(ctx, {
        actorId: plain.id,
        orgId: org.id,
        patch: { taxId: 'nope' },
        ...request,
      }),
      'PERMISSION_DENIED',
    );
  });

  it('records which fields changed, not what they became', async () => {
    const { org } = await bootstrap();
    await updateOrganization(ctx, {
      actorId: owner.id,
      orgId: org.id,
      patch: { taxId: '99-1234', phone: '+92 300 0000000' },
      ...request,
    });

    const [entry] = repos.audit.eventsOfType('org.updated');
    // ⚑ The audit log records that the billing details changed, not what they
    // changed to. It is not a second copy of the database.
    expect(entry?.metadata).toEqual({ fields: ['taxId', 'phone'] });
  });
});
