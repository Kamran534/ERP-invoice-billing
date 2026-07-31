/**
 * Organizations, membership and the permissions a token carries
 * (AUTH-MODULE-PLAN.md §10.5–§10.9, §5.14).
 *
 * The shape of this file follows one idea: **an organization is a boundary, and a
 * boundary needs an owner from the instant it exists.** Everything else — the
 * bootstrap rule, the transaction, the last-owner guard, the subset rule on
 * invitations — is that idea defended from a different direction.
 */

import { AuthError, errors } from '../errors.js';
import { audit, emit, type AuthContext, type RequestContext } from '../context.js';
import type { MembershipView, Org, OrgId, UserId } from '../ports.js';
import type { CryptoDeps } from './deps.js';

/** What a token needs to know about the caller's tenant. */
export interface ResolvedAccess {
  orgId: OrgId | null;
  roles: string[];
  perms: string[];
}

export const NO_ACCESS: ResolvedAccess = { orgId: null, roles: [], perms: [] };

/**
 * §10.8 — what the access token should say, resolved fresh.
 *
 * ⚑ Called at login, at **every refresh**, and at org switch. Re-reading here is
 * what makes a role change take effect within one access-token lifetime instead of
 * at the user's next login, and it is the reason access tokens can be short and
 * carry their permissions inline.
 */
export async function resolveAccess(
  ctx: AuthContext,
  userId: UserId,
  preferredOrgId: OrgId | null,
): Promise<ResolvedAccess> {
  if (ctx.config.tenancy === 'none') return NO_ACCESS;

  const memberships = await ctx.repos.memberships.listActiveForUser(userId);
  if (memberships.length === 0) return NO_ACCESS;

  // ⚑ Fall back rather than fail when the preferred org is gone. A membership
  // revoked mid-session must not leave the user carrying a dead tenant, and must
  // not lock them out of the orgs they do still belong to.
  const chosen =
    (preferredOrgId ? memberships.find((m) => m.org.id === preferredOrgId) : undefined) ??
    memberships[0]!;

  return {
    orgId: chosen.org.id,
    roles: [chosen.role.key],
    perms: await ctx.repos.roles.permissionsFor(chosen.role.id),
  };
}

/**
 * §10.1 — does this permission set allow the action?
 *
 * ⚑ Default deny. `*` is a full grant, `invoice:*` covers `invoice:write`, and
 * anything not matched is refused. An unregistered action is denied, not allowed.
 */
export function permits(perms: readonly string[], required: string): boolean {
  if (perms.includes('*') || perms.includes(required)) return true;
  const [namespace] = required.split(':');
  return namespace !== undefined && perms.includes(`${namespace}:*`);
}

/** True when `granted` is a subset of `held` — the rule invitations turn on. */
function withinGrantOf(held: readonly string[], granted: readonly string[]): boolean {
  if (held.includes('*')) return true;
  return granted.every((permission) => permits(held, permission));
}

// ── Creating one ────────────────────────────────────────────────────────────

export interface CreateOrgInput extends RequestContext {
  userId: UserId;
  name: string;
  slug?: string;
}

export async function createOrganization(
  ctx: AuthContext,
  input: CreateOrgInput,
): Promise<{ org: Org; role: string }> {
  const { selfService, systemRoles, ownerRole } = ctx.config.orgs;

  if (ctx.config.tenancy === 'none') {
    throw new AuthError('VALIDATION_FAILED', 'This deployment does not use organizations');
  }
  if (selfService === 'never') {
    throw errors.permissionDenied('org:create');
  }

  const user = await ctx.repos.users.findById(input.userId);
  if (!user) throw new AuthError('NOT_FOUND', 'User not found');

  // ⚑ A verified address, always. Creating a tenant is the most consequential
  // thing an unauthenticated-adjacent flow can do, and "can receive mail at this
  // address" is the weakest claim we ever want backing it.
  if (!user.emailVerifiedAt) {
    throw new AuthError('EMAIL_NOT_VERIFIED', 'Confirm your email address first');
  }

  const existing = await ctx.repos.memberships.listActiveForUser(input.userId);
  if (selfService === 'anyone' && existing.length > 0) {
    throw new AuthError('CONFLICT', 'You already belong to an organization');
  }

  const name = input.name.trim();
  const slug = normaliseSlug(input.slug ?? name);
  if (!slug) throw new AuthError('VALIDATION_FAILED', 'Organization name must contain a letter or digit');

  const result = await ctx.repos.orgs.createWithOwner({
    name,
    slug,
    ownerId: input.userId,
    roles: systemRoles,
    ownerRoleKey: ownerRole,
    // ⚑ Evaluated inside the transaction by the repository. Counting out here and
    // then inserting would let two people racing to claim a fresh instance both
    // see zero and both become owners of different orgs.
    onlyIfFirst: selfService === 'first-user',
  });

  if ('conflict' in result) {
    if (result.conflict === 'slug_taken') {
      throw new AuthError('CONFLICT', 'That organization name is already taken');
    }
    // `first-user` and someone got there first. Deliberately not "you were too
    // slow": from the caller's side this is simply not permitted any more.
    throw errors.permissionDenied('org:create');
  }

  await audit(ctx, {
    event: 'org.created',
    actorType: 'user',
    actorUserId: input.userId,
    orgId: result.org.id,
    targetType: 'org',
    targetId: result.org.id,
    ip: input.ip,
    userAgent: input.userAgent,
    metadata: { slug: result.org.slug, bootstrap: selfService === 'first-user' },
  });
  await emit(ctx, 'org.created', { orgId: result.org.id, ownerId: input.userId });

  return { org: result.org, role: ownerRole };
}

/**
 * Slug from a display name: lowercase, ASCII-ish, no leading or trailing dashes.
 * Uniqueness is the database's job — this only has to be *shaped* like a slug.
 */
function normaliseSlug(source: string): string {
  return source
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60);
}

// ── Reading ─────────────────────────────────────────────────────────────────

export async function listMyOrganizations(
  ctx: AuthContext,
  userId: UserId,
): Promise<MembershipView[]> {
  return ctx.repos.memberships.listActiveForUser(userId);
}

export interface MemberView {
  membershipId: string;
  userId: UserId;
  email: string | null;
  role: string;
  status: 'invited' | 'active' | 'suspended';
  joinedAt: Date | null;
}

export async function listMembers(ctx: AuthContext, orgId: OrgId): Promise<MemberView[]> {
  const rows = await ctx.repos.memberships.listForOrg(orgId);
  return rows.map((row) => ({
    membershipId: row.membershipId,
    userId: row.userId,
    email: row.email,
    role: row.role.key,
    status: row.status,
    joinedAt: row.joinedAt,
  }));
}

// ── Switching ───────────────────────────────────────────────────────────────

export interface SwitchOrgInput extends RequestContext {
  userId: UserId;
  sessionId: string;
  orgId: OrgId;
}

/**
 * §10.9. ⚑ Mints an access token and nothing else — no new refresh token, no new
 * session. The identity did not change: same human, same device, same login.
 * Rotating the chain here would leave every tab that had not switched holding a
 * spent token, which is indistinguishable from theft (§5.5.4).
 */
export async function switchOrg(
  ctx: AuthContext,
  input: SwitchOrgInput,
): Promise<{ accessToken: string; expiresIn: number; org: Org }> {
  const membership = await ctx.repos.memberships.findActive(input.userId, input.orgId);
  // Ownership before existence: a distinct answer for "real org, not yours" would
  // let anyone enumerate tenants.
  if (!membership) throw new AuthError('NOT_FOUND', 'Organization not found');

  const session = await ctx.repos.sessions.findById(input.sessionId);
  if (!session || session.revokedAt) {
    throw new AuthError('SESSION_REVOKED', 'This session has been signed out');
  }

  await ctx.repos.sessions.setOrg(session.id, input.orgId);

  const access = await ctx.tokens.mintAccess({
    sub: input.userId,
    sid: session.id,
    org: input.orgId,
    roles: [membership.role.key],
    perms: await ctx.repos.roles.permissionsFor(membership.role.id),
    amr: session.amr,
  });

  await audit(ctx, {
    event: 'org.switched',
    actorType: 'user',
    actorUserId: input.userId,
    orgId: input.orgId,
    sessionId: session.id,
    ip: input.ip,
    userAgent: input.userAgent,
  });

  return { accessToken: access.token, expiresIn: access.expiresIn, org: membership.org };
}

// ── Invitations (§5.14) ─────────────────────────────────────────────────────

export interface InviteMemberInput extends RequestContext {
  inviterId: UserId;
  orgId: OrgId;
  email: string;
  roleKey: string;
}

export async function inviteMember(
  ctx: AuthContext,
  deps: CryptoDeps,
  input: InviteMemberInput,
): Promise<{ status: 'invited' }> {
  const inviter = await ctx.repos.memberships.findActive(input.inviterId, input.orgId);
  if (!inviter) throw new AuthError('NOT_FOUND', 'Organization not found');

  const inviterPerms = await ctx.repos.roles.permissionsFor(inviter.role.id);
  if (!permits(inviterPerms, 'member:invite')) throw errors.permissionDenied('member:invite');

  const role = await ctx.repos.roles.findByKey(input.orgId, input.roleKey);
  if (!role) throw new AuthError('VALIDATION_FAILED', 'No such role');

  // ⚑ You cannot grant what you do not hold. Without this an `admin` invites an
  // `owner` and has escalated themselves by proxy in two steps.
  const grantedPerms = await ctx.repos.roles.permissionsFor(role.id);
  if (!withinGrantOf(inviterPerms, grantedPerms)) {
    throw errors.permissionDenied(`role:assign:${input.roleKey}`);
  }

  const email = input.email.trim();
  const secret = deps.newSecret('inv');

  await ctx.repos.oneTimeTokens.issue({
    // ⚑ Null: the invitee may not have an account yet, and the invitation is
    // addressed to an *address*, not to a user id. Binding it to a user we guessed
    // at would let an invite follow the wrong account.
    userId: null,
    purpose: 'org_invite',
    hash: deps.sha256(secret),
    payload: { orgId: input.orgId, roleKey: input.roleKey, email, invitedBy: input.inviterId },
    expiresAt: new Date(ctx.clock.now().getTime() + ctx.config.orgs.inviteTtl),
    requestedIp: input.ip,
  });

  const org = await ctx.repos.orgs.findById(input.orgId);
  const url = `${ctx.config.urls.appOrigin}${ctx.config.urls.invitePath}?token=${secret}`;

  await ctx.mailer.send({
    to: email,
    subject: `You have been invited to ${org?.name ?? ctx.config.appName}`,
    text:
      `You have been invited to join ${org?.name ?? ctx.config.appName} as a ${role.name}.\n\n` +
      `${url}\n\nThis invitation expires in 7 days.`,
    html:
      `<p>You have been invited to join <strong>${org?.name ?? ctx.config.appName}</strong> as a ${role.name}.</p>` +
      `<p><a href="${url}">Accept the invitation</a></p><p>This invitation expires in 7 days.</p>`,
  });

  await audit(ctx, {
    event: 'member.invited',
    actorType: 'user',
    actorUserId: input.inviterId,
    orgId: input.orgId,
    ip: input.ip,
    userAgent: input.userAgent,
    metadata: { role: input.roleKey },
  });

  return { status: 'invited' };
}

export interface AcceptInviteInput extends RequestContext {
  userId: UserId;
  token: string;
}

export async function acceptInvite(
  ctx: AuthContext,
  deps: CryptoDeps,
  input: AcceptInviteInput,
): Promise<{ org: Org; role: string }> {
  const user = await ctx.repos.users.findById(input.userId);
  if (!user) throw new AuthError('NOT_FOUND', 'User not found');

  const consumed = await ctx.repos.oneTimeTokens.consume(deps.sha256(input.token), 'org_invite');
  if (!consumed) {
    throw new AuthError('CODE_EXPIRED', 'This invitation is no longer valid');
  }

  const { orgId, roleKey, email, invitedBy } = consumed.payload as {
    orgId?: string;
    roleKey?: string;
    email?: string;
    invitedBy?: string;
  };
  if (!orgId || !roleKey || !email) {
    throw new AuthError('CODE_EXPIRED', 'This invitation is no longer valid');
  }

  // ⚑ The invitation is addressed to a mailbox. Accepting it while signed in as
  // someone else would let a forwarded link move a seat to the wrong account —
  // and the forwarding is the normal case, not the attack.
  if (user.email?.toLowerCase() !== email.toLowerCase()) {
    throw errors.permissionDenied('org:join');
  }

  const org = await ctx.repos.orgs.findById(orgId);
  const role = await ctx.repos.roles.findByKey(orgId, roleKey);
  if (!org || !role) throw new AuthError('CODE_EXPIRED', 'This invitation is no longer valid');

  const already = await ctx.repos.memberships.findActive(input.userId, orgId);
  if (already) return { org, role: already.role.key };

  // ⚑ Re-checked at acceptance, not only at invite time (§5.14). An inviter
  // demoted in the days since must not still be able to hand out what they held.
  if (invitedBy) {
    const inviter = await ctx.repos.memberships.findActive(invitedBy, orgId);
    const inviterPerms = inviter ? await ctx.repos.roles.permissionsFor(inviter.role.id) : [];
    const grantedPerms = await ctx.repos.roles.permissionsFor(role.id);
    if (!permits(inviterPerms, 'member:invite') || !withinGrantOf(inviterPerms, grantedPerms)) {
      throw errors.permissionDenied('org:join');
    }
  }

  await ctx.repos.memberships.create({
    orgId,
    userId: input.userId,
    roleId: role.id,
    status: 'active',
    invitedBy: invitedBy ?? null,
  });

  await audit(ctx, {
    event: 'member.joined',
    actorType: 'user',
    actorUserId: input.userId,
    orgId,
    ip: input.ip,
    userAgent: input.userAgent,
    metadata: { role: roleKey },
  });
  await emit(ctx, 'member.joined', { orgId, userId: input.userId, role: roleKey });

  return { org, role: role.key };
}

// ── Changing and removing members (§10.7) ───────────────────────────────────

export interface ChangeMemberInput extends RequestContext {
  actorId: UserId;
  orgId: OrgId;
  membershipId: string;
  roleKey?: string;
}

export async function changeMemberRole(
  ctx: AuthContext,
  input: ChangeMemberInput & { roleKey: string },
): Promise<void> {
  const { actor, target, actorPerms } = await loadPair(ctx, input);
  if (!permits(actorPerms, 'member:update')) throw errors.permissionDenied('member:update');

  const role = await ctx.repos.roles.findByKey(input.orgId, input.roleKey);
  if (!role) throw new AuthError('VALIDATION_FAILED', 'No such role');

  const grantedPerms = await ctx.repos.roles.permissionsFor(role.id);
  if (!withinGrantOf(actorPerms, grantedPerms)) {
    throw errors.permissionDenied(`role:assign:${input.roleKey}`);
  }

  await assertNotLastOwner(ctx, input.orgId, target, input.roleKey);

  await ctx.repos.memberships.updateRole(target.membershipId, role.id);
  await audit(ctx, {
    event: 'member.role_changed',
    actorType: 'user',
    actorUserId: actor.userId,
    orgId: input.orgId,
    targetType: 'membership',
    targetId: target.membershipId,
    ip: input.ip,
    userAgent: input.userAgent,
    metadata: { from: target.role.key, to: input.roleKey },
  });
}

export async function removeMember(ctx: AuthContext, input: ChangeMemberInput): Promise<void> {
  const { actor, target, actorPerms } = await loadPair(ctx, input);
  if (!permits(actorPerms, 'member:remove')) throw errors.permissionDenied('member:remove');

  await assertNotLastOwner(ctx, input.orgId, target, null);

  await ctx.repos.memberships.remove(target.membershipId);
  await audit(ctx, {
    event: 'member.removed',
    actorType: 'user',
    actorUserId: actor.userId,
    orgId: input.orgId,
    targetType: 'membership',
    targetId: target.membershipId,
    ip: input.ip,
    userAgent: input.userAgent,
  });
  await emit(ctx, 'member.removed', { orgId: input.orgId, membershipId: target.membershipId });
}

async function loadPair(ctx: AuthContext, input: ChangeMemberInput) {
  const actor = await ctx.repos.memberships.findActive(input.actorId, input.orgId);
  if (!actor) throw new AuthError('NOT_FOUND', 'Organization not found');

  const members = await ctx.repos.memberships.listForOrg(input.orgId);
  const target = members.find((m) => m.membershipId === input.membershipId);
  if (!target) throw new AuthError('NOT_FOUND', 'Member not found');

  return {
    actor: { ...actor, userId: input.actorId },
    target,
    actorPerms: await ctx.repos.roles.permissionsFor(actor.role.id),
  };
}

/**
 * ⚑ An organization must never be left without an active owner. There is no
 * permission that repairs one — the ability to appoint an owner *is* an owner
 * permission — so this is a refusal, not a warning.
 */
async function assertNotLastOwner(
  ctx: AuthContext,
  orgId: OrgId,
  target: { role: { key: string } },
  newRoleKey: string | null,
): Promise<void> {
  const ownerRole = ctx.config.orgs.ownerRole;
  if (target.role.key !== ownerRole) return;
  if (newRoleKey === ownerRole) return;

  const owners = await ctx.repos.memberships.countActiveWithRole(orgId, ownerRole);
  if (owners <= 1) {
    throw new AuthError(
      'CONFLICT',
      'This is the only owner — appoint another owner before removing or changing this one',
    );
  }
}
