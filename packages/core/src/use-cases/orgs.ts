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
import type { MembershipView, Org, OrgId, OrgProfile, UserId } from '../ports.js';
import type { CryptoDeps } from './deps.js';
import { checkSlug, normaliseSlug } from '../slug.js';

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
 * ⚑ Called at login and at **every refresh**. Re-reading here is what makes a role
 * change take effect within one access-token lifetime instead of at the user's next
 * login, and it is the reason access tokens can be short and carry their
 * permissions inline.
 *
 * ⚑ There is nothing to choose between: a user belongs to one organization
 * (§10.10). A session pointing at an org the user is no longer in simply resolves
 * to whatever they are in now, or to nothing — a revoked membership must not leave
 * a session carrying a dead tenant.
 */
export async function resolveAccess(ctx: AuthContext, userId: UserId): Promise<ResolvedAccess> {
  if (ctx.config.tenancy === 'none') return NO_ACCESS;

  const membership = await ctx.repos.memberships.findActiveForUser(userId);
  if (!membership) return NO_ACCESS;

  return {
    orgId: membership.org.id,
    roles: [membership.role.key],
    perms: await ctx.repos.roles.permissionsFor(membership.role.id),
  };
}

/**
 * Mints an access token for an existing session, picking up whatever organization
 * and permissions the user has *now*.
 *
 * Used after creating an organization or accepting an invitation: the caller's
 * current token still says they belong to nothing, and making them refresh to
 * discover otherwise is a round trip for no reason.
 *
 * ⚑ Access token only. No refresh rotation, no new session — nothing about the
 * identity changed.
 */
export async function mintAccessForSession(
  ctx: AuthContext,
  userId: UserId,
  sessionId: string,
): Promise<{ accessToken: string; expiresIn: number }> {
  const session = await ctx.repos.sessions.findById(sessionId);
  if (!session || session.revokedAt) {
    throw new AuthError('SESSION_REVOKED', 'This session has been signed out');
  }

  const access = await resolveAccess(ctx, userId);
  if (access.orgId !== session.orgId) {
    await ctx.repos.sessions.setOrg(session.id, access.orgId);
  }

  const minted = await ctx.tokens.mintAccess({
    sub: userId,
    sid: session.id,
    org: access.orgId,
    roles: access.roles,
    perms: access.perms,
    amr: session.amr,
  });
  return { accessToken: minted.token, expiresIn: minted.expiresIn };
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
  /** Everything optional — an organization is usable with a name alone (§10.11). */
  profile?: Partial<OrgProfile>;
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

  // ⚑ Checked in every mode, not only under `anyone` (§10.10). One user, one
  // organization — and the database agrees, via `uq_memberships_user`, so this is
  // the friendly error rather than the only defence.
  const existing = await ctx.repos.memberships.findActiveForUser(input.userId);
  if (existing) {
    throw new AuthError('CONFLICT', 'You already belong to an organization');
  }

  const name = input.name.trim();
  const slug = normaliseSlug(input.slug ?? name);

  // ⚑ §10.13 — the slug is this tenant's subdomain from here on, so it is checked
  // against DNS rules and the reserved list *before* the insert. A tenant that
  // exists at a name nobody can resolve is a support ticket the database cannot
  // undo, because the slug is not editable afterwards.
  const problem = checkSlug(slug);
  if (problem === 'empty') {
    throw new AuthError('VALIDATION_FAILED', 'Organization name must contain a letter or digit', {
      details: { field: 'name' },
    });
  }
  if (problem === 'malformed') {
    throw new AuthError('VALIDATION_FAILED', 'That name cannot be turned into a web address', {
      details: { field: 'name' },
    });
  }
  if (problem === 'reserved') {
    throw new AuthError('CONFLICT', 'That name is reserved. Please choose another', {
      details: { field: 'name' },
    });
  }

  const result = await ctx.repos.orgs.createWithOwner({
    name,
    slug,
    ...(input.profile ? { profile: input.profile } : {}),
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

// ── Reading ─────────────────────────────────────────────────────────────────

export async function getMyOrganization(
  ctx: AuthContext,
  userId: UserId,
): Promise<MembershipView | null> {
  return ctx.repos.memberships.findActiveForUser(userId);
}

export interface UpdateOrgInput extends RequestContext {
  actorId: UserId;
  orgId: OrgId;
  patch: Partial<OrgProfile> & { name?: string };
}

/**
 * §10.11 — fill in the details after the fact.
 *
 * ⚑ The slug is deliberately not updatable here. It appears in invitation links
 * and in anything a customer has bookmarked or scripted, so renaming it is a
 * migration rather than an edit.
 */
export async function updateOrganization(ctx: AuthContext, input: UpdateOrgInput): Promise<Org> {
  const membership = await ctx.repos.memberships.findActive(input.actorId, input.orgId);
  if (!membership) throw new AuthError('NOT_FOUND', 'Organization not found');

  const perms = await ctx.repos.roles.permissionsFor(membership.role.id);
  if (!permits(perms, 'org:update')) throw errors.permissionDenied('org:update');

  const org = await ctx.repos.orgs.updateProfile(input.orgId, input.patch);

  await audit(ctx, {
    event: 'org.updated',
    actorType: 'user',
    actorUserId: input.actorId,
    orgId: input.orgId,
    targetType: 'org',
    targetId: input.orgId,
    ip: input.ip,
    userAgent: input.userAgent,
    // ⚑ Field names only. An audit row records that the billing address changed,
    // not what it changed to — the log is not a second copy of the database.
    metadata: { fields: Object.keys(input.patch) },
  });

  return org;
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

  const already = await ctx.repos.memberships.findActiveForUser(input.userId);
  if (already) {
    // Already here — accepting again is a no-op rather than an error, because a
    // double-clicked link is not a mistake worth reporting.
    if (already.org.id === orgId) return { org, role: already.role.key };
    // ⚑ In a different one. One user, one organization (§10.10) — and the unique
    // index would refuse this anyway, as a 500 rather than something a UI can act on.
    throw new AuthError(
      'CONFLICT',
      'You already belong to an organization — leave it before joining another',
    );
  }

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
