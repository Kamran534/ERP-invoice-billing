/**
 * Employee accounts (AUTH-MODULE-PLAN.md §10.12).
 *
 * The people who work in an organization do not register — the owner creates them,
 * and what the owner creates is a username scoped to that organization. They have
 * no email address, sign in only at their tenant's own subdomain (§5.3.1, §10.13),
 * and exist entirely at the owner's discretion.
 *
 * Everything here is an authenticated, permissioned operation on *somebody else's*
 * credentials, which is a shape worth naming: the rules below are not about
 * proving who the caller is — the route already did that — they are about stopping
 * an admin doing something to an account an admin should not be able to touch.
 */

import { AuthError, errors } from '../errors.js';
import { audit, emit, type AuthContext, type RequestContext } from '../context.js';
import type { MembershipStatus, OrgId, User, UserId } from '../ports.js';
import { permits } from './orgs.js';
import { assertPasswordAcceptable } from './register.js';

/** Usernames are typed by people, daily. Deliberately narrow, and case-folded. */
const USERNAME_PATTERN = /^[a-z0-9][a-z0-9._-]{1,38}[a-z0-9]$/;

export interface EmployeeView {
  userId: UserId;
  membershipId: string;
  username: string;
  name: string | null;
  role: string;
  status: MembershipStatus;
  accountStatus: User['status'];
  lastLoginAt: Date | null;
  createdAt: Date;
}

export interface CreateEmployeeInput extends RequestContext {
  actorId: UserId;
  orgId: OrgId;
  username: string;
  password: string;
  name?: string | null;
  roleKey: string;
}

export async function createEmployee(
  ctx: AuthContext,
  input: CreateEmployeeInput,
): Promise<EmployeeView> {
  const actorPerms = await actorPermissions(ctx, input.actorId, input.orgId);
  if (!permits(actorPerms, 'member:invite')) throw errors.permissionDenied('member:invite');

  const username = input.username.trim().toLowerCase();
  if (!USERNAME_PATTERN.test(username)) {
    throw new AuthError(
      'VALIDATION_FAILED',
      'Use 3–40 characters: letters, digits, dot, dash or underscore',
      { details: { field: 'username' } },
    );
  }

  const role = await resolveGrantableRole(ctx, actorPerms, input.orgId, input.roleKey);

  // ⚑ The same password policy as a self-service signup, breach check included.
  // Someone typing a password *for* another person is the case most likely to
  // produce `Welcome123`, and the account they are creating is not theirs to
  // weaken — the employee is the one who lives with it.
  await assertPasswordAcceptable(ctx, input.password);
  const hashed = await ctx.hasher.hash(input.password);

  const result = await ctx.repos.orgs.createEmployee({
    orgId: input.orgId,
    username,
    name: input.name ?? null,
    passwordHash: hashed.hash,
    roleId: role.id,
    createdBy: input.actorId,
  });

  if ('conflict' in result) {
    throw new AuthError('CONFLICT', 'That username is already taken in this organization', {
      details: { field: 'username' },
    });
  }

  await audit(ctx, {
    event: 'member.joined',
    actorType: 'user',
    actorUserId: input.actorId,
    orgId: input.orgId,
    targetType: 'user',
    targetId: result.user.id,
    ip: input.ip,
    userAgent: input.userAgent,
    // ⚑ The username, never the password — not even its length.
    metadata: { kind: 'employee', username, role: input.roleKey },
  });
  await emit(ctx, 'member.joined', {
    orgId: input.orgId,
    userId: result.user.id,
    role: input.roleKey,
  });

  return {
    userId: result.user.id,
    membershipId: result.membership.id,
    username,
    name: result.user.name,
    role: input.roleKey,
    status: 'active',
    accountStatus: result.user.status,
    lastLoginAt: null,
    createdAt: result.user.createdAt,
  };
}

export async function listEmployees(
  ctx: AuthContext,
  input: { actorId: UserId; orgId: OrgId },
): Promise<EmployeeView[]> {
  const actorPerms = await actorPermissions(ctx, input.actorId, input.orgId);
  if (!permits(actorPerms, 'member:read')) throw errors.permissionDenied('member:read');

  const members = await ctx.repos.memberships.listForOrg(input.orgId);
  const employees: EmployeeView[] = [];

  for (const member of members) {
    const user = await ctx.repos.users.findById(member.userId);
    // Email accounts belong to the members endpoint; this one lists the accounts
    // the owner created and is expected to administer.
    if (!user?.username) continue;
    employees.push({
      userId: user.id,
      membershipId: member.membershipId,
      username: user.username,
      name: user.name,
      role: member.role.key,
      status: member.status,
      accountStatus: user.status,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt,
    });
  }

  return employees;
}

export interface ResetEmployeePasswordInput extends RequestContext {
  actorId: UserId;
  orgId: OrgId;
  employeeId: UserId;
  password: string;
}

/**
 * Set a new password for an employee.
 *
 * ⚑ Every session that employee holds dies with it. A reset that leaves the old
 * sessions alive is not a reset — it is a second password, and the reason someone
 * is resetting is usually that the first one is in the wrong hands.
 */
export async function resetEmployeePassword(
  ctx: AuthContext,
  input: ResetEmployeePasswordInput,
): Promise<void> {
  const actorPerms = await actorPermissions(ctx, input.actorId, input.orgId);
  if (!permits(actorPerms, 'member:update')) throw errors.permissionDenied('member:update');

  const employee = await requireEmployee(ctx, input.orgId, input.employeeId);
  await assertActingWithinGrant(ctx, actorPerms, input.orgId, input.employeeId);
  await assertPasswordAcceptable(ctx, input.password);

  const hashed = await ctx.hasher.hash(input.password);
  await ctx.repos.users.update(employee.id, {
    passwordHash: hashed.hash,
    passwordAlgo: 'argon2id',
    // A credential-change marker: refresh (§5.5.3) refuses every session created
    // before this instant, which is what makes the revocation below stick.
    passwordUpdatedAt: ctx.clock.now(),
  });
  await ctx.repos.sessions.revokeAllForUser(employee.id, 'password_change');

  await audit(ctx, {
    event: 'password.changed',
    actorType: 'user',
    actorUserId: input.actorId,
    orgId: input.orgId,
    targetType: 'user',
    targetId: employee.id,
    ip: input.ip,
    userAgent: input.userAgent,
    metadata: { kind: 'employee', by: 'admin' },
  });
}

export interface SetEmployeeStatusInput extends RequestContext {
  actorId: UserId;
  orgId: OrgId;
  employeeId: UserId;
  status: 'active' | 'suspended';
}

export async function setEmployeeStatus(
  ctx: AuthContext,
  input: SetEmployeeStatusInput,
): Promise<void> {
  const actorPerms = await actorPermissions(ctx, input.actorId, input.orgId);
  if (!permits(actorPerms, 'member:update')) throw errors.permissionDenied('member:update');

  const employee = await requireEmployee(ctx, input.orgId, input.employeeId);
  await assertActingWithinGrant(ctx, actorPerms, input.orgId, input.employeeId);

  await ctx.repos.users.update(employee.id, { status: input.status });

  if (input.status === 'suspended') {
    // ⚑ Sessions too. Suspending someone who holds a live access token suspends
    // them in ten minutes' time, which is not what anybody means by the word.
    await ctx.repos.sessions.revokeAllForUser(employee.id, 'admin');
  }

  await audit(ctx, {
    event: input.status === 'suspended' ? 'member.suspended' : 'member.restored',
    actorType: 'user',
    actorUserId: input.actorId,
    orgId: input.orgId,
    targetType: 'user',
    targetId: employee.id,
    ip: input.ip,
    userAgent: input.userAgent,
    metadata: { kind: 'employee' },
  });
}

// ── guards ──────────────────────────────────────────────────────────────────

async function actorPermissions(
  ctx: AuthContext,
  userId: UserId,
  orgId: OrgId,
): Promise<string[]> {
  const membership = await ctx.repos.memberships.findActive(userId, orgId);
  // Not a member of the org named in the token: nothing here is visible, and the
  // answer is the same one a member without the permission gets.
  if (!membership) throw errors.permissionDenied('member:read');
  return ctx.repos.roles.permissionsFor(membership.role.id);
}

async function requireEmployee(
  ctx: AuthContext,
  orgId: OrgId,
  employeeId: UserId,
): Promise<User> {
  const employee = await ctx.repos.users.findById(employeeId);

  // ⚑ Scope, not merely existence. Without the `orgScopeId` check an admin of one
  // tenant could reset the password of any user id they can obtain — and a uuid in
  // a URL is not an authorization.
  if (!employee || !employee.username || employee.orgScopeId !== orgId) {
    throw new AuthError('NOT_FOUND', 'No such employee in this organization');
  }
  return employee;
}

/**
 * ⚑ The subset rule (§10.7) applied to *acting on* someone rather than inviting
 * them: nobody may reset the password of, or suspend, an account whose role grants
 * more than their own. Without it, `admin` is a role that can take the owner's
 * account simply by resetting its password.
 */
async function assertActingWithinGrant(
  ctx: AuthContext,
  actorPerms: readonly string[],
  orgId: OrgId,
  targetId: UserId,
): Promise<void> {
  const target = await ctx.repos.memberships.findActive(targetId, orgId);
  if (!target) return;
  const targetPerms = await ctx.repos.roles.permissionsFor(target.role.id);
  if (!withinGrantOf(actorPerms, targetPerms)) throw errors.permissionDenied('member:update');
}

function withinGrantOf(held: readonly string[], granted: readonly string[]): boolean {
  if (held.includes('*')) return true;
  return granted.every((permission) => permits(held, permission));
}

/**
 * The role to grant, refusing anything the actor could not hold themselves.
 *
 * ⚑ `owner` is refused outright, whoever is asking. The owner is the account that
 * receives the password-reset mail; an employee has no mailbox, so an employee
 * owner is a tenant one forgotten password away from needing a database
 * administrator (§10.12).
 */
async function resolveGrantableRole(
  ctx: AuthContext,
  actorPerms: readonly string[],
  orgId: OrgId,
  roleKey: string,
): Promise<{ id: string }> {
  if (roleKey === ctx.config.orgs.ownerRole) {
    throw new AuthError('VALIDATION_FAILED', 'An employee account cannot be the owner', {
      details: { field: 'role' },
    });
  }

  const role = await ctx.repos.roles.findByKey(orgId, roleKey);
  if (!role) {
    throw new AuthError('VALIDATION_FAILED', 'No such role', { details: { field: 'role' } });
  }

  const granted = await ctx.repos.roles.permissionsFor(role.id);
  if (!withinGrantOf(actorPerms, granted)) throw errors.permissionDenied('member:invite');

  return role;
}
