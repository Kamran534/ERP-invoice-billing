/**
 * Organizations, memberships and roles (AUTH-MODULE-PLAN.md §10.5–§10.9).
 *
 * The only interesting query here is `createWithOwner`. Everything else is
 * ordinary reads with the joins a UI needs.
 */

import { and, asc, eq, sql } from 'drizzle-orm';
import type {
  Membership,
  MembershipRepo,
  MembershipView,
  Org,
  OrgId,
  OrgRepo,
  Role,
  RoleRepo,
  UserId,
} from '@auth/core';
import type { Database } from '../pool.js';
import type { RepoDeps } from './deps.js';
import { toUser } from './users.js';
import { memberships, orgs, rolePermissions, roles, users } from '../schema.js';

/**
 * Advisory-lock key for the "claim a fresh instance" path (§10.5). Arbitrary, and
 * only has to stay stable — anything else taking this key would serialise against
 * org bootstrap, which nothing else has any reason to do.
 */
const BOOTSTRAP_LOCK = 0x0a17_0009;

type OrgRow = typeof orgs.$inferSelect;
type RoleRow = typeof roles.$inferSelect;
type MembershipRow = typeof memberships.$inferSelect;

const toOrg = (row: OrgRow): Org => ({
  id: row.id,
  name: row.name,
  slug: row.slug,
  status: row.status,
  legalName: row.legalName,
  taxId: row.taxId,
  email: row.email,
  phone: row.phone,
  website: row.website,
  logoUrl: row.logoUrl,
  address: (row.address as Org['address']) ?? null,
  timezone: row.timezone,
  locale: row.locale,
  currency: row.currency,
  createdAt: row.createdAt,
});

const toRole = (row: RoleRow): Role => ({
  id: row.id,
  orgId: row.orgId,
  key: row.key,
  name: row.name,
  isSystem: row.isSystem,
});

/** Postgres `unique_violation`. Driver-shaped, so it is checked defensively. */
function isUniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === '23505';
}

const toMembership = (row: MembershipRow): Membership => ({
  id: row.id,
  orgId: row.orgId,
  userId: row.userId,
  roleId: row.roleId,
  status: row.status,
  joinedAt: row.joinedAt,
});

export function createOrgRepo(db: Database, deps: RepoDeps): OrgRepo {
  return {
    /**
     * ⚑ One transaction for the org, its roles and the owner's membership.
     *
     * Not for tidiness. An org with no owner is unreachable through the API —
     * nobody holds the permission to invite the first member — so a partial
     * failure here leaves something only a human with psql can repair.
     *
     * ⚑ The `onlyIfFirst` count runs *inside* the transaction. Two people racing
     * to claim a fresh instance must produce one owner and one refusal, and
     * counting outside the transaction gives both of them zero.
     */
    async createWithOwner(input) {
      return db.transaction(async (tx) => {
        if (input.onlyIfFirst) {
          // ⚑ The count alone is not enough, and an integration test proved it:
          // under READ COMMITTED a plain `SELECT count(*)` takes no lock, so two
          // transactions racing to claim a fresh instance both read zero and both
          // insert. The instance ends up with two owners of two organizations,
          // which is precisely the state `first-user` exists to prevent.
          //
          // A transaction-scoped advisory lock serialises exactly this path and
          // nothing else, and is released on commit or rollback either way. The
          // key is an arbitrary constant; it only has to be stable.
          await tx.execute(sql`SELECT pg_advisory_xact_lock(${BOOTSTRAP_LOCK})`);

          const [existing] = await tx.select({ n: sql<number>`count(*)::int` }).from(orgs);
          if ((existing?.n ?? 0) > 0) return { conflict: 'not_first' as const };
        }

        const [taken] = await tx.select({ id: orgs.id }).from(orgs).where(eq(orgs.slug, input.slug));
        if (taken) return { conflict: 'slug_taken' as const };

        const [orgRow] = await tx
          .insert(orgs)
          .values({
            id: deps.uuid(),
            name: input.name,
            slug: input.slug,
            ...(input.profile ?? {}),
          })
          .returning();
        const org = toOrg(orgRow!);

        const roleIds = new Map<string, string>();
        for (const role of input.roles) {
          const [roleRow] = await tx
            .insert(roles)
            .values({
              id: deps.uuid(),
              orgId: org.id,
              key: role.key,
              name: role.name,
              // ⚑ Marks them undeletable through the API. A tenant that loses its
              // `owner` role definition cannot appoint another owner.
              isSystem: true,
            })
            .returning();
          roleIds.set(role.key, roleRow!.id);

          if (role.permissions.length > 0) {
            await tx.insert(rolePermissions).values(
              role.permissions.map((permission) => ({ roleId: roleRow!.id, permission })),
            );
          }
        }

        const ownerRoleId = roleIds.get(input.ownerRoleKey);
        if (!ownerRoleId) {
          throw new Error(`owner role "${input.ownerRoleKey}" is not among the seeded roles`);
        }

        const [membershipRow] = await tx
          .insert(memberships)
          .values({
            id: deps.uuid(),
            orgId: org.id,
            userId: input.ownerId,
            roleId: ownerRoleId,
            status: 'active',
            joinedAt: new Date(),
          })
          .returning();

        return { org, membership: toMembership(membershipRow!) };
      });
    },

    /**
     * §10.12 — an employee account and its membership, in one transaction.
     *
     * ⚑ The conflict is decided by the unique index, not by a prior SELECT. Two
     * admins creating `ahmed` at the same moment both find the name free; only the
     * constraint can pick a winner, and catching its violation is how the loser
     * learns. `23505` is Postgres' unique_violation.
     */
    async createEmployee(input) {
      try {
        return await db.transaction(async (tx) => {
          const [userRow] = await tx
            .insert(users)
            .values({
              id: deps.uuid(),
              // ⚑ No email, ever. An employee has no mailbox here: no verification,
              // no reset link, and no way to sign in at the apex (§5.3.1).
              email: null,
              username: input.username,
              orgScopeId: input.orgId,
              name: input.name ?? null,
              passwordHash: input.passwordHash,
              passwordAlgo: 'argon2id',
              passwordUpdatedAt: new Date(),
              // Active immediately: the owner vouching for them *is* the
              // verification step an email account gets from its mailbox.
              status: 'active',
            })
            .returning();

          const [membershipRow] = await tx
            .insert(memberships)
            .values({
              id: deps.uuid(),
              orgId: input.orgId,
              userId: userRow!.id,
              roleId: input.roleId,
              status: 'active',
              invitedBy: input.createdBy,
              joinedAt: new Date(),
            })
            .returning();

          return { user: toUser(userRow!), membership: toMembership(membershipRow!) };
        });
      } catch (error) {
        if (isUniqueViolation(error)) return { conflict: 'username_taken' as const };
        throw error;
      }
    },

    async findById(id) {
      const [row] = await db.select().from(orgs).where(eq(orgs.id, id));
      return row ? toOrg(row) : null;
    },

    async findBySlug(slug) {
      const [row] = await db.select().from(orgs).where(eq(orgs.slug, slug));
      return row ? toOrg(row) : null;
    },

    /**
     * ⚑ Only the keys present in `patch` are written. Drizzle omits `undefined`
     * from the SET clause, so "leave alone" and "clear to null" stay distinct —
     * without that, a form that submits three fields would blank the other seven.
     */
    async updateProfile(id, patch) {
      const [row] = await db
        .update(orgs)
        .set({ ...patch, updatedAt: new Date() })
        .where(eq(orgs.id, id))
        .returning();
      if (!row) throw new Error(`org ${id} not found`);
      return toOrg(row);
    },

    async count() {
      const [row] = await db.select({ n: sql<number>`count(*)::int` }).from(orgs);
      return row?.n ?? 0;
    },
  };
}

export function createMembershipRepo(db: Database, deps: RepoDeps): MembershipRepo {
  const view = (m: MembershipRow, o: OrgRow, r: RoleRow): MembershipView => ({
    membershipId: m.id,
    org: toOrg(o),
    role: toRole(r),
    status: m.status,
    joinedAt: m.joinedAt,
  });

  return {
    /**
     * ⚑ `status = 'active'` only. An invitation is not a tenancy: a pending
     * membership must never resolve into an access token (§10.8).
     *
     * At most one row can exist per user — `uq_memberships_user` guarantees it —
     * so this is a lookup, not a list (§10.10).
     */
    async findActiveForUser(userId) {
      const [row] = await db
        .select({ m: memberships, o: orgs, r: roles })
        .from(memberships)
        .innerJoin(orgs, eq(orgs.id, memberships.orgId))
        .innerJoin(roles, eq(roles.id, memberships.roleId))
        .where(and(eq(memberships.userId, userId), eq(memberships.status, 'active')));
      return row ? view(row.m, row.o, row.r) : null;
    },

    async findActive(userId, orgId) {
      const [row] = await db
        .select({ m: memberships, o: orgs, r: roles })
        .from(memberships)
        .innerJoin(orgs, eq(orgs.id, memberships.orgId))
        .innerJoin(roles, eq(roles.id, memberships.roleId))
        .where(
          and(
            eq(memberships.userId, userId),
            eq(memberships.orgId, orgId),
            eq(memberships.status, 'active'),
          ),
        );
      return row ? view(row.m, row.o, row.r) : null;
    },

    async listForOrg(orgId) {
      const rows = await db
        .select({ m: memberships, o: orgs, r: roles, email: users.email })
        .from(memberships)
        .innerJoin(orgs, eq(orgs.id, memberships.orgId))
        .innerJoin(roles, eq(roles.id, memberships.roleId))
        .innerJoin(users, eq(users.id, memberships.userId))
        .where(eq(memberships.orgId, orgId))
        .orderBy(asc(memberships.joinedAt));
      return rows.map((row) => ({
        ...view(row.m, row.o, row.r),
        userId: row.m.userId,
        email: row.email,
      }));
    },

    async create(input) {
      const [row] = await db
        .insert(memberships)
        .values({
          id: deps.uuid(),
          orgId: input.orgId,
          userId: input.userId,
          roleId: input.roleId,
          status: input.status,
          invitedBy: input.invitedBy ?? null,
          joinedAt: input.status === 'active' ? new Date() : null,
        })
        .returning();
      return toMembership(row!);
    },

    async activate(id, at) {
      await db
        .update(memberships)
        .set({ status: 'active', joinedAt: at })
        .where(eq(memberships.id, id));
    },

    async updateRole(id, roleId) {
      await db.update(memberships).set({ roleId }).where(eq(memberships.id, id));
    },

    async remove(id) {
      await db.delete(memberships).where(eq(memberships.id, id));
    },

    /** ⚑ Active holders only — a suspended owner cannot rescue an ownerless org. */
    async countActiveWithRole(orgId, roleKey) {
      const [row] = await db
        .select({ n: sql<number>`count(*)::int` })
        .from(memberships)
        .innerJoin(roles, eq(roles.id, memberships.roleId))
        .where(
          and(
            eq(memberships.orgId, orgId),
            eq(memberships.status, 'active'),
            eq(roles.key, roleKey),
          ),
        );
      return row?.n ?? 0;
    },
  };
}

export function createRoleRepo(db: Database): RoleRepo {
  return {
    async findByKey(orgId, key) {
      const [row] = await db
        .select()
        .from(roles)
        .where(and(eq(roles.orgId, orgId), eq(roles.key, key)));
      return row ? toRole(row) : null;
    },

    async listForOrg(orgId) {
      const rows = await db.select().from(roles).where(eq(roles.orgId, orgId)).orderBy(asc(roles.key));
      return rows.map(toRole);
    },

    async permissionsFor(roleId) {
      const rows = await db
        .select({ permission: rolePermissions.permission })
        .from(rolePermissions)
        .where(eq(rolePermissions.roleId, roleId));
      return rows.map((row) => row.permission);
    },
  };
}
