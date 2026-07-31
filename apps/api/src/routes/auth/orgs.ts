/**
 * Organizations, membership and tenant switching (§10.5–§10.9, §5.14).
 *
 * ⚑ `orgId` is taken from the **verified token**, never from a path parameter or a
 * body field (§10.3). `/orgs/current/...` reads oddly next to a REST convention of
 * `/orgs/{id}/...`, and it is deliberate: a route that accepts the tenant from the
 * URL invites exactly one bug, and that bug is cross-tenant access.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  AuthError,
  acceptInvite,
  changeMemberRole,
  createOrganization,
  inviteMember,
  listMembers,
  listMyOrganizations,
  removeMember,
  switchOrg,
} from '@auth/core';
import { route, errorSchema } from '../../lib/schema.js';
import { TAGS } from '../../plugins/swagger.js';
import { okResponse, uuidField } from '../../schemas/auth.js';
import {
  acceptInviteBody,
  changeRoleBody,
  createOrgBody,
  inviteBody,
  memberSummary,
  membershipSummary,
  organization,
  switchOrgBody,
  switchOrgResponse,
} from '../../schemas/orgs.js';
import { setSessionCookies } from '../../lib/cookies.js';
import { requestContext } from '../../lib/present.js';

const cookieSecurity: Array<Record<string, string[]>> = [
  { cookieAuth: [], csrfToken: [] },
  { bearerAuth: [] },
];

const presentOrg = (org: {
  id: string;
  name: string;
  slug: string;
  status: 'active' | 'suspended';
  createdAt: Date;
}) => ({ ...org, createdAt: org.createdAt.toISOString() });

export async function orgRoutes(app: FastifyInstance): Promise<void> {
  const { auth, authDeps } = app;

  /** The tenant the caller is acting in, from the token. */
  function activeOrg(request: FastifyRequest): string {
    const orgId = request.auth?.org;
    if (!orgId) {
      throw new AuthError(
        'ORG_CONTEXT_REQUIRED',
        'Select or create an organization before calling this',
      );
    }
    return orgId;
  }

  // ── Creating and listing ──────────────────────────────────────────────────
  app.post(
    '/auth/orgs',
    {
      preHandler: app.requireAuth,
      config: { rateLimit: { max: 10, timeWindow: '1 hour' } },
      schema: route({
        summary: 'Create an organization',
        description:
          'Creates the organization, seeds its roles, and makes you its **owner** — all in one ' +
          'transaction, because an organization with no owner cannot be repaired through the API.\n\n' +
          'Who may call this depends on `orgs.selfService`:\n\n' +
          '* `first-user` *(default)* — only while no organization exists at all. The first person ' +
          'to finish verification claims the instance; everyone else joins by invitation.\n' +
          '* `anyone` — any verified user who is not already a member of one.\n' +
          '* `never` — always `403`.\n\n' +
          '⚑ Your existing access token does **not** carry the new organization. Refresh, or read ' +
          'the token returned here, before calling anything org-scoped.',
        tags: [TAGS.auth],
        operationId: 'createOrganization',
        security: cookieSecurity,
        rateLimit: '10 per hour per IP',
        body: createOrgBody,
        response: {
          201: z.object({ org: organization, role: z.string(), accessToken: z.string().optional() }),
          403: errorSchema,
          409: errorSchema,
        },
      }),
    },
    async (request, reply) => {
      const body = request.body as { name: string; slug?: string };
      const { org, role } = await createOrganization(auth, {
        userId: request.auth!.sub,
        name: body.name,
        ...(body.slug ? { slug: body.slug } : {}),
        ...requestContext(request),
      });

      // The caller is now an owner, and their current token says otherwise.
      // Switching immediately saves every client from having to know that.
      const switched = await switchOrg(auth, {
        userId: request.auth!.sub,
        sessionId: request.auth!.sid,
        orgId: org.id,
        ...requestContext(request),
      });

      setSessionCookies(reply, auth.config, {
        accessToken: switched.accessToken,
        expiresIn: switched.expiresIn,
        csrfToken: authDeps.newSecret('csrf'),
      });

      return reply.code(201).send({
        org: presentOrg(org),
        role,
        ...(auth.config.cookies.mode !== 'cookie' ? { accessToken: switched.accessToken } : {}),
      });
    },
  );

  app.get(
    '/auth/orgs',
    {
      preHandler: app.requireAuth,
      schema: route({
        summary: 'Organizations you belong to',
        description:
          'Active memberships only — a pending invitation is not a tenancy and never appears here. ' +
          'An empty array means the account belongs to nothing yet; offer to create one.',
        tags: [TAGS.auth],
        operationId: 'listOrganizations',
        security: cookieSecurity,
        response: { 200: z.object({ organizations: z.array(membershipSummary) }), 401: errorSchema },
      }),
    },
    async (request) => {
      const rows = await listMyOrganizations(auth, request.auth!.sub);
      return {
        organizations: rows.map((row) => ({
          membershipId: row.membershipId,
          org: presentOrg(row.org),
          role: row.role.key,
          status: row.status,
          joinedAt: row.joinedAt?.toISOString() ?? null,
        })),
      };
    },
  );

  app.post(
    '/auth/token/switch-org',
    {
      preHandler: app.requireAuth,
      schema: route({
        summary: 'Switch the active organization',
        description:
          'Mints a new access token scoped to another organization you belong to.\n\n' +
          '⚑ No new refresh token and no new session — the identity has not changed. Rotating the ' +
          'chain here would leave every tab that had not switched holding a spent token, which is ' +
          'indistinguishable from theft (§5.5.4).',
        tags: [TAGS.auth],
        operationId: 'switchOrg',
        security: cookieSecurity,
        body: switchOrgBody,
        response: { 200: switchOrgResponse, 401: errorSchema, 404: errorSchema },
      }),
    },
    async (request, reply) => {
      const { orgId } = request.body as { orgId: string };
      const result = await switchOrg(auth, {
        userId: request.auth!.sub,
        sessionId: request.auth!.sid,
        orgId,
        ...requestContext(request),
      });

      setSessionCookies(reply, auth.config, {
        accessToken: result.accessToken,
        expiresIn: result.expiresIn,
        csrfToken: authDeps.newSecret('csrf'),
      });

      return {
        ...(auth.config.cookies.mode !== 'cookie' ? { accessToken: result.accessToken } : {}),
        expiresIn: result.expiresIn,
        org: presentOrg(result.org),
      };
    },
  );

  // ── Members ───────────────────────────────────────────────────────────────
  app.get(
    '/auth/orgs/current/members',
    {
      preHandler: app.requirePermission('member:read'),
      schema: route({
        summary: 'List members of the active organization',
        tags: [TAGS.auth],
        operationId: 'listMembers',
        security: cookieSecurity,
        response: {
          200: z.object({ members: z.array(memberSummary) }),
          401: errorSchema,
          403: errorSchema,
        },
      }),
    },
    async (request) => {
      const members = await listMembers(auth, activeOrg(request));
      return {
        members: members.map((member) => ({
          ...member,
          joinedAt: member.joinedAt?.toISOString() ?? null,
        })),
      };
    },
  );

  app.post(
    '/auth/orgs/current/invites',
    {
      preHandler: app.requirePermission('member:invite'),
      config: { rateLimit: { max: 30, timeWindow: '1 hour' } },
      schema: route({
        summary: 'Invite someone to the active organization',
        description:
          'Emails a single-use invitation, valid for 7 days.\n\n' +
          '⚑ You may only grant a role whose permissions are a subset of your own — an `admin` ' +
          'cannot invite an `owner`. The check runs again when the invitation is *accepted*, so a ' +
          'demoted inviter cannot still hand out what they used to hold.\n\n' +
          '⚑ Answers `202` whether or not the address already has an account, for the same ' +
          'enumeration reason as registration.',
        tags: [TAGS.auth],
        operationId: 'inviteMember',
        security: cookieSecurity,
        rateLimit: '30 per hour per IP',
        body: inviteBody,
        response: {
          202: z.object({ status: z.literal('invited') }),
          401: errorSchema,
          403: errorSchema,
        },
      }),
    },
    async (request, reply) => {
      const body = request.body as { email: string; role: string };
      const result = await inviteMember(auth, authDeps, {
        inviterId: request.auth!.sub,
        orgId: activeOrg(request),
        email: body.email,
        roleKey: body.role,
        ...requestContext(request),
      });
      return reply.code(202).send(result);
    },
  );

  app.post(
    '/auth/invites/accept',
    {
      preHandler: app.requireAuth,
      config: { rateLimit: { max: 20, timeWindow: '1 hour' } },
      schema: route({
        summary: 'Accept an invitation',
        description:
          'Requires being signed in **as the invited address**. ⚑ A forwarded invitation must not ' +
          'move a seat to whoever happened to open it, and forwarding is the normal case rather ' +
          'than the attack.',
        tags: [TAGS.auth],
        operationId: 'acceptInvite',
        security: cookieSecurity,
        body: acceptInviteBody,
        response: {
          200: z.object({ org: organization, role: z.string() }),
          403: errorSchema,
          410: errorSchema,
        },
      }),
    },
    async (request) => {
      const { token } = request.body as { token: string };
      const result = await acceptInvite(auth, authDeps, {
        userId: request.auth!.sub,
        token,
        ...requestContext(request),
      });
      return { org: presentOrg(result.org), role: result.role };
    },
  );

  app.patch(
    '/auth/orgs/current/members/:id',
    {
      preHandler: app.requirePermission('member:update'),
      schema: route({
        summary: "Change a member's role",
        description:
          '⚑ Refuses with `409` when it would leave the organization without an active owner. ' +
          'There is no permission that repairs that state — appointing an owner is itself an ' +
          'owner permission.',
        tags: [TAGS.auth],
        operationId: 'changeMemberRole',
        security: cookieSecurity,
        params: z.object({ id: uuidField }),
        body: changeRoleBody,
        response: { 200: okResponse, 403: errorSchema, 404: errorSchema, 409: errorSchema },
      }),
    },
    async (request) => {
      const { id } = request.params as { id: string };
      const { role } = request.body as { role: string };
      await changeMemberRole(auth, {
        actorId: request.auth!.sub,
        orgId: activeOrg(request),
        membershipId: id,
        roleKey: role,
        ...requestContext(request),
      });
      return { ok: true as const };
    },
  );

  app.delete(
    '/auth/orgs/current/members/:id',
    {
      preHandler: app.requirePermission('member:remove'),
      schema: route({
        summary: 'Remove a member',
        description: '⚑ Refuses with `409` when it would leave the organization without an owner.',
        tags: [TAGS.auth],
        operationId: 'removeMember',
        security: cookieSecurity,
        params: z.object({ id: uuidField }),
        response: { 204: null, 403: errorSchema, 404: errorSchema, 409: errorSchema },
      }),
    },
    async (request, reply) => {
      const { id } = request.params as { id: string };
      await removeMember(auth, {
        actorId: request.auth!.sub,
        orgId: activeOrg(request),
        membershipId: id,
        ...requestContext(request),
      });
      return reply.code(204).send();
    },
  );
}
