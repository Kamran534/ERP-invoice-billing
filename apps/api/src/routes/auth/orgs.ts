/**
 * Organizations, membership and invitations (§10.5–§10.11, §5.14).
 *
 * ⚑ `orgId` is taken from the **verified token**, never from a path parameter or a
 * body field (§10.3). `/orgs/current/...` reads oddly next to a REST convention of
 * `/orgs/{id}/...`, and it is deliberate: a route that accepts the tenant from the
 * URL invites exactly one bug, and that bug is cross-tenant access.
 *
 * ⚑ There is no `switch-org`. A user belongs to one organization (§10.10), so
 * there is nothing to switch to.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  AuthError,
  acceptInvite,
  changeMemberRole,
  createOrganization,
  getMyOrganization,
  inviteMember,
  listMembers,
  mintAccessForSession,
  removeMember,
  updateOrganization,
  type Org,
  type OrgProfile,
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
  updateOrgBody,
} from '../../schemas/orgs.js';
import { setSessionCookies } from '../../lib/cookies.js';
import { requestContext } from '../../lib/present.js';

const cookieSecurity: Array<Record<string, string[]>> = [
  { cookieAuth: [], csrfToken: [] },
  { bearerAuth: [] },
];

const presentOrg = (org: Org) => ({ ...org, createdAt: org.createdAt.toISOString() });

/** The profile keys a client may set, so nothing else in a body can reach the row. */
const PROFILE_KEYS = [
  'legalName',
  'taxId',
  'email',
  'phone',
  'website',
  'logoUrl',
  'address',
  'timezone',
  'locale',
  'currency',
] as const satisfies ReadonlyArray<keyof OrgProfile>;

/**
 * ⚑ Picks only keys the caller actually sent. Copying the whole body would turn
 * "update the phone number" into "clear everything the form did not render",
 * because an absent key and an explicit `null` mean different things here.
 */
function pickProfile(body: Record<string, unknown>): Partial<OrgProfile> {
  const patch: Record<string, unknown> = {};
  for (const key of PROFILE_KEYS) {
    if (key in body) patch[key] = body[key];
  }
  return patch as Partial<OrgProfile>;
}

export async function orgRoutes(app: FastifyInstance): Promise<void> {
  const { auth, authDeps } = app;

  /** The tenant the caller is acting in, from the token. */
  function activeOrg(request: FastifyRequest): string {
    const orgId = request.auth?.org;
    if (!orgId) {
      throw new AuthError(
        'ORG_CONTEXT_REQUIRED',
        'Create or join an organization before calling this',
      );
    }
    return orgId;
  }

  // ── Creating and reading ──────────────────────────────────────────────────
  app.post(
    '/auth/orgs',
    {
      preHandler: app.requireAuth,
      config: { rateLimit: { max: 10, timeWindow: '1 hour' } },
      schema: route({
        summary: 'Create your organization',
        description:
          'Creates the organization, seeds its roles, and makes you its **owner** — all in one ' +
          'transaction, because an organization with no owner cannot be repaired through the API.\n\n' +
          'Who may call this depends on `orgs.selfService`:\n\n' +
          '* `first-user` *(default)* — only while no organization exists at all. The first person ' +
          'to finish verification claims the instance; everyone else joins by invitation.\n' +
          '* `anyone` — any verified user who does not already belong to one.\n' +
          '* `never` — always `403`.\n\n' +
          '⚑ One organization per user. Calling this while you already belong to one returns `409`.\n\n' +
          'Every detail beyond `name` is optional and can be filled in later with ' +
          '`PATCH /auth/orgs/current`. The response carries a fresh access token that already ' +
          'knows about the organization, so you do not have to refresh to use it.',
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
      const body = request.body as Record<string, unknown> & { name: string; slug?: string };

      const { org, role } = await createOrganization(auth, {
        userId: request.auth!.sub,
        name: body.name,
        ...(body.slug ? { slug: body.slug } : {}),
        profile: pickProfile(body),
        ...requestContext(request),
      });

      // The caller is an owner now, and the token in their hand says they belong
      // to nothing. Minting here saves every client from having to know that.
      const minted = await mintAccessForSession(auth, request.auth!.sub, request.auth!.sid);
      setSessionCookies(reply, auth.config, {
        accessToken: minted.accessToken,
        expiresIn: minted.expiresIn,
        csrfToken: authDeps.newSecret('csrf'),
      });

      return reply.code(201).send({
        org: presentOrg(org),
        role,
        ...(auth.config.cookies.mode !== 'cookie' ? { accessToken: minted.accessToken } : {}),
      });
    },
  );

  app.get(
    '/auth/orgs/current',
    {
      preHandler: app.requireAuth,
      schema: route({
        summary: 'Your organization',
        description:
          'The full profile of the organization you belong to, with your role in it. ' +
          '`null` when you belong to none — that is an ordinary state, not an error: the account ' +
          'is authenticated and the client should offer to create one.',
        tags: [TAGS.auth],
        operationId: 'getCurrentOrganization',
        security: cookieSecurity,
        response: {
          200: z.object({ membership: membershipSummary.nullable() }),
          401: errorSchema,
        },
      }),
    },
    async (request) => {
      const membership = await getMyOrganization(auth, request.auth!.sub);
      return {
        membership: membership
          ? {
              membershipId: membership.membershipId,
              org: presentOrg(membership.org),
              role: membership.role.key,
              status: membership.status,
              joinedAt: membership.joinedAt?.toISOString() ?? null,
            }
          : null,
      };
    },
  );

  app.patch(
    '/auth/orgs/current',
    {
      preHandler: app.requirePermission('org:update'),
      schema: route({
        summary: 'Update the organization profile',
        description:
          'Address, tax number, billing contact, logo, currency — the details an invoice needs.\n\n' +
          '⚑ Omit a field to leave it alone; send `null` to clear it. The two are different, so a ' +
          'form that only renders three fields must send only those three.\n\n' +
          '⚑ `slug` is not editable. It appears in invitation links and in whatever customers have ' +
          'bookmarked or scripted, so changing it is a migration rather than an edit.',
        tags: [TAGS.auth],
        operationId: 'updateOrganization',
        security: cookieSecurity,
        body: updateOrgBody,
        response: { 200: z.object({ org: organization }), 401: errorSchema, 403: errorSchema },
      }),
    },
    async (request) => {
      const body = request.body as Record<string, unknown> & { name?: string };
      const org = await updateOrganization(auth, {
        actorId: request.auth!.sub,
        orgId: activeOrg(request),
        patch: { ...pickProfile(body), ...(body.name !== undefined ? { name: body.name } : {}) },
        ...requestContext(request),
      });
      return { org: presentOrg(org) };
    },
  );

  // ── Members ───────────────────────────────────────────────────────────────
  app.get(
    '/auth/orgs/current/members',
    {
      preHandler: app.requirePermission('member:read'),
      schema: route({
        summary: 'List members of your organization',
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
        summary: 'Invite someone to your organization',
        description:
          'Emails a single-use invitation, valid for 7 days.\n\n' +
          '⚑ You may only grant a role whose permissions are a subset of your own — an `admin` ' +
          'cannot invite an `owner`. The check runs again when the invitation is *accepted*, so a ' +
          'demoted inviter cannot still hand out what they used to hold.',
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
          'than the attack.\n\n' +
          '⚑ Returns `409` if you already belong to an organization — one user, one organization.\n\n' +
          'The response carries a fresh access token that already knows about the organization.',
        tags: [TAGS.auth],
        operationId: 'acceptInvite',
        security: cookieSecurity,
        body: acceptInviteBody,
        response: {
          200: z.object({
            org: organization,
            role: z.string(),
            accessToken: z.string().optional(),
          }),
          403: errorSchema,
          409: errorSchema,
          410: errorSchema,
        },
      }),
    },
    async (request, reply) => {
      const { token } = request.body as { token: string };
      const result = await acceptInvite(auth, authDeps, {
        userId: request.auth!.sub,
        token,
        ...requestContext(request),
      });

      const minted = await mintAccessForSession(auth, request.auth!.sub, request.auth!.sid);
      setSessionCookies(reply, auth.config, {
        accessToken: minted.accessToken,
        expiresIn: minted.expiresIn,
        csrfToken: authDeps.newSecret('csrf'),
      });

      return {
        org: presentOrg(result.org),
        role: result.role,
        ...(auth.config.cookies.mode !== 'cookie' ? { accessToken: minted.accessToken } : {}),
      };
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
