/**
 * Employee accounts (§10.12).
 *
 * The staff of an organization never register: the owner creates them here, with a
 * username scoped to the tenant and no email address at all. They sign in at the
 * tenant's own subdomain (§10.13) with `{ username, org, password }`.
 *
 * ⚑ Like every route under `/auth/orgs/current`, the tenant comes from the
 * **verified token**, never from the URL. The `:id` in these paths identifies an
 * employee *within* that tenant, and the use-case re-checks that the id actually
 * belongs to it — a uuid in a path is not an authorization.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  AuthError,
  createEmployee,
  listEmployees,
  resetEmployeePassword,
  setEmployeeStatus,
  type EmployeeView,
} from '@auth/core';
import { route, errorSchema } from '../../lib/schema.js';
import { TAGS } from '../../plugins/swagger.js';
import { okResponse, uuidField } from '../../schemas/auth.js';
import {
  createEmployeeBody,
  employeeSummary,
  resetEmployeePasswordBody,
  setEmployeeStatusBody,
} from '../../schemas/orgs.js';
import { requestContext } from '../../lib/present.js';

const cookieSecurity: Array<Record<string, string[]>> = [
  { cookieAuth: [], csrfToken: [] },
  { bearerAuth: [] },
];

const present = (employee: EmployeeView) => ({
  ...employee,
  lastLoginAt: employee.lastLoginAt?.toISOString() ?? null,
  createdAt: employee.createdAt.toISOString(),
});

export async function employeeRoutes(app: FastifyInstance): Promise<void> {
  const { auth } = app;

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

  app.get(
    '/auth/orgs/current/employees',
    {
      preHandler: app.requirePermission('member:read'),
      schema: route({
        summary: 'List employee accounts',
        description:
          'The username accounts created for this organization. Members who joined by email ' +
          'invitation are listed by `GET /auth/orgs/current/members` instead — the two are ' +
          'different kinds of account, administered differently (§10.12).',
        tags: [TAGS.auth],
        operationId: 'listEmployees',
        security: cookieSecurity,
        response: {
          200: z.object({ employees: z.array(employeeSummary) }),
          401: errorSchema,
          403: errorSchema,
        },
      }),
    },
    async (request) => {
      const employees = await listEmployees(auth, {
        actorId: request.auth!.sub,
        orgId: activeOrg(request),
      });
      return { employees: employees.map(present) };
    },
  );

  app.post(
    '/auth/orgs/current/employees',
    {
      preHandler: app.requirePermission('member:invite'),
      config: { rateLimit: { max: 60, timeWindow: '1 hour' } },
      schema: route({
        summary: 'Create an employee account',
        description:
          'Creates a username-and-password account inside your organization, active immediately — ' +
          'there is no invitation and no mailbox to confirm, because the person creating it is ' +
          'vouching for the person using it.\n\n' +
          '⚑ You may only grant a role whose permissions are a subset of your own, and **never** ' +
          '`owner`: the owner is the account that receives the password-reset mail, and an owner ' +
          'without a mailbox is a tenant one forgotten password away from needing a DBA.\n\n' +
          'The password is held to the same policy as a signup, breach check included.',
        tags: [TAGS.auth],
        operationId: 'createEmployee',
        security: cookieSecurity,
        rateLimit: '60 per hour per IP',
        body: createEmployeeBody,
        response: {
          201: employeeSummary,
          400: errorSchema,
          401: errorSchema,
          403: errorSchema,
          409: errorSchema,
          422: errorSchema,
        },
      }),
    },
    async (request, reply) => {
      const body = request.body as {
        username: string;
        password: string;
        name?: string;
        role: string;
      };
      const employee = await createEmployee(auth, {
        actorId: request.auth!.sub,
        orgId: activeOrg(request),
        username: body.username,
        password: body.password,
        name: body.name ?? null,
        roleKey: body.role,
        ...requestContext(request),
      });
      return reply.code(201).send(present(employee));
    },
  );

  app.post(
    '/auth/orgs/current/employees/:id/password',
    {
      preHandler: app.requirePermission('member:update'),
      config: { rateLimit: { max: 30, timeWindow: '1 hour' } },
      schema: route({
        summary: "Set an employee's password",
        description:
          'For the case the product is actually built around: somebody forgot theirs and there is ' +
          'no mailbox to send a link to.\n\n' +
          '⚑ Every session that employee holds is revoked. A reset that leaves the old sessions ' +
          'alive is not a reset — it is a second password, and the usual reason for resetting is ' +
          'that the first one is in the wrong hands.',
        tags: [TAGS.auth],
        operationId: 'resetEmployeePassword',
        security: cookieSecurity,
        rateLimit: '30 per hour per IP',
        params: z.object({ id: uuidField }),
        body: resetEmployeePasswordBody,
        response: {
          200: okResponse,
          401: errorSchema,
          403: errorSchema,
          404: errorSchema,
          422: errorSchema,
        },
      }),
    },
    async (request) => {
      const { id } = request.params as { id: string };
      const { password } = request.body as { password: string };
      await resetEmployeePassword(auth, {
        actorId: request.auth!.sub,
        orgId: activeOrg(request),
        employeeId: id,
        password,
        ...requestContext(request),
      });
      return { ok: true as const };
    },
  );

  app.patch(
    '/auth/orgs/current/employees/:id',
    {
      preHandler: app.requirePermission('member:update'),
      schema: route({
        summary: 'Suspend or restore an employee',
        description:
          '⚑ Suspending revokes their sessions as well as flipping the flag. Suspending someone ' +
          'who holds a live access token otherwise suspends them in ten minutes’ time, which is ' +
          'not what anyone means by the word.',
        tags: [TAGS.auth],
        operationId: 'setEmployeeStatus',
        security: cookieSecurity,
        params: z.object({ id: uuidField }),
        body: setEmployeeStatusBody,
        response: {
          200: okResponse,
          401: errorSchema,
          403: errorSchema,
          404: errorSchema,
        },
      }),
    },
    async (request) => {
      const { id } = request.params as { id: string };
      const { status } = request.body as { status: 'active' | 'suspended' };
      await setEmployeeStatus(auth, {
        actorId: request.auth!.sub,
        orgId: activeOrg(request),
        employeeId: id,
        status,
        ...requestContext(request),
      });
      return { ok: true as const };
    },
  );
}
