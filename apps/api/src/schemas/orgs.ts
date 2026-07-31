/**
 * Organization contracts (AUTH-MODULE-PLAN.md §10.5–§10.9, §5.14).
 */

import { z } from 'zod';
import { emailField, uuidField } from './auth.js';

export const organization = z
  .object({
    id: uuidField,
    name: z.string(),
    slug: z.string().meta({
      description: 'URL-safe, derived from the name and unique across the instance.',
      example: 'acme-billing',
    }),
    status: z.enum(['active', 'suspended']),
    createdAt: z.string(),
  })
  .meta({ id: 'Organization' });

export const createOrgBody = z.object({
  name: z.string().min(1).max(200).meta({ example: 'Acme Billing' }),
  slug: z
    .string()
    .min(1)
    .max(60)
    .regex(/^[a-z0-9]+(-[a-z0-9]+)*$/)
    .optional()
    .meta({ description: 'Derived from `name` when omitted.' }),
});

export const membershipSummary = z
  .object({
    membershipId: uuidField,
    org: organization,
    role: z.string().meta({ description: 'Role key: `owner`, `admin`, `member`.', example: 'owner' }),
    status: z.enum(['invited', 'active', 'suspended']),
    joinedAt: z.string().nullable(),
  })
  .meta({ id: 'Membership' });

export const memberSummary = z
  .object({
    membershipId: uuidField,
    userId: uuidField,
    email: emailField.nullable(),
    role: z.string(),
    status: z.enum(['invited', 'active', 'suspended']),
    joinedAt: z.string().nullable(),
  })
  .meta({ id: 'OrgMember' });

export const switchOrgBody = z.object({ orgId: uuidField });

export const switchOrgResponse = z.object({
  accessToken: z
    .string()
    .optional()
    .meta({ description: '`bearer` mode only; in cookie mode the `__Host-at` cookie is replaced.' }),
  expiresIn: z.number(),
  org: organization,
});

export const inviteBody = z.object({
  email: emailField,
  role: z.string().min(1).meta({ description: 'Role key. Must be one you hold yourself.', example: 'member' }),
});

export const acceptInviteBody = z.object({ token: z.string().min(20) });

export const changeRoleBody = z.object({ role: z.string().min(1) });
