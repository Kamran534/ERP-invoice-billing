/**
 * Organization contracts (AUTH-MODULE-PLAN.md §10.5–§10.11, §5.14).
 */

import { z } from 'zod';
import { emailField, uuidField } from './auth.js';

export const orgAddress = z
  .object({
    line1: z.string().max(200).optional(),
    line2: z.string().max(200).optional(),
    city: z.string().max(120).optional(),
    region: z.string().max(120).optional().meta({ description: 'State, province or county.' }),
    postalCode: z.string().max(30).optional(),
    country: z
      .string()
      .length(2)
      .optional()
      .meta({ description: 'ISO 3166-1 alpha-2, uppercase.', example: 'PK' }),
  })
  .meta({ id: 'OrgAddress' });

/**
 * ⚑ Every field optional. An organization is usable the moment it has a name;
 * requiring a tax number before anyone can sign in is how onboarding is abandoned.
 */
export const orgProfileFields = {
  legalName: z
    .string()
    .max(200)
    .nullish()
    .meta({ description: 'Registered name, when it differs from the display name.' }),
  taxId: z
    .string()
    .max(60)
    .nullish()
    .meta({ description: 'VAT / GST / NTN. Free text — every jurisdiction formats it differently.' }),
  email: emailField.nullish().meta({ description: 'Billing contact, separate from any individual account.' }),
  phone: z.string().max(40).nullish().meta({ example: '+92 300 1234567' }),
  website: z.string().url().max(300).nullish(),
  logoUrl: z.string().url().max(500).nullish(),
  address: orgAddress.nullish(),
  timezone: z.string().max(60).nullish().meta({ description: 'IANA zone.', example: 'Asia/Karachi' }),
  locale: z.string().max(20).nullish().meta({ description: 'BCP-47 tag.', example: 'en-PK' }),
  currency: z
    .string()
    .length(3)
    .nullish()
    .meta({ description: 'ISO 4217. The default an invoice is drawn in.', example: 'PKR' }),
};

export const organization = z
  .object({
    id: uuidField,
    name: z.string(),
    slug: z.string().meta({
      description: 'URL-safe, derived from the name and unique across the instance. Not editable.',
      example: 'acme-billing',
    }),
    status: z.enum(['active', 'suspended']),
    legalName: z.string().nullable(),
    taxId: z.string().nullable(),
    email: z.string().nullable(),
    phone: z.string().nullable(),
    website: z.string().nullable(),
    logoUrl: z.string().nullable(),
    address: orgAddress.nullable(),
    timezone: z.string().nullable(),
    locale: z.string().nullable(),
    currency: z.string().nullable(),
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
    .meta({ description: 'Derived from `name` when omitted. Cannot be changed afterwards.' }),
  ...orgProfileFields,
});

/** ⚑ Omit a field to leave it alone; send `null` to clear it. `slug` is not editable. */
export const updateOrgBody = z.object({
  name: z.string().min(1).max(200).optional(),
  ...orgProfileFields,
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

export const inviteBody = z.object({
  email: emailField,
  role: z.string().min(1).meta({ description: 'Role key. Must be one you hold yourself.', example: 'member' }),
});

export const acceptInviteBody = z.object({ token: z.string().min(20) });

export const changeRoleBody = z.object({ role: z.string().min(1) });
