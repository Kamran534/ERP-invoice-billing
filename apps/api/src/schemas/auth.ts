/**
 * Request/response contracts for the auth surface.
 *
 * These are the source of truth for validation, serialization AND the OpenAPI
 * document. Descriptions here are what a client developer reads in Swagger UI, so
 * they carry the operational detail (what's enumeration-safe, what rotates, what
 * must be single-flighted) rather than restating the field name.
 */

import { z } from 'zod';

// ── Primitives ─────────────────────────────────────────────────────────────

export const emailField = z
  .string()
  .email()
  .max(320)
  .meta({ description: 'Email address. Compared case-insensitively.', example: 'ada@example.com' });

export const passwordField = z
  .string()
  .min(12)
  .max(200)
  .meta({
    description:
      'Minimum 12 characters. No composition rules (NIST 800-63B) — but the value is checked ' +
      'against the Have I Been Pwned breach corpus via k-anonymity, so a long common password ' +
      'is still rejected with `PASSWORD_BREACHED`.',
    example: 'correct horse battery staple',
  });

export const otpCodeField = z
  .string()
  .regex(/^\d{4,10}$/)
  .meta({ description: 'The numeric code from the email or SMS.', example: '481920' });

export const uuidField = z.string().uuid();

// ── Shared response objects ────────────────────────────────────────────────

export const publicUser = z
  .object({
    id: uuidField,
    email: emailField.nullable(),
    emailVerified: z.boolean(),
    name: z.string().nullable(),
    status: z.enum(['pending', 'active', 'suspended']),
    mfaEnrolled: z.boolean().meta({ description: 'True when at least one confirmed second factor exists.' }),
    createdAt: z.string().meta({ description: 'ISO 8601 timestamp.' }),
  })
  .meta({ id: 'PublicUser' });

export const sessionSummary = z
  .object({
    accessToken: z
      .string()
      .optional()
      .meta({
        description:
          'Present only in `bearer` transport mode. In cookie mode the token is set as ' +
          '`__Host-at` and this field is omitted entirely.',
      }),
    refreshToken: z
      .string()
      .optional()
      .meta({
        description:
          '`bearer` mode only. Opaque — not a JWT, and not introspectable. Store it in the OS ' +
          'keychain. It is invalidated the moment you use it (§5.5.3).',
      }),
    expiresIn: z.number().meta({ description: 'Access-token lifetime in seconds.', example: 600 }),
    user: publicUser,
  })
  .meta({ id: 'SessionSummary' });

/**
 * Login and OTP verify share one response so a client has a single branch point.
 * `mfa_required` deliberately carries no session — nothing is authenticated yet.
 */
export const authOutcome = z
  .discriminatedUnion('status', [
    z.object({ status: z.literal('authenticated'), session: sessionSummary }),
    z.object({
      status: z.literal('mfa_required'),
      mfaToken: z.string().meta({
        description:
          'Single-use, 5-minute challenge token. Bound to your user-agent and /24. Valid ONLY on ' +
          '`/auth/mfa/verify` and `/auth/mfa/otp/send` — it carries no session and no permissions.',
      }),
      availableMethods: z.array(z.enum(['totp', 'email_otp', 'sms_otp', 'webauthn', 'recovery'])).meta({
        description:
          'Render your method picker from this — do not hardcode a list, or enabling a channel ' +
          'server-side will need a client release.',
      }),
    }),
    z.object({
      status: z.literal('mfa_enrollment_required'),
      session: sessionSummary,
      enrollBy: z.string().nullable().meta({
        description:
          'Quarantined session (§5.4.6): it can reach only the enrollment endpoints and `/auth/me`. ' +
          'ISO 8601 deadline, or null when enrollment is immediate.',
      }),
    }),
  ])
  .meta({ id: 'AuthOutcome' });

// ── Registration ───────────────────────────────────────────────────────────

export const registerBody = z.object({
  email: emailField,
  password: passwordField,
  name: z.string().min(1).max(200).optional(),
});

export const registerResponse = z.object({
  status: z.literal('verification_sent'),
  message: z.string(),
});

// ── Login ──────────────────────────────────────────────────────────────────

export const loginBody = z.object({
  email: emailField,
  password: z.string().min(1).max(200).meta({ description: 'Not length-validated on login — that would leak policy.' }),
  rememberDevice: z
    .boolean()
    .optional()
    .meta({
      description:
        'Ask to skip 2FA on this device for 30 days. Honoured only when trusted devices are ' +
        'enabled server-side, and never accepted for step-up (§5.4.5).',
    }),
});

// ── Refresh ────────────────────────────────────────────────────────────────

export const refreshBody = z.object({
  refreshToken: z
    .string()
    .optional()
    .meta({
      description:
        '`bearer` mode only. Omit in cookie mode — the `__Host-rt` cookie is used instead.',
    }),
});

export const refreshResponse = z.object({
  accessToken: z.string().optional(),
  refreshToken: z.string().optional().meta({ description: 'The NEW token. The one you sent is now dead.' }),
  expiresIn: z.number(),
});

// ── OTP ────────────────────────────────────────────────────────────────────

export const otpRequestBody = z.object({
  destination: z
    .string()
    .min(3)
    .max(320)
    .meta({ description: 'Email address, or E.164 phone number when `channel` is `sms`.', example: 'ada@example.com' }),
  channel: z.enum(['email', 'sms']).default('email').meta({
    description: 'SMS is disabled by default (SIM-swap risk) and returns `VALIDATION_FAILED` unless enabled.',
  }),
});

export const otpRequestResponse = z
  .object({
    challengeId: uuidField.meta({
      description:
        'Pass this to `/auth/otp/verify`. Issued even for addresses with no account — probing this ' +
        'endpoint cannot distinguish the two cases (§5.11.1).',
    }),
    expiresIn: z.number().meta({ description: 'Seconds until the code expires.', example: 600 }),
    resendAfter: z.number().meta({ description: 'Seconds before a resend is accepted. Drive your timer from this, not a client-side guess.', example: 60 }),
    maskedDestination: z.string().meta({ example: 'a••@example.com' }),
  })
  .meta({ id: 'OtpChallengeIssued' });

export const otpVerifyBody = z.object({
  challengeId: uuidField,
  code: otpCodeField,
});

// ── 2FA ────────────────────────────────────────────────────────────────────

export const mfaVerifyBody = z.object({
  mfaToken: z.string().meta({ description: 'From the `mfa_required` login response.' }),
  method: z.enum(['totp', 'email_otp', 'sms_otp', 'recovery']),
  code: z.string().min(4).max(32).meta({ description: 'TOTP code, OTP code, or a recovery code.' }),
  rememberDevice: z.boolean().optional(),
});

export const totpSetupResponse = z
  .object({
    factorId: uuidField,
    secret: z.string().meta({ description: 'Base32 secret. Shown once — never retrievable again.' }),
    provisioningUri: z.string().meta({
      description: 'otpauth:// URI for the QR code.',
      example: 'otpauth://totp/Acme:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme',
    }),
    recoveryCodes: z.array(z.string()).meta({
      description:
        'Ten single-use codes, returned only after the factor is confirmed. Shown once. ' +
        'Regenerating invalidates every previous code.',
    }),
  })
  .meta({ id: 'TotpSetup' });

export const totpConfirmBody = z.object({
  factorId: uuidField,
  code: z.string().regex(/^\d{6,8}$/),
});

export const mfaFactorSummary = z
  .object({
    id: uuidField,
    type: z.enum(['totp', 'webauthn', 'sms']),
    label: z.string().nullable(),
    confirmed: z.boolean(),
    lastUsedAt: z.string().nullable(),
    createdAt: z.string(),
  })
  .meta({ id: 'MfaFactor' });

export const mfaStateResponse = z.object({
  enforced: z.enum(['optional', 'admins', 'all']),
  required: z.boolean().meta({ description: 'True when policy requires 2FA for this specific user.' }),
  enrolled: z.boolean(),
  factors: z.array(mfaFactorSummary),
  recoveryCodesRemaining: z.number(),
});

// ── Sessions & devices ─────────────────────────────────────────────────────

export const deviceSession = z
  .object({
    id: uuidField,
    current: z.boolean(),
    deviceLabel: z.string().nullable(),
    ip: z.string().nullable(),
    amr: z.array(z.string()).meta({ description: 'Auth methods used: e.g. ["pwd","otp"].' }),
    createdAt: z.string(),
    lastSeenAt: z.string(),
    absoluteExpiresAt: z.string().meta({ description: 'Hard cap. Never extended, for any reason.' }),
  })
  .meta({ id: 'DeviceSession' });

export const trustedDeviceSummary = z
  .object({
    id: uuidField,
    label: z.string().nullable(),
    lastUsedAt: z.string().nullable(),
    expiresAt: z.string(),
  })
  .meta({ id: 'TrustedDevice' });

// ── Account ────────────────────────────────────────────────────────────────

export const forgotPasswordBody = z.object({ email: emailField });

export const resetPasswordBody = z.object({
  token: z.string().min(20),
  newPassword: passwordField,
});

export const changePasswordBody = z.object({
  currentPassword: z.string().min(1).meta({
    description:
      'Required even with a live session — otherwise an XSS or CSRF foothold becomes a full ' +
      'account takeover (§5.8).',
  }),
  newPassword: passwordField,
});

export const okResponse = z.object({ ok: z.literal(true) });

export const jwksResponse = z
  .object({
    keys: z.array(z.record(z.string(), z.unknown())),
  })
  .meta({ id: 'Jwks' });
