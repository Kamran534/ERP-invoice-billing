---
aliases: [Auth plan, Auth module plan]
tags: [spec, auth]
status: living
updated: 2026-07-31
---

> [!info] This is the specification. [[Auth module]] is the way in.
> Section numbers (`§`) are cited from source comments, `501` response bodies,
> Prometheus alert notes and k6 thresholds. **Add sections; never renumber them.**

# Auth Module — End-to-End Plan

A reusable, drop-in authentication & authorization module. Designed once, portable to any
project (starting with this invoice & billing app, but nothing in the core knows about invoices).

---

## 0. Assumptions (veto any of these before Phase 0 starts)

The project is empty, so these are my defaults. Each is cheap to change **now** and expensive to
change after Phase 1.

| # | Decision | Default chosen | Why | Cost to change later |
|---|---|---|---|---|
| A1 | Language / runtime | TypeScript, Node 20+ | Largest ecosystem for auth primitives (jose, argon2, simplewebauthn); same language as a likely React frontend | High |
| A2 | Framework coupling | **None in core.** Framework adapters for Express / Fastify / NestJS | This is the whole point of "generic module" | High |
| A3 | Database | Postgres 14+ as the reference; access behind repository ports | `citext`, `jsonb`, partial indexes, `FOR UPDATE SKIP LOCKED` | Medium (ports absorb it) |
| A4 | ORM | Ships raw SQL migrations + a Drizzle adapter and a Prisma adapter | Module must own its schema without dictating your ORM | Low |
| A5 | Session strategy | **Hybrid**: short-lived JWT access token + opaque rotating refresh token stored server-side | Stateless authorization at the edge, real revocation where it matters | High |
| A6 | Token transport | httpOnly cookies for first-party browsers; `Authorization: Bearer` for mobile/API clients. Both supported, chosen by config | Cookies survive XSS better; bearer is required for native apps | Medium |
| A7 | Password hashing | Argon2id (with bcrypt read-compat for migrations) | OWASP current recommendation | Low (lazy rehash) |
| A8 | Multi-tenancy | Built in but **optional** (`tenancy: 'none' \| 'orgs'`) | A billing app needs orgs; a side project doesn't | High |
| A9 | Authorization model | RBAC with permission keys, scoped per membership, plus a policy hook for row-level rules | Roles alone always break by month six | Medium |
| A10 | Build vs buy | Build. (If you'd rather buy — Clerk/Auth0/Keycloak/Supabase — say so now; ~80% of this plan becomes a thin adapter and Phases 3–7 mostly disappear.) | — | Very high |
| A11 | Login methods | Password, **email OTP code**, magic link, OAuth, passkey — each independently toggleable per deployment | Staff want password+2FA; customers paying an invoice want zero friction | Low (config) |
| A12 | 2FA channels | TOTP + passkey + email OTP on; **SMS off by default** | SMS is phishable and SIM-swappable — opt-in only, never the promoted option | Low |
| A13 | Trusted devices | "Don't ask for 2FA on this device for 30 days" supported, **off** by default | Cuts 2FA friction without weakening the default posture | Medium |

**Non-goals:** it is not an identity provider for third parties (no "Login with Us" OAuth server —
see §18 for where that would slot in), not a user-profile/CRM service, not a consent-management
platform, and it does not handle payment credentials (PCI stays with Stripe et al.).

---

## 1. Goals & design principles

1. **Core is pure.** `@auth/core` imports no HTTP framework, no ORM, no logger, no `process.env`.
   Everything external arrives as a port (§6). This is what makes it reusable, and it is also what
   makes it testable without a database.
2. **Secure by default, insecure only on purpose.** Every weakening (longer TTLs, disabled MFA,
   permissive CORS) is an explicit config value with a comment explaining the risk.
3. **One way to do each thing.** No two code paths that both "log a user in."
4. **Every security-relevant event is audited.** Append-only, queryable, exportable.
5. **Revocable.** Any session, token, key, or credential can be killed within one access-token TTL.
6. **No user enumeration.** Identical responses and timing whether or not an account exists.
7. **Errors are typed and stable.** Machine-readable codes; human strings live in i18n bundles the
   host app can override.
8. **Migrations are additive and reversible.** The module owns its tables and never touches yours.

---

## 2. Scope map — what "auth" means here

```
┌─ Identity ──────────────┬─ Credentials ───────────┬─ Session ───────────────────────┐
│ users                   │ password (argon2id)     │ access token (JWT, 10m)         │
│ external identities     │ TOTP authenticator app  │ refresh token (opaque, rotating)│
│ passkeys / WebAuthn     │ email OTP code (6-digit)│ rotation + reuse detection      │
│ orgs & memberships      │ SMS OTP (opt-in)        │ session + device records        │
│ service accounts        │ magic links             │ step-up / re-auth               │
│                         │ recovery codes          │ trusted-device skip (opt-in)    │
│                         │ API keys                │ revocation + JWKS rotation      │
├─ Account lifecycle ─────┼─ Authorization ─────────┼─ Platform ──────────────────────┤
│ register / verify       │ roles & permissions     │ rate limiting (per IP+identity) │
│ invite / accept         │ tenant scoping          │ audit log (append-only)         │
│ password reset / change │ policy hook (ABAC)      │ signing-key rotation            │
│ email change (dual      │ scopes for machines     │ email / SMS delivery ports      │
│   confirmation)         │ impersonation           │ metrics, alerts, runbooks       │
│ suspend / delete /      │ 401 vs 403 semantics    │ GDPR export & erasure           │
│   anonymize             │                         │ breach-password check           │
└─────────────────────────┴─────────────────────────┴─────────────────────────────────┘
```

---

## 3. Architecture

### 3.1 Packages

```
packages/
  auth-core/            # entities, use-cases, ports, errors, policy engine. Zero I/O deps.
  auth-crypto/          # hashing, HKDF, AEAD for secrets-at-rest, token mint/verify, JWKS
  auth-db-postgres/     # SQL migrations + repository implementations (pg / Drizzle)
  auth-db-prisma/       # same ports, Prisma implementation
  auth-http-express/    # router, cookie handling, CSRF, error mapping
  auth-http-fastify/    # same
  auth-http-nest/       # DynamicModule + guards + decorators
  auth-mail/            # templates (mjml -> html+text) + SMTP/Resend/SES adapters
  auth-ratelimit/       # in-memory + Redis token-bucket adapters
  auth-client/          # framework-free browser SDK: token cache, single-flight refresh
  auth-react/           # AuthProvider, useAuth, <RequireAuth>, <RequirePermission>
  auth-testing/         # in-memory adapters, fixtures, fake clock, factory builders
apps/
  auth-playground/      # runnable demo app used by e2e tests and manual QA
```

Consumers install `auth-core` + one DB adapter + one HTTP adapter. Everything else is opt-in.

### 3.2 Layering

```
HTTP adapter        → parses request, maps errors to status codes, sets cookies
  ↓  (plain DTOs)
Use case            → orchestration, invariants, audit emission, event publication
  ↓  (ports)
Repositories / Services (interfaces)
  ↓
Adapters            → Postgres, Redis, SMTP, OAuth providers, WebAuthn lib
```

Rules enforced by lint (`no-restricted-imports`) and a dependency-cruiser check in CI:
core → crypto only; adapters → core; nothing → adapters except the composition root.

### 3.3 Composition root

One factory, fully explicit, no globals or singletons:

```ts
const auth = createAuth({
  config: authConfig,                         // §7, validated by zod at boot
  repos: createPostgresRepos(pool),
  clock: systemClock,                         // injectable for tests
  random: nodeRandom,
  hasher: argon2idHasher({ memoryCost: 19456, timeCost: 2, parallelism: 1 }),
  tokens: jwtTokenService({ keyStore }),      // EdDSA, key rotation via keyStore
  mailer: resendMailer(env.RESEND_KEY),
  rateLimiter: redisRateLimiter(redis),
  events: eventBus,                           // host app subscribes here
  logger: pinoLogger,                         // redaction configured in-adapter
})
```

---

## 4. Data model

Postgres reference DDL. All tables take a configurable prefix (default `auth_`). All ids are UUIDv7
(time-sortable, index-friendly). Every timestamp is `timestamptz`. Secrets are **never** stored raw:
passwords are hashed, tokens are SHA-256 hashed, TOTP secrets are AEAD-encrypted with a KEK.

### 4.1 Identity

```sql
CREATE TABLE auth_users (
  id                  uuid PRIMARY KEY,
  email               citext UNIQUE,                -- nullable: passkey/SSO-only accounts
  email_verified_at   timestamptz,
  phone               text UNIQUE,                  -- E.164; only for the opt-in SMS OTP channel
  phone_verified_at   timestamptz,
  password_hash       text,                         -- nullable: passwordless accounts
  password_algo       text,                         -- 'argon2id' | 'bcrypt' (legacy)
  password_updated_at timestamptz,
  status              text NOT NULL DEFAULT 'pending',  -- pending|active|suspended|deleted
  name                text,
  avatar_url          text,
  locale              text,
  timezone            text,
  profile             jsonb NOT NULL DEFAULT '{}',  -- host-app extension point (§7.3)
  mfa_required_at     timestamptz,                  -- org policy forced MFA on this user
  failed_login_count  int  NOT NULL DEFAULT 0,
  locked_until        timestamptz,
  last_login_at       timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);
CREATE INDEX ON auth_users (status) WHERE deleted_at IS NULL;

CREATE TABLE auth_identities (               -- federated logins
  id                uuid PRIMARY KEY,
  user_id           uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  provider          text NOT NULL,           -- 'google' | 'github' | 'microsoft' | 'saml:<conn>'
  provider_user_id  text NOT NULL,
  email             citext,
  email_verified    boolean NOT NULL DEFAULT false,
  profile           jsonb NOT NULL DEFAULT '{}',
  created_at        timestamptz NOT NULL DEFAULT now(),
  last_login_at     timestamptz,
  UNIQUE (provider, provider_user_id)
);
-- NOTE: provider access/refresh tokens are deliberately NOT stored. If the host app needs
-- ongoing API access to the provider, that belongs in a separate integrations module.

CREATE TABLE auth_password_history (         -- reuse prevention, config-gated
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  password_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
```

### 4.2 Sessions & tokens

```sql
CREATE TABLE auth_sessions (
  id                  uuid PRIMARY KEY,
  user_id             uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  org_id              uuid REFERENCES auth_orgs(id),      -- active tenant, nullable
  created_at          timestamptz NOT NULL DEFAULT now(),
  last_seen_at        timestamptz NOT NULL DEFAULT now(),
  idle_expires_at     timestamptz NOT NULL,               -- sliding
  absolute_expires_at timestamptz NOT NULL,               -- hard cap
  revoked_at          timestamptz,
  revoked_reason      text,          -- logout|logout_all|password_change|reuse_detected|admin|expired
  amr                 text[] NOT NULL DEFAULT '{}',       -- ['pwd','otp'] auth methods used
  mfa_satisfied_at    timestamptz,
  ip                  inet,
  user_agent          text,
  device_label        text,                               -- "Chrome on Windows"
  impersonated_by     uuid REFERENCES auth_users(id)      -- support impersonation, always audited
);
CREATE INDEX ON auth_sessions (user_id) WHERE revoked_at IS NULL;

CREATE TABLE auth_refresh_tokens (
  id             uuid PRIMARY KEY,
  session_id     uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
  token_hash     bytea NOT NULL UNIQUE,     -- sha256(secret); secret never persisted
  issued_at      timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL,
  used_at        timestamptz,
  replaced_by_id uuid REFERENCES auth_refresh_tokens(id),
  revoked_at     timestamptz
);
CREATE INDEX ON auth_refresh_tokens (session_id);
```

Rotation invariant: exactly one refresh token per session is unused. Presenting a token whose
`used_at` is already set means either replay or theft → revoke the whole session family (§5.5).

### 4.3 Second factors

```sql
CREATE TABLE auth_mfa_factors (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  type text NOT NULL,                 -- 'totp' | 'webauthn' | 'sms' (sms discouraged)
  label text,
  secret_enc bytea,                   -- AEAD(TOTP secret, KEK); null for webauthn
  confirmed_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE auth_webauthn_credentials (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  credential_id bytea NOT NULL UNIQUE,
  public_key bytea NOT NULL,
  sign_count bigint NOT NULL DEFAULT 0,
  transports text[],
  aaguid uuid,
  backed_up boolean,
  label text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);

CREATE TABLE auth_recovery_codes (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  code_hash bytea NOT NULL,
  used_at timestamptz
);
```

One table serves **both** OTP-as-login (§5.11) and OTP-as-second-factor (§5.4), because the
generate → deliver → attempt-capped-verify engine is identical; only `purpose` differs:

```sql
CREATE TABLE auth_otp_challenges (
  id               uuid PRIMARY KEY,
  user_id          uuid REFERENCES auth_users(id) ON DELETE CASCADE,  -- null until identified
  purpose          text NOT NULL,      -- login | mfa | step_up | phone_verify
  channel          text NOT NULL,      -- email | sms
  destination_hash bytea NOT NULL,     -- sha256(normalized email/E.164) — no raw PII in this table
  code_hash        bytea NOT NULL,     -- sha256(code || id) — the code itself is never stored
  attempts         int NOT NULL DEFAULT 0,
  max_attempts     int NOT NULL DEFAULT 5,
  resend_count     int NOT NULL DEFAULT 0,
  client_binding   bytea,              -- sha256(user_agent || ip/24) when bindToClient
  expires_at       timestamptz NOT NULL,
  consumed_at      timestamptz,
  last_sent_at     timestamptz NOT NULL DEFAULT now(),
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON auth_otp_challenges (destination_hash, purpose) WHERE consumed_at IS NULL;
-- Purge job: DELETE WHERE expires_at < now() - interval '1 day' (hourly, §16)

CREATE TABLE auth_trusted_devices (    -- "don't ask for 2FA on this device for 30 days"
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  token_hash bytea NOT NULL UNIQUE,    -- httpOnly cookie value, hashed
  label text, ip inet, user_agent text,
  mfa_satisfied_at timestamptz NOT NULL,   -- the 2FA event that earned the trust
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON auth_trusted_devices (user_id) WHERE revoked_at IS NULL;
```

### 4.4 One-time tokens (one table, many purposes)

```sql
CREATE TABLE auth_one_time_tokens (
  id           uuid PRIMARY KEY,
  user_id      uuid REFERENCES auth_users(id) ON DELETE CASCADE,  -- null for invites to new emails
  purpose      text NOT NULL,   -- email_verify|password_reset|magic_link|email_change|org_invite
  token_hash   bytea NOT NULL UNIQUE,
  payload      jsonb NOT NULL DEFAULT '{}',   -- e.g. {"newEmail": "...", "orgId": "...", "role": "..."}
  expires_at   timestamptz NOT NULL,
  consumed_at  timestamptz,
  requested_ip inet,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON auth_one_time_tokens (user_id, purpose) WHERE consumed_at IS NULL;
```

Consumption is a single atomic statement — never read-then-write:

```sql
UPDATE auth_one_time_tokens SET consumed_at = now()
WHERE token_hash = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > now()
RETURNING user_id, payload;
```

### 4.5 Tenancy & authorization

```sql
CREATE TABLE auth_orgs (
  id uuid PRIMARY KEY, name text NOT NULL, slug citext UNIQUE,
  status text NOT NULL DEFAULT 'active',
  settings jsonb NOT NULL DEFAULT '{}',   -- e.g. {"requireMfa": true, "allowedDomains": [...]}
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE auth_memberships (
  id uuid PRIMARY KEY,
  org_id  uuid NOT NULL REFERENCES auth_orgs(id)  ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  role_id uuid NOT NULL REFERENCES auth_roles(id),
  status text NOT NULL DEFAULT 'active',   -- invited|active|suspended
  invited_by uuid REFERENCES auth_users(id),
  joined_at timestamptz,
  UNIQUE (org_id, user_id)
);

CREATE TABLE auth_roles (
  id uuid PRIMARY KEY,
  org_id uuid REFERENCES auth_orgs(id) ON DELETE CASCADE,  -- null = system role
  key text NOT NULL,                -- 'owner'|'admin'|'member'|'viewer'|custom
  name text NOT NULL,
  is_system boolean NOT NULL DEFAULT false,
  UNIQUE (org_id, key)
);

CREATE TABLE auth_role_permissions (
  role_id uuid NOT NULL REFERENCES auth_roles(id) ON DELETE CASCADE,
  permission text NOT NULL,         -- 'invoice:read', 'invoice:*', '*'
  PRIMARY KEY (role_id, permission)
);
```

Permission keys are declared by the **host app**, not the module:
`auth.registerPermissions(['invoice:read','invoice:write','subscription:cancel', ...])`.
The module validates role grants against that registry at write time, so typos fail loudly.

### 4.6 Machine identity

```sql
CREATE TABLE auth_api_keys (
  id uuid PRIMARY KEY,
  org_id uuid REFERENCES auth_orgs(id) ON DELETE CASCADE,
  created_by uuid REFERENCES auth_users(id),
  name text NOT NULL,
  prefix text NOT NULL,             -- 'ak_live_7f3a' — shown in UI, indexed for fast lookup
  key_hash bytea NOT NULL,
  scopes text[] NOT NULL DEFAULT '{}',
  last_used_at timestamptz, expires_at timestamptz, revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX ON auth_api_keys (prefix);
```

### 4.7 Audit & forensics

```sql
CREATE TABLE auth_audit_events (           -- append-only; no UPDATE/DELETE grant for the app role
  id uuid PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  org_id uuid, actor_user_id uuid, actor_type text,   -- user|system|api_key|support
  event text NOT NULL,                                -- see §9 catalogue
  target_type text, target_id text,
  ip inet, user_agent text, session_id uuid,
  metadata jsonb NOT NULL DEFAULT '{}',
  outcome text NOT NULL DEFAULT 'success'             -- success|failure
);
CREATE INDEX ON auth_audit_events (org_id, occurred_at DESC);
CREATE INDEX ON auth_audit_events (actor_user_id, occurred_at DESC);
-- Partition monthly once volume justifies it; retention per §15.

CREATE TABLE auth_login_attempts (         -- short-lived, drives lockout + anomaly detection
  id bigserial PRIMARY KEY,
  email_hash bytea, ip inet, success boolean NOT NULL, reason text,
  created_at timestamptz NOT NULL DEFAULT now()
);
```

### 4.8 Signing keys

```sql
CREATE TABLE auth_signing_keys (
  kid text PRIMARY KEY, alg text NOT NULL,          -- 'EdDSA' (Ed25519) default
  public_jwk jsonb NOT NULL, private_key_enc bytea NOT NULL,  -- AEAD with KEK from env/KMS
  status text NOT NULL,                             -- next|active|retiring|retired
  created_at timestamptz NOT NULL DEFAULT now(), activated_at timestamptz, retired_at timestamptz
);
```

---

## 5. Core flows

Each flow below is one use-case class in `auth-core`, with the stated audit events, rate limits, and
failure modes. `→` marks the response; ⚑ marks a security-critical detail that reviewers must check.

### 5.1 Registration

1. Validate email (RFC-ish + DNS MX check optional) and password against policy (§8.1).
2. ⚑ Check breached-password list via HIBP range API (k-anonymity: send 5 hex chars of SHA-1, never
   the password). Configurable; fail-open on API timeout, but log it.
3. Insert user `status='pending'` inside a transaction. ⚑ On unique-violation, **do not** reveal it:
   send a "someone tried to register with your email" mail to the existing address and return the
   same generic success response.
4. Issue `email_verify` one-time token (TTL 24h), send mail.
5. → `202 { status: "verification_sent" }`. No session issued yet (configurable:
   `allowUnverifiedLogin: false` by default).

Audit: `user.registered`, `email.verification_sent`.

### 5.2 Email verification

Atomic consume (§4.4) → set `email_verified_at`, `status='active'` → optionally auto-login (issue
session) → audit `email.verified`. Expired token → `410` with a one-click "resend" affordance.
Resend endpoint is rate-limited harder than most (3/hour/account) to prevent mail bombing.

### 5.3 Login (password)

1. Rate-limit pre-check on **both** `ip` and `email` buckets (§8.2). Exceeded → `429` with
   `Retry-After`.
2. Load user. ⚑ If absent, still run a dummy Argon2 verify against a fixed hash so response timing
   doesn't leak existence.
3. Check `status`: `suspended` → `403 ACCOUNT_SUSPENDED`; `deleted` → generic invalid-credentials;
   `locked_until > now()` → `423 ACCOUNT_LOCKED`.
4. Verify password. Failure → increment counter, record attempt, generic `401 INVALID_CREDENTIALS`.
5. ⚑ If `password_algo != 'argon2id'`, rehash now with the plaintext in hand (legacy migration).
6. If 2FA is enrolled or required by org policy → issue an **MFA challenge token** (§5.4.2) →
   `200 { status: "mfa_required", mfaToken, availableMethods }`. ⚑ No session and no access token
   exist at this point. A valid trusted-device cookie (§5.4.5) short-circuits this step and is
   recorded as `amr: ['pwd','device']`.
   If 2FA is required but no factor is confirmed → quarantined session (§5.4.6), not a hard failure.
7. Otherwise create session + refresh token + access token → `200 { status: "authenticated", user }`.

Audit: `auth.login_succeeded` / `auth.login_failed` (with reason) / `auth.mfa_challenged`.

### 5.4 Two-factor authentication (2FA) — full lifecycle

Four possible second factors, all sharing one verification pipeline and one challenge object.

| Channel | Strength | Default | Notes |
|---|---|---|---|
| TOTP (authenticator app) | Good | **on** | Offline, zero delivery cost, only real-time-phishable |
| Passkey / WebAuthn | Strongest | on (Phase 6) | Origin-bound ⇒ phishing-resistant; counts as two factors by itself |
| Email OTP code | Moderate | **on** | Shares the engine in §5.11; only as strong as the mailbox |
| SMS OTP code | Weak | **off** | SIM swap, SS7, port-out fraud. Enable only if a customer contract demands it, and never present it as the recommended option |

#### 5.4.1 Enrollment (TOTP)
Step-up required (§5.4.6). Server generates a 160-bit base32 secret, returns it **once** with an
`otpauth://totp/...` provisioning URI + QR payload, and stores it AEAD-encrypted with `confirmed_at`
NULL. The user must submit a valid code to confirm; only then is the factor active and the recovery
codes shown. ⚑ Unconfirmed factors never satisfy a challenge and are purged after 15 minutes —
otherwise a half-finished enrollment becomes a permanent unverified bypass. ⚑ Enabling 2FA revokes
other sessions (config) and sends an out-of-band notice email.

#### 5.4.2 The challenge object
After a successful first factor (§5.3 password, or §5.11 OTP), the server issues an **MFA challenge
token** — deliberately not a session:

| Property | Value |
|---|---|
| TTL | 5 min |
| Uses | single — but ⚑ *consumed on success only*. A wrong code spends an attempt; consuming up front would mean one guess per challenge, which is a different (and worse) design than five |
| Claims | `{ cid, sub, amr: ['pwd'], availableMethods: ['totp','email_otp','webauthn','recovery'] }` |
| Binding | `sha256(user_agent ‖ ip/24)` — must be redeemed from the same client |
| Authorizes | exactly one endpoint, `POST /auth/mfa/verify` (and `/auth/mfa/otp/send`) |
| Attempt cap | 5, then the **challenge** is destroyed, not merely the attempt |

⚑ It carries no `sid`, no permissions, and no resource-server audience — a leaked challenge token
cannot read a single byte of application data. `availableMethods` lets the UI offer "use your
authenticator / email me a code / use a passkey / use a recovery code" without a second round trip.

#### 5.4.3 Verification
- **TOTP**: accept ±1 timestep (30 s) for clock drift. ⚑ The same code must not be replayable
  inside its own validity window — drift tolerance is otherwise a 90-second window in which a
  shoulder-surfed or phished code still works.

  Implemented as a monotonic `last_used_timestep` on the factor row, advanced by a guarded
  `UPDATE ... WHERE last_used_timestep IS NULL OR last_used_timestep < $step`. A code whose step is
  not strictly greater is refused *even though it verified*. This replaced the originally-specified
  "record the `(userId, factorId, timestep)` triple in the rate limiter" for one reason: a replay
  guard in a cache **fails open** when the cache is down, and the failure mode of an open TOTP
  replay guard is silent. One integer column in the row that is already being read fails closed and
  costs nothing.
- **Enrolment burns its own timestep.** ⚑ The code that confirms a factor cannot also be the first
  login code — otherwise the ±1 window means the enrolment screen hands over a working credential.
- **Email/SMS OTP**: delegate to §5.11's verify path with `purpose='mfa'`.
- **Passkey**: WebAuthn assertion (§5.13).
- **Recovery code**: single-use (§5.4.4).
- ⚑ All comparisons constant-time. ⚑ `amr` distinctness is enforced: if the first factor was email
  OTP, an email OTP cannot also be the second factor — that is one factor counted twice.

Success → session created with `amr: ['pwd','otp']` (or `['pwd','webauthn']`),
`mfa_satisfied_at = now()`, then the normal §5.5 token pair is issued.
Audit `auth.mfa_succeeded` / `auth.mfa_failed` (with method and attempts remaining).

#### 5.4.4 Recovery
Ten single-use 128-bit codes, displayed once, hashed at rest, downloadable/printable. Using one
audits, emails the user, and prompts regeneration. ⚑ Warn in the UI at ≤2 remaining. Regenerating
invalidates all previous codes atomically. Total loss falls back to a **human** support flow —
identity proof plus an audited admin reset — never to security questions (guessable, and NIST
explicitly deprecates them).

#### 5.4.5 Trusted devices — "don't ask again for 30 days"
Opt-in per deployment (A13) and per login (a checkbox on the challenge screen). On 2FA success,
mint a 256-bit token into a **separate** `httpOnly; Secure; SameSite=Lax` cookie, hashed
server-side (§4.3). On the next login, a valid unrevoked trusted-device cookie satisfies the second
factor and records `amr: ['pwd','device']`.

⚑ Hard rules, because this is the feature most often implemented as a permanent 2FA bypass:
- Trust is scoped to (user, device token) and dies on password change, factor add/remove, 2FA
  disable, `logout-all`, or reuse detection.
- It is **never** accepted for step-up (§5.4.6) — a stolen laptop must not be able to change the
  password or export data.
- Each device is listed with label/IP/last-used in account settings and individually revocable.
- Max 10 per user, LRU-evicted; absolute cap 30 days with no sliding renewal.

#### 5.4.6 Enforcement policy and the enrollment quarantine
`mfa.enforce: 'optional' | 'admins' | 'all'`, overridable per org via `org.settings.requireMfa`.
When 2FA is required but the user has no confirmed factor, login **succeeds** into a quarantined
session: `amr: ['pwd']`, `mfa_required_at` set, access limited to `/auth/me`, the enrollment
endpoints, and logout. Every other route returns `403 MFA_ENROLLMENT_REQUIRED`.
⚑ This avoids the classic enforcement bug where the policy locks users out of the very screen that
would satisfy the policy. An optional `mfaGracePeriod` (e.g. 7 days) lets existing users keep
working while a banner counts down.

#### 5.4.7 Step-up / re-authentication
Sensitive operations require `mfa_satisfied_at` within `stepUpMaxAge` (default 15 min), else
`403 { code: 'REAUTH_REQUIRED', reauthMethods: ['password','totp','webauthn','email_otp'] }` so the
UI can prompt inline without losing the user's work. Gated set: password change, email change,
factor add/remove, recovery regeneration, trusted-device revoke-all, API-key create/revoke,
`logout-all`, role/permission changes, org deletion, bank/payout details, GDPR erasure, and starting
an impersonation. ⚑ A CI test walks the route table and asserts every endpoint on that list carries
the guard — enforcement by convention rots.

#### 5.4.8 Disabling 2FA
Requires step-up with a **currently active** factor (not a trusted device, not a password alone
when a factor exists). Audits, emails, revokes all trusted devices, and is refused outright with
`403 MFA_REQUIRED_BY_POLICY` when org policy mandates 2FA.

---

### 5.5 Refresh-token flow (rotation, reuse detection, revocation)

The most security-sensitive flow in the module, so it is specified end to end.

#### 5.5.1 The two tokens are deliberately different animals

| | Access token | Refresh token |
|---|---|---|
| Format | JWT, EdDSA-signed | Opaque: `rt_` + base64url(32 random bytes) |
| Server-side record | none (stateless) | row in `auth_refresh_tokens`, **hash only** |
| Lifetime | 10 min | idle 30 d, absolute 90 d (session-capped) |
| Accepted by | any resource server in `aud` | only `POST /auth/token/refresh` |
| Transport | `Authorization: Bearer` or `__Host-at` cookie | `__Host-rt` cookie scoped `Path=/auth/token`, or native secure storage |
| Revocable | at expiry, or instantly via §5.5.9 | immediately |
| Carries identity data | yes — claims | no. It is a lookup key and nothing else |

⚑ Refresh tokens are never JWTs. A self-contained refresh token cannot be revoked before expiry,
which defeats the entire purpose of having one.

#### 5.5.2 Issuance
Exactly one *unused* refresh token exists per session at any time. It is minted when a session is
created — password login, MFA success, OAuth callback, passkey login, magic link, OTP login — and
replaced on every use. ⚑ `switch-org` (§5.14) mints a new **access** token only: the session
identity has not changed, so the refresh chain must not fork.

#### 5.5.3 The rotation sequence

```
POST /auth/token/refresh
  cookie:  __Host-rt=rt_xxxxx          (bearer mode: body {refreshToken})
  header:  X-CSRF-Token: <csrf>        (cookie mode only)

BEGIN  -- SERIALIZABLE, or SELECT ... FOR UPDATE on the token row
 1  h := sha256(presented_secret)
 2  row := SELECT * FROM auth_refresh_tokens WHERE token_hash = h
 3  row IS NULL                          → 401 INVALID_REFRESH_TOKEN   audit refresh_unknown
 4  row.used_at IS NOT NULL              → ⚑ REUSE — go to §5.5.4      audit refresh_reuse_detected
 5  row.revoked_at IS NOT NULL           → 401 SESSION_REVOKED
 6  row.expires_at <= now()              → 401 REFRESH_EXPIRED
 7  s := session(row); s.revoked_at      → 401 SESSION_REVOKED
 8  s.absolute_expires_at <= now()       → 401 SESSION_EXPIRED   (re-login; never extended)
 9  s.idle_expires_at <= now()           → 401 SESSION_IDLE_TIMEOUT + revoke session
10  u := user(s); u.status != 'active'   → 401 ACCOUNT_INACTIVE  + revoke session
11  u.password_updated_at > s.created_at → 401 CREDENTIALS_CHANGED + revoke session
12  tenancy && membership(u, s.org_id) not active
                                         → drop org from session, re-resolve permissions
13  UPDATE auth_refresh_tokens SET used_at = now()
      WHERE id = row.id AND used_at IS NULL          -- the guard row
    0 rows affected → a concurrent refresh won      → 409 REFRESH_IN_PROGRESS (NOT theft)
14  new := INSERT refresh token, expires_at = min(now + idleTtl, s.absolute_expires_at)
15  UPDATE row SET replaced_by_id = new.id
16  UPDATE session SET last_seen_at = now(),
      idle_expires_at = min(now + idleTtl, absolute_expires_at)
17  claims := resolve(user, session, org)   -- roles & permissions re-read from the DB
18  access := mintAccess(claims)
COMMIT

→ 200 { accessToken, expiresIn: 600, user? }
  Set-Cookie: __Host-rt=<new secret>; HttpOnly; Secure; SameSite=Lax; Path=/auth/token
  Set-Cookie: __Host-at=<access>;     HttpOnly; Secure; SameSite=Lax; Path=/
  audit auth.refresh_rotated
```

⚑ Step 17 is the reason access tokens can be short-lived and dumb: every ~10 minutes the permission
set is re-derived from the database, so a role change, suspension, or org removal takes effect
within one access-token TTL with no distributed cache and no invalidation fan-out.

#### 5.5.4 Reuse means presumed theft
A used refresh token being presented again means two parties hold the same secret. Response:

1. Revoke the **entire chain** for that session (`revokeChain(session_id)` — walk `replaced_by_id`).
2. Revoke the session with `reason='reuse_detected'`.
3. `audit auth.refresh_reuse_detected` at high severity; emit `security.refresh_reuse_detected`.
4. Page an operator (§16) and email the user: "we signed out a device on your account."
5. Optionally revoke **every** session for the user (`reuseRevokesAllSessions`, default false).
6. Return a plain `401`. ⚑ Never reveal that reuse was detected — don't teach the attacker that the
   alarm exists or which token tripped it.

Why the whole family dies: after theft, the attacker and the legitimate client both hold valid
tokens and both will eventually refresh. Whoever comes second trips the alarm, so the theft window
closes automatically instead of lasting the full 90 days. That property is the entire justification
for rotation, and it evaporates if you only revoke the single reused token.

#### 5.5.5 The concurrency false-positive (and why most implementations get logged out)
Four browser tabs, four simultaneously-expired access tokens, four refreshes → three "reuse"
alarms and a logged-out user. Defenses in order of importance:

1. **Client-side single-flight + cross-tab leader election** (§13.3) — the real fix. One refresh in
   flight per browser, ever; the others await the same promise.
2. **The guard row**, step 13 — a request that reads the row clean and then loses the guarded
   `UPDATE` is *provably* a race: someone claimed the token between our read and our write. It gets
   `409 REFRESH_IN_PROGRESS`, waits ~200 ms, retries once, and picks up the winner's new cookie.
   Never counted as theft.
3. **`inFlightWindowMs`** (default `2 s`, max 30 s) — ⚑ the guard row alone is not enough, and
   assuming it was is the mistake this design originally made. Four tabs do not read in lockstep:
   whichever ones the connection pool starts *after* the winner commits read a row that is simply
   used, which is byte-for-byte what a replay looks like. The database cannot tell them apart, so
   the use-case decides on recency — a token claimed within this window is a sibling, not a thief.
   The asymmetry is what makes this cheap: a `409` hands the caller no tokens, so an attacker inside
   the window gains a retry and nothing else, while every attempt outside it still trips detection.
   Setting it to `0` restores the false positive and is flagged by `auditProductionConfig`.
4. **`reuseGraceMs`** (default `0`, max 10 s) — re-presenting the *immediate predecessor* within the
   window returns the current successor instead of alarming. Pragmatic for flaky mobile networks,
   but it widens the theft window, so it ships off. ⚑ Grace applies only to the direct predecessor,
   never deeper in the chain, and never after the successor has itself been used.

The three are ordered by how much they prove. (2) is a fact about ordering; (3) is a judgement about
time; (4) is a concession to unreliable networks. Only (2) is free.

#### 5.5.6 Where the tokens live, per client class

| Client | Access token | Refresh token | Notes |
|---|---|---|---|
| First-party web, same site | `__Host-at` httpOnly cookie | `__Host-rt` httpOnly cookie, `Path=/auth/token` | XSS can read neither; CSRF token required (§8.3) |
| Cross-origin SPA | memory only | httpOnly cookie on the auth origin, CORS with credentials | ⚑ never `localStorage`/`sessionStorage` |
| iOS / Android | memory | Keychain / EncryptedSharedPreferences (hardware-backed) | bind to app attestation where available |
| Desktop (Electron/Tauri) | memory | OS keyring | never a plain file on disk |
| Server-to-server / CLI | — | none — use API keys or client credentials (§4.6) | refresh tokens are for interactive humans only |

#### 5.5.7 Everything that must kill a refresh token
Logout; logout-all; password change; password reset; email change; 2FA enable/disable; factor
removal; reuse detection; admin session revoke; user suspension; user deletion; org membership
removal (that org's sessions); emergency key rotation; idle TTL reached; absolute TTL reached.
⚑ Each row above has a named test asserting both that the old refresh token is immediately dead and
that the old access token stops working within one TTL (§5.5.10).

#### 5.5.8 TTL matrix — tune per client class, don't use one number everywhere

| Client class | Access | Refresh idle | Refresh absolute | Rationale |
|---|---|---|---|---|
| Web app (default) | 10 min | 30 d | 90 d | Balance; a quarterly re-login is tolerable |
| Admin / billing console | 5 min | 12 h | 7 d | Blast radius of an admin token is much larger |
| Mobile app | 15 min | 60 d | 180 d | Re-login on a phone keyboard is expensive; device storage is stronger |
| Kiosk / shared terminal | 5 min | 15 min | 8 h | Walk-away risk dominates |
| High-security tenant (config) | 5 min | 8 h | 24 h | Per-org override, contract-driven |

#### 5.5.9 Optional instant access-token revocation
`revocationCheck: 'none' | 'cache'`. In cache mode, revoking a session writes
`SETEX revoked:sid:<sid> <accessTtl> 1`; resource servers do one O(1) Redis `GET` per request keyed
on the `sid` claim. Memory is bounded by (revocations × access TTL) and staleness is zero.
⚑ Fail **open** with a loud alert if Redis is unreachable — otherwise one cache outage becomes a
total authentication outage — and record that trade-off as an accepted risk in the ASVS checklist.

#### 5.5.10 Refresh test matrix (all must pass, §14.2)
Happy rotation · 50 sequential rotations · reuse of the immediate predecessor · reuse of an ancient
ancestor · reuse just inside and just outside `reuseGraceMs` · reuse just inside and just outside
`inFlightWindowMs` · 10 concurrent refreshes against real Postgres (exactly one `200`; every loser
either `concurrent` or a `reuse` whose `usedAt` is from moments ago — ⚑ asserting that `reuse` never
occurs here passes on a fast laptop and fails on CI, because it asserts a scheduling accident rather
than a guarantee) · expired refresh · revoked session · idle timeout · absolute timeout not extendable
· password changed mid-session · user suspended mid-session · user deleted mid-session · org
membership removed mid-session · missing CSRF token · cross-origin request · tampered token ·
another user's token · refresh after logout-all · refresh spanning a signing-key rotation · clock
skew ±60 s · an access token submitted in the refresh slot · refresh with a cookie whose `Path`
should have prevented it from being sent.

### 5.6 Logout

- `POST /auth/logout` — revoke current session + its refresh chain, clear cookies. ⚑ Idempotent, and
  returns 204 even for an already-dead session (no information leak, no client-side error paths).
- `POST /auth/logout-all` — revoke every session for the user except optionally the current one.
- Access tokens remain technically valid until expiry (≤10 min). For instant kill, enable
  `revocationCheck: 'cache'`: resource servers consult a Redis set of revoked session ids
  (`sid` claim) — one O(1) lookup per request, TTL-bounded by access-token lifetime.

### 5.7 Password reset

1. `POST /auth/password/forgot { email }` → ⚑ always `202`, always the same latency, regardless of
   existence. Rate-limit 3/hour/email and 10/hour/IP.
2. Token: 256-bit random, TTL 60 min, single-use, hashed at rest. ⚑ Link origin comes from config,
   **never** from the `Host`/`X-Forwarded-Host` header (host-header injection).
3. `POST /auth/password/reset { token, newPassword }` → validate policy + breach check + history →
   atomic consume → update hash, set `password_updated_at`.
4. ⚑ Revoke **all** sessions and **all** pending reset tokens for that user, then optionally issue a
   fresh session. Send a "your password was changed" notification (out-of-band tamper signal).

### 5.8 Password change (authenticated)

Requires current password even with a live session (⚑ defeats drive-by XSS/CSRF takeover). Same
policy checks, then revoke all *other* sessions by default.

### 5.9 Email change (dual confirmation)

1. Authenticated request + step-up → store `{newEmail}` in token payload; ⚑ check the new address
   isn't taken (generic error if it is).
2. Send **confirm** link to the new address, and a **notice** to the old one with a
   "this wasn't me — cancel" link that kills the pending token.
3. On confirm: atomic swap, set `email_verified_at`, audit `email.changed` with both values,
   revoke other sessions.

### 5.10 OAuth / social login

- `GET /auth/oauth/:provider/start` — PKCE (S256), `state` and `nonce` stored in a signed,
  httpOnly, 10-minute cookie. ⚑ `redirectTo` is validated against an allowlist of exact paths or
  origins — never reflected blindly (open redirect → token exfiltration).
- `GET /auth/oauth/:provider/callback` — verify `state`, exchange code (PKCE verifier), verify ID
  token signature/`iss`/`aud`/`nonce`/`exp` against cached JWKS.
- **Account linking rules** (get these wrong and you have an account-takeover primitive):
  - Existing identity match → log in.
  - No identity, email matches an existing user, **and** provider asserts `email_verified` **and**
    the provider is in `trustedEmailProviders` → link and log in.
  - Otherwise → do **not** auto-link. Create a new account, or require the user to log in with their
    existing method first and link deliberately from account settings.
  - ⚑ Never link on an unverified provider email. Never unlink the last remaining credential.
- Provider adapters: Google, Microsoft, GitHub, Apple built in; generic OIDC adapter for the rest.

### 5.11 Login by one-time passcode (OTP)

Passwordless login with a short numeric code — the flow most users now expect, and the right default
for the customer-facing side of a billing product ("view and pay your invoice" shouldn't require
inventing a password).

**Why OTP codes *and* magic links (§5.12):** a code can be typed into the device that started the
flow. It survives corporate mail gateways that rewrite or sandbox links, it works when the mail
arrives on a phone but the session is on a laptop, and it can't be silently consumed by a
link-prefetching security scanner. Magic links are one tap and better for mobile. Ship OTP first;
links are optional sugar over the same token machinery.

#### 5.11.1 Request

`POST /auth/otp/request { destination, channel }` where `channel` ∈ `email` (default) | `sms`.

1. Normalize the destination (lowercase/trim email, E.164 for phone) and validate shape.
2. Rate-limit per destination **and** per IP (§8.2).
3. ⚑ Respond `202 { challengeId, expiresIn, resendAfter, maskedDestination }` **identically**
   whether or not an account exists — and send no message when it doesn't. Same latency, same body.
   The `challengeId` for a non-existent account is a real, verifiable-looking, permanently-failing
   challenge, so probing tells the attacker nothing.
4. Generate a 6-digit code from a CSPRNG using **rejection sampling**. ⚑ Not `random() % 1_000_000`
   — modulo bias skews the distribution and shrinks the effective keyspace.
5. Store `sha256(code ‖ challengeId)`, `expires_at = now + 10 min`, `max_attempts = 5`, and (when
   `bindToClient`) `client_binding = sha256(ua ‖ ip/24)`.
6. ⚑ Invalidate any previous unconsumed challenge for the same (destination, purpose) so exactly one
   code is live — "the last code I received" must be unambiguous, and multiple live codes multiply
   the guessing surface.
7. Deliver. Resend permitted after 60 s, max 3 per challenge, then a fresh request is required.

⚑ Message content rules: state the app name, the code, the TTL, and "if you didn't request this,
ignore this message." The code goes in the **body only, never the subject line** — subjects render in
lock-screen previews and notification banners.

#### 5.11.2 Verify

`POST /auth/otp/verify { challengeId, code }`

```sql
-- ⚑ One atomic statement: parallel guesses cannot exceed the attempt cap
UPDATE auth_otp_challenges SET attempts = attempts + 1
WHERE id = $1 AND consumed_at IS NULL AND expires_at > now() AND attempts < max_attempts
RETURNING *;
```

- Constant-time compare of `sha256(submitted ‖ id)` against `code_hash`.
- Wrong code → `401 INVALID_CODE { attemptsRemaining }`. Cap reached → challenge destroyed, `429`.
- ⚑ Verify `client_binding` when `bindToClient: true` (default for `purpose='login'`): the code must
  be redeemed from the same user agent and /24 that requested it. This is what breaks the
  "attacker triggers the code, phones the victim, and asks them to read it out" attack — the code is
  useless in the attacker's browser.
- On success, mark consumed and branch on `purpose`:

| `purpose` | Outcome |
|---|---|
| `login`, account exists, no 2FA | Create session, `amr: ['otp']`. ⚑ If the destination was an unverified email, this **verifies** it — redeeming the code proves control |
| `login`, account has 2FA | Issue an MFA challenge (§5.4.2). ⚑ `amr` distinctness enforced: email OTP cannot be both factors |
| `login`, no account, `allowSignup: true` | Create user `status='active'`, `email_verified_at=now()`, emit `user.registered` |
| `login`, no account, `allowSignup: false` | `401` — byte-identical to a wrong code |
| `mfa` | Complete the 2FA challenge (§5.4.3) |
| `step_up` | Refresh `mfa_satisfied_at` only — no new session, no new refresh token |
| `phone_verify` | Set `phone_verified_at` |

#### 5.11.3 Config and the privilege caveat

```ts
otp: { enabled: true, channels: ['email'], codeLength: 6, ttl: '10m',
       maxAttempts: 5, resendAfter: '60s', maxResends: 3,
       bindToClient: true, singleActiveChallenge: true,
       allowSignup: false, excludeRoles: ['owner','admin'] }
```

⚑ OTP login is a **weaker** primary factor than password + 2FA: possession of the mailbox is the
entire credential, and mailbox compromise is common. Keep `excludeRoles` populated so owners and
admins of a billing org must use password + 2FA, and treat OTP-only login as the convenience path
for low-privilege and customer-portal accounts. Six digits is 10⁶ ≈ 20 bits — safe only because of
the 5-attempt cap, the single live challenge, and the 10-minute TTL. All three are load-bearing;
none may be relaxed independently.

Audit: `otp.requested`, `otp.sent`, `otp.resent`, `otp.verified`, `otp.failed`,
`otp.challenge_exhausted`.

### 5.12 Magic link (passwordless email)

Token 256-bit, TTL 15 min, single-use, ⚑ consumed via POST (not the GET the mail client prefetches),
⚑ bound to the requesting user agent unless `allowCrossDevice: true`. Same
enumeration-resistant response shape as password reset. Shares delivery, rate limits, and audit
shape with §5.11 — it is the same engine with a long random token instead of a short code.

### 5.13 Passkeys / WebAuthn

- Registration: server-generated challenge (stored, single-use, 5 min), `residentKey: preferred`,
  `userVerification: preferred`. Verify attestation, store credential, ⚑ enforce
  monotonic `sign_count` where the authenticator provides one (clone detection).
- Login: usernameless (discoverable credentials) or by user handle; `amr: ['webauthn']` counts as
  two factors, so passkey login satisfies MFA policy on its own.
- ⚑ `rpId` is fixed by config. It must not follow the request host.

### 5.14 Org invitations & tenant switching

- Invite → `org_invite` token (TTL 7 days) carrying `{orgId, roleId, email}`. Accepting requires
  being logged in as that email (or registering with it). ⚑ Role in the token is validated against
  the inviter's own permissions at *acceptance* time too — a demoted inviter's pending invite can't
  grant more than they now hold.
- `POST /auth/token/switch-org { orgId }` — verifies active membership, updates
  `session.org_id`, mints an access token with the new `org` and permission set. ⚑ No new refresh
  token; the session identity doesn't change.

### 5.15 Support impersonation

Off unless `impersonation.enabled`. Requires a system-level permission, records
`impersonated_by`, caps session TTL at 30 min, forces `amr: ['impersonation']`, blocks
step-up-gated operations entirely, stamps every audit row with both actors, and notifies the
impersonated user per policy. Non-negotiable: it is always visible in the audit log.

### 5.16 Account deletion

`soft` (default): `status='deleted'`, `deleted_at`, sessions revoked, credentials destroyed, email
released or tombstoned per config. `hard`: after a grace period a job anonymizes PII in place
(`email → deleted+<id>@invalid`, name/avatar nulled) while ⚑ preserving audit rows and financial
records — an invoicing product legally cannot delete those (§15).

---

## 6. Ports (the genericity contract)

These interfaces are the entire coupling surface. Implement them and the module runs anywhere.

```ts
// --- persistence ---
interface UserRepo {
  findById(id: UserId): Promise<User | null>
  findByEmail(email: string): Promise<User | null>
  create(input: NewUser): Promise<User>
  update(id: UserId, patch: Partial<User>): Promise<User>
  incrementFailedLogins(id: UserId, lockAfter: number, lockFor: Duration): Promise<LockState>
}
interface SessionRepo {
  create(s: NewSession): Promise<Session>
  findById(id: SessionId): Promise<Session | null>
  listActive(userId: UserId): Promise<Session[]>
  touch(id: SessionId, at: Date, idleExpiresAt: Date): Promise<void>
  revoke(id: SessionId, reason: RevokeReason): Promise<void>
  revokeAllForUser(userId: UserId, reason: RevokeReason, except?: SessionId): Promise<number>
}
interface RefreshTokenRepo {
  issue(sessionId: SessionId, hash: Uint8Array, expiresAt: Date): Promise<RefreshToken>
  /** Atomically mark used and return the row; null if unknown/expired/revoked. */
  claim(hash: Uint8Array): Promise<ClaimResult>
  revokeChain(sessionId: SessionId, reason: RevokeReason): Promise<void>
}
interface OneTimeTokenRepo { issue(...): Promise<void>; consume(hash, purpose): Promise<Payload|null>;
                             revokeAllForUser(userId, purpose): Promise<void> }
interface IdentityRepo { /* find/create/link/unlink */ }
interface MfaRepo { /* factors, webauthn creds, recovery codes */ }
interface OtpChallengeRepo {
  create(c: NewOtpChallenge): Promise<OtpChallenge>
  /** ⚑ Atomically increments attempts; null if consumed, expired, or already at max_attempts. */
  claimAttempt(id: ChallengeId): Promise<OtpChallenge | null>
  markConsumed(id: ChallengeId): Promise<void>
  /** Enforces singleActiveChallenge — call before creating a new one. */
  invalidateActive(destinationHash: Uint8Array, purpose: OtpPurpose): Promise<void>
  registerResend(id: ChallengeId): Promise<ResendDecision>
}
interface TrustedDeviceRepo {
  create(d: NewTrustedDevice): Promise<TrustedDevice>
  findValidByHash(hash: Uint8Array): Promise<TrustedDevice | null>
  listForUser(userId: UserId): Promise<TrustedDevice[]>
  revoke(id: DeviceId): Promise<void>
  revokeAllForUser(userId: UserId, reason: string): Promise<number>
}
interface OrgRepo { /* orgs, memberships, roles, permissions */ }
interface ApiKeyRepo { /* create/verify/revoke/list */ }
interface AuditRepo { append(e: AuditEvent): Promise<void>; query(f: AuditFilter): Promise<Page<AuditEvent>> }
interface UnitOfWork { transaction<T>(fn: (repos: Repos) => Promise<T>, opts?: TxOpts): Promise<T> }

// --- services ---
interface PasswordHasher { hash(p: string): Promise<HashResult>
                           verify(p: string, hash: string): Promise<boolean>
                           needsRehash(hash: string): boolean }
interface TokenService  { mintAccess(c: AccessClaims): Promise<string>
                          verifyAccess(t: string): Promise<AccessClaims>
                          jwks(): Promise<Jwks> }
interface KeyStore      { active(): Promise<SigningKey>; all(): Promise<SigningKey[]>; rotate(): Promise<void> }
interface RateLimiter   { consume(key: string, rule: Rule): Promise<Decision>; reset(key: string): Promise<void> }
interface Mailer        { send(msg: RenderedMail): Promise<void> }
interface SmsSender     { send(to: E164, body: string): Promise<void> }   // optional, off by default
interface TemplateEngine{ render(id: TemplateId, locale: string, vars: object): Promise<RenderedMail> }
interface TotpService   { generateSecret(): TotpSecret
                          provisioningUri(secret, account, issuer): string
                          verify(secret: TotpSecret, code: string, at: Date, window: number): boolean }
interface OtpCodeGen    { generate(length: number): string }  // ⚑ CSPRNG + rejection sampling, §5.11.1
interface WebAuthnService { registrationOptions/verifyRegistration/
                            authenticationOptions/verifyAuthentication }
interface Clock         { now(): Date }
interface RandomSource  { bytes(n: number): Uint8Array; uuid(): string }
interface EventBus      { publish(e: AuthEvent): Promise<void> }  // fire-and-forget, never blocks auth
interface Logger        { debug/info/warn/error(msg, ctx?): void }  // adapter applies redaction
interface BreachChecker { isBreached(password: string): Promise<boolean> }
interface GeoIp         { lookup(ip: string): Promise<GeoInfo | null> }  // optional, for anomaly mail
```

**Domain events** the host app can subscribe to (all async, all failure-isolated):
`user.registered`, `user.verified`, `user.logged_in`, `user.logged_out`, `user.password_changed`,
`user.suspended`, `user.deleted`, `session.revoked`, `mfa.enabled`, `mfa.disabled`,
`mfa.factor_added`, `mfa.factor_removed`, `otp.requested`, `otp.verified`,
`device.trusted`, `device.trust_revoked`,
`identity.linked`, `org.created`, `member.invited`, `member.joined`, `member.role_changed`,
`member.removed`, `apikey.created`, `apikey.revoked`, `security.suspicious_login`,
`security.refresh_reuse_detected`.

⚑ Event handlers must never be able to block or fail a login. Publish after commit, catch and log.

---

## 7. Configuration surface

### 7.1 Shape (zod-validated at boot; boot fails loudly on bad config)

```ts
{
  appName: 'Acme Billing',
  urls: { appOrigin: 'https://app.acme.com',      // ⚑ used to build every emailed link
          verifyPath: '/verify', resetPath: '/reset-password',
          invitePath: '/invite', magicLinkPath: '/magic',
          postLoginRedirectAllowlist: ['/dashboard', '/invoices'] },
  tenancy: 'orgs',                                 // 'none' | 'orgs'
  loginMethods: ['password', 'otp', 'oauth', 'passkey'],   // 'magic_link' opt-in; each toggleable
  tokens: {
    accessTtl: '10m', alg: 'EdDSA', issuer: 'https://auth.acme.com', audience: ['api.acme.com'],
    refresh: { idleTtl: '30d', absoluteTtl: '90d',
               rotate: true,              // ⚑ never false in production
               reuseGraceMs: 0,           // §5.5.5 — raising this widens the theft window
               inFlightWindowMs: 2000,    // §5.5.5 — ⚑ 0 turns every multi-tab race into "theft"
               reuseRevokesAllSessions: false,
               concurrentRetry: { attempts: 1, backoffMs: 200 } },
    revocationCheck: 'none',              // 'cache' for instant kill (§5.5.9)
    mfaChallengeTtl: '5m', stepUpMaxAge: '15m',
    perClientOverrides: { admin: { accessTtl: '5m', idleTtl: '12h', absoluteTtl: '7d' } },  // §5.5.8
  },
  cookies: { mode: 'cookie',                        // 'cookie' | 'bearer' | 'both'
             domain: '.acme.com', sameSite: 'lax', secure: true, path: '/',
             names: { access: '__Host-at', refresh: '__Host-rt' } },
  password: { minLength: 12, maxLength: 200, checkBreached: true, historyDepth: 5,
              // ⚑ NIST 800-63B: no composition rules, no forced expiry
              argon2: { memoryCost: 19456, timeCost: 2, parallelism: 1 } },
  lockout: { maxFailures: 10, lockFor: '15m', resetWindow: '15m' },
  mfa: { enabled: true,
         methods: ['totp','webauthn','email_otp'],   // 'sms_otp' opt-in only (A12)
         enforce: 'admins',                          // optional | admins | all
         gracePeriod: '7d',                          // quarantine-with-countdown, §5.4.6
         recoveryCodeCount: 10,
         totp: { digits: 6, period: 30, window: 1 },
         trustedDevices: { enabled: false, ttl: '30d', max: 10 } },   // §5.4.5, A13
  otp: { enabled: true, channels: ['email'], codeLength: 6, ttl: '10m',
         maxAttempts: 5, resendAfter: '60s', maxResends: 3,
         bindToClient: true, singleActiveChallenge: true,
         allowSignup: false, excludeRoles: ['owner','admin'] },       // §5.11.3
  email: { requireVerification: true, allowUnverifiedLogin: false, fromAddress: '...' },
  oauth: { google: { clientId, clientSecret, trustedEmail: true }, github: {...} },
  webauthn: { rpId: 'acme.com', rpName: 'Acme', origins: ['https://app.acme.com'] },
  rateLimits: { /* per-endpoint overrides, see §8.2 */ },
  audit: { retention: '400d', includeIp: true, ipPrecision: 'full' },  // 'full'|'masked'
  impersonation: { enabled: false, maxTtl: '30m', requiredPermission: 'support:impersonate' },
  i18n: { defaultLocale: 'en', bundles: { /* host overrides */ } },
}
```

### 7.2 Secrets

Never in config literals. `KEK` (for encrypting signing keys and TOTP secrets), OAuth client
secrets, and mail credentials come from env or a KMS/Secrets-Manager port. CI has a
gitleaks/trufflehog check; the config validator refuses obvious placeholder values in production.

### 7.3 Extension points

- `profile` jsonb on users + optional `profileSchema` (zod) the module validates against.
- `hooks`: `beforeRegister`, `afterRegister`, `beforeLogin`, `afterLogin`, `enrichAccessClaims`,
  `onSuspiciousLogin`. ⚑ Throwing from a `before*` hook aborts the operation with a
  host-supplied error code — that's the intended way to add allowlists, invite-only signup, or
  domain restrictions without forking.
- `registerPermissions()` for the host app's permission vocabulary.

---

## 8. Security controls

### 8.1 Password policy
Length 12–200 (upper bound prevents DoS via giant Argon2 inputs), no composition rules, no forced
rotation, breach-list check, reject values equal to email/appName, optional history check.
Argon2id at ~19 MiB / t=2 / p=1 (tune to ≤500 ms on target hardware; document the measured number).

### 8.2 Rate limiting (token bucket, per rule; Redis-backed in prod)

| Endpoint | Per IP | Per identity | On breach |
|---|---|---|---|
| `POST /auth/login` | 20 / 5 min | 10 / 15 min per email | 429 + `Retry-After`; progressive delay |
| `POST /auth/register` | 5 / hour | — | 429 |
| `POST /auth/password/forgot` | 10 / hour | 3 / hour per email | 202 (silent drop) |
| `POST /auth/password/reset` | 20 / hour | 5 / hour per token | 429 |
| `POST /auth/mfa/verify` | 30 / 5 min | 5 per challenge (hard fail) | invalidate challenge |
| `POST /auth/otp/request` | 10 / hour | 3 / hour per destination **and** 1 per 60 s | 202 (silent drop) |
| `POST /auth/otp/verify` | 30 / 5 min | 5 per challenge (hard fail) + 10 / hour per destination | destroy challenge, 429 |
| `POST /auth/mfa/otp/send` | 20 / hour | 3 per challenge | 429 |
| trusted-device cookie presented | 60 / 5 min | — | ignore the cookie, force full 2FA |
| `POST /auth/token/refresh` | 120 / 5 min | 60 / 5 min per session | 429 (⚑ distinct from the `409` concurrency case) |
| `POST /auth/magic-link/request` | 10 / hour | 3 / hour per email | 202 |
| email verification resend | 10 / hour | 3 / hour per account | 429 |
| OAuth start/callback | 60 / 5 min | — | 429 |
| API-key auth | per-key quota | — | 429 |

⚑ Bucket keys are hashed (`sha256(email)`), never raw PII in Redis. ⚑ Fail-**closed** on limiter
outage for login/reset (a limiter outage must not become an open brute-force window); fail-open only
for refresh, and alert.

### 8.3 Cookies & CSRF (cookie mode)
`httpOnly; Secure; SameSite=Lax; Path=/`, `__Host-` prefix when no subdomain sharing is needed.
Refresh cookie scoped to `Path=/auth/token`. ⚑ CSRF: double-submit token (random value in a
readable cookie + `X-CSRF-Token` header) verified on every state-changing route, plus `Origin`
header validation against the allowlist. `SameSite=Lax` alone is not sufficient defense.

Two carve-outs, both narrow, both deliberate:

1. **Pre-session routes** — login, register, verify-email, resend-verification, forgot/reset
   password, OTP request/verify, MFA verify. ⚑ The property that makes a route forgeable is that it
   acts on an *existing* session using ambient credentials; none of these do. Being under `/auth` is
   not the test, and treating it as one would exempt logout and refresh, which are forgeable.
2. **Requests carrying no session cookie at all** — not `csrf`, not the access cookie, not the
   refresh cookie. ⚑ A cross-site attacker cannot *remove* the victim's cookies; the browser sends
   whatever it holds. So a request arriving with none provably cannot act on an ambient credential,
   and refusing it only breaks the two calls a client must be able to make with nothing in hand:
   logging out, and discovering that it is logged out. See ADR-0010.

### 8.4 JWT hygiene
⚑ Pin accepted `alg` to the configured value — never trust the token header (`none`/HS-vs-RS
confusion). ⚑ Resolve `kid` only against the local key store (no URL fetching from the token).
Verify `iss`, `aud`, `exp`, `nbf`, `iat` with ≤60 s clock skew. Claims:

```json
{ "iss":"...", "aud":["api.acme.com"], "sub":"<userId>", "sid":"<sessionId>",
  "org":"<orgId>", "roles":["admin"], "perms":["invoice:*"], "amr":["pwd","otp"],
  "iat":0, "exp":0, "jti":"<uuid>", "ver":1 }
```
⚑ If `perms` would exceed ~1 KB, emit a `perms_ref` digest instead and have the resource server
resolve from cache — oversized headers break proxies and leak the permission model.

### 8.5 Response headers (HTTP adapter defaults)
`Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`,
`Cache-Control: no-store` on every auth response, restrictive CORS allowlist with
`credentials: true` only for configured origins, and `Permissions-Policy` for `publickey-credentials-get`.

### 8.6 Key rotation
Ed25519 keypair; `next` key published in JWKS ≥1 access-token-TTL before activation, old key kept in
JWKS while any token signed by it can still be valid, then retired. Rotation is a scheduled job
(default 90 days) plus a manual `auth keys rotate --emergency` that revokes all sessions.

### 8.7 Threat model → mitigation

| Threat | Mitigation | Where |
|---|---|---|
| Credential stuffing | Breach check, per-email + per-IP limits, lockout, anomaly mail, MFA | §5.1, §8.2 |
| Online brute force | Argon2id cost, progressive delay, lockout | §8.1–8.2 |
| Offline cracking after DB leak | Argon2id + per-hash salt + optional pepper in KMS | §8.1 |
| User enumeration | Uniform responses & timing on login/register/forgot/magic-link | §5.1, 5.3, 5.7 |
| Refresh-token theft | Rotation + reuse detection + family revocation + user alert | §5.5 |
| Access-token theft via XSS | httpOnly cookies (or in-memory only), 10-min TTL, strict CSP in host app | §8.3, §13 |
| CSRF | Double-submit token + Origin check + SameSite | §8.3 |
| Session fixation | Session id always freshly minted post-auth; challenge tokens never upgrade in place | §5.3 |
| Open redirect → token exfil | Exact-match redirect allowlist | §5.10 |
| Host-header injection in links | Links built from `config.urls.appOrigin` only | §5.7 |
| Account takeover via OAuth linking | Never auto-link on unverified provider email | §5.10 |
| Magic-link prefetch consumption | POST-to-consume, UA binding | §5.12 |
| TOTP replay inside drift window | Consumed `(user, factor, timestep)` tracking; 5-attempt cap kills the challenge | §5.4.3 |
| OTP brute force (10⁶ keyspace) | 5-attempt cap, exactly one live challenge, 10-min TTL, per-destination + per-IP limits — all three load-bearing | §5.11 |
| OTP relay ("read me the code you just got") | Challenge bound to `sha256(ua ‖ ip/24)`; code unusable in the attacker's browser | §5.11.2 |
| Predictable OTP codes | CSPRNG with rejection sampling, never `random % 10^n` | §5.11.1 |
| OTP code leaked via notification preview | Code in body only, never the subject line | §5.11.1 |
| One factor counted twice (email OTP as 1st + 2nd) | `amr` distinctness enforced at verification | §5.4.3 |
| SMS interception / SIM swap / port-out | SMS channel off by default and never presented as recommended | §5.4 |
| Trusted device = permanent 2FA bypass | Separate httpOnly cookie, 30-day absolute cap with no renewal, dies on any credential change, never accepted for step-up, individually revocable | §5.4.5 |
| 2FA enforcement locks users out (availability) | Quarantine session reaching only enrollment endpoints | §5.4.6 |
| Refresh race → spurious logout (availability) | Client single-flight, server guard row → `409` not theft, optional predecessor grace | §5.5.5 |
| Passkey cloning | Monotonic sign-count enforcement | §5.13 |
| Privilege escalation | Server-side permission resolution, role grants validated against registry, no client-supplied roles | §4.5, §10 |
| IDOR / cross-tenant read | `org_id` from token, never from request body; repo-level tenant scoping + RLS option | §10.3 |
| Timing side channels | Constant-time compares for all token/hash equality (`crypto.timingSafeEqual`) | crypto pkg |
| Token-consumption race | Single atomic `UPDATE ... WHERE consumed_at IS NULL RETURNING` | §4.4 |
| Mail bombing / spam relay | Per-account resend caps, suppression list, bounce handling | §8.2 |
| Log leakage of secrets | Adapter-level redaction allowlist + a test asserting no secret ever appears in logs | §14.3 |
| Insider / support abuse | Impersonation gated, capped, always audited and notified | §5.15 |
| Audit tampering | Append-only grants; no UPDATE/DELETE for the app DB role; optional WORM export | §4.7 |

---

## 9. Audit event catalogue

`user.registered`, `email.verification_sent|verified|changed|change_requested|change_cancelled`,
`auth.login_succeeded|login_failed|logout|logout_all`, `auth.mfa_challenged|mfa_succeeded|mfa_failed`,
`auth.refresh_rotated|refresh_unknown|refresh_expired|refresh_concurrent|refresh_reuse_detected`,
`auth.step_up_succeeded|step_up_failed`,
`otp.requested|sent|resent|verified|failed|challenge_exhausted|delivery_failed`,
`password.reset_requested|reset_completed|changed`, `account.locked|unlocked|suspended|reactivated|deleted|anonymized`,
`mfa.factor_added|factor_confirmed|factor_removed|enabled|disabled|enforcement_quarantined`,
`mfa.recovery_codes_generated|recovery_code_used|recovery_codes_low`,
`device.trusted|trust_used|trust_revoked|trust_expired`,
`identity.linked|unlinked`, `passkey.registered|removed|used`,
`org.created|updated|settings_changed`, `member.invited|invite_accepted|invite_revoked|role_changed|removed|suspended`,
`role.created|updated|deleted|permissions_changed`,
`apikey.created|used_first_time|revoked|expired`,
`session.revoked_by_admin`, `impersonation.started|ended`,
`keys.rotated|emergency_rotated`, `security.suspicious_login|new_device|new_country`,
`gdpr.export_requested|export_delivered|erasure_requested|erasure_completed`.

Each row carries actor, target, ip, ua, session, outcome, and a purpose-shaped `metadata`.

---

## 10. Authorization

### 10.1 Resolution order
1. Access token carries `org`, `roles`, `perms` — minted at login/refresh/org-switch, so a role
   change takes effect within one access-token TTL (or immediately with `revocationCheck`).
2. `can(subject, action, resource?)`:
   - explicit deny (if `denyPermissions` used) → deny
   - wildcard/exact permission match → continue
   - registered **policy** for that action → must also return allow (row-level: "only the invoice
     owner or an admin", "only within your own org")
   - otherwise deny.
3. ⚑ Default deny. An unregistered action is denied, not allowed.

### 10.2 Enforcement surfaces
Express/Fastify middleware `requireAuth()`, `requirePermission('invoice:write')`,
`requireStepUp()`, `requireOrgContext()`; Nest guards + `@Permissions()` decorator; and a plain
`auth.can()` for service-layer checks. ⚑ HTTP-layer checks alone are insufficient — service layer
re-checks, because internal callers bypass middleware.

### 10.3 Tenant isolation
`org_id` is read **only** from the verified token. Repositories in the host app take an
`AuthContext` and every query is scoped by it; the Postgres adapter can additionally emit
`SET LOCAL app.current_org` + RLS policies for defense in depth. A CI test attempts ~20
cross-tenant reads/writes and must get 403/404 on all of them.

### 10.4 401 vs 403
`401` = no/invalid/expired credential (client should refresh, then re-login).
`403` = authenticated but not allowed (client must not retry). `403 REAUTH_REQUIRED` is the one
403 the client *should* act on, by prompting for step-up.

---

## 11. HTTP API surface

All under `/auth`. JSON in/out. Errors: `{ error: { code, message, details?, traceId } }`.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/register` | — | Create account |
| POST | `/verify-email` | — | Consume verify token |
| POST | `/verify-email/resend` | — | Resend verification |
| POST | `/login` | — | Password login → session or MFA challenge |
| POST | `/otp/request` | — | Send a login OTP code (email/SMS) → `{challengeId}` |
| POST | `/otp/verify` | — | Redeem code → session, MFA challenge, or signup |
| POST | `/mfa/verify` | challenge | Complete 2FA (TOTP / OTP / recovery) → session |
| POST | `/mfa/otp/send` | challenge | Send an OTP code as the *second* factor |
| POST | `/token/refresh` | refresh | Rotate refresh chain + mint access token (§5.5.3) |
| POST | `/token/switch-org` | access | Change active tenant |
| POST | `/logout` | access | Revoke current session |
| POST | `/logout-all` | access + step-up | Revoke all sessions |
| GET | `/me` | access | Current user, orgs, perms |
| PATCH | `/me` | access | Update profile |
| GET | `/sessions` | access | List devices |
| DELETE | `/sessions/:id` | access | Revoke one device |
| POST | `/password/forgot` | — | Request reset |
| POST | `/password/reset` | — | Complete reset |
| POST | `/password/change` | access + current pw | Change password |
| POST | `/email/change-request` | access + step-up | Start email change |
| POST | `/email/change-confirm` | — | Confirm from new address |
| POST | `/email/change-cancel` | — | Cancel from old address |
| POST | `/mfa/totp/setup` | access + step-up | Return secret + `otpauth://` URI + QR payload (once) |
| POST | `/mfa/totp/confirm` | access | Verify a code → activate the factor |
| GET | `/mfa/factors` | access | List factors + enrollment/enforcement state |
| DELETE | `/mfa/factors/:id` | access + step-up | Remove factor (refused if policy requires 2FA) |
| POST | `/mfa/recovery-codes` | access + step-up | (Re)generate codes, invalidating the old set |
| GET | `/trusted-devices` | access | List remembered devices |
| DELETE | `/trusted-devices/:id` | access | Forget one device |
| DELETE | `/trusted-devices` | access + step-up | Forget all devices |
| GET | `/oauth/:provider/start` | — | Begin OAuth (PKCE) |
| GET | `/oauth/:provider/callback` | — | Complete OAuth |
| POST | `/oauth/:provider/link` | access + step-up | Link to existing account |
| DELETE | `/oauth/:provider/link` | access + step-up | Unlink (never the last credential) |
| POST | `/magic-link/request` | — | Email a login link |
| POST | `/magic-link/consume` | — | Exchange for session |
| POST | `/webauthn/register/options` \| `/verify` | access | Enroll passkey |
| POST | `/webauthn/login/options` \| `/verify` | — | Passkey login |
| GET/POST | `/orgs` | access | List / create |
| GET/PATCH | `/orgs/:id` | perm | Read / update |
| GET/POST/DELETE | `/orgs/:id/members[/:userId]` | perm | Manage members |
| PATCH | `/orgs/:id/members/:userId/role` | perm | Change role |
| POST | `/orgs/:id/invitations` | perm | Invite |
| GET/DELETE | `/orgs/:id/invitations[/:id]` | perm | List / revoke |
| POST | `/invitations/accept` | access | Accept invite |
| GET/POST/DELETE | `/orgs/:id/roles[/:id]` | perm | Custom roles |
| GET | `/permissions` | access | Registry (for admin UI) |
| GET/POST/DELETE | `/api-keys[/:id]` | perm + step-up | Machine credentials |
| GET | `/audit-events` | perm | Paginated audit log |
| POST | `/gdpr/export` \| `/gdpr/erase` | access + step-up | Data rights |
| GET | `/.well-known/jwks.json` | — | Public keys (cacheable) |
| GET | `/health` \| `/ready` | — | Liveness / dependency checks |

An OpenAPI 3.1 document is generated from the zod schemas; the browser SDK's types are generated
from it, so contract drift breaks the build.

---

## 12. Emails

**Email templates:** verify-email, welcome, **login-otp-code**, **mfa-otp-code**, magic-link,
password-reset, password-changed, email-change-confirm, email-change-notice, org-invite,
mfa-enabled, mfa-disabled, recovery-code-used, recovery-codes-low, **trusted-device-added**,
new-device-login, suspicious-login, **signed-out-suspicious-activity** (reuse detection, §5.5.4),
account-locked, account-deleted, gdpr-export-ready.

**SMS templates** (only if the channel is enabled): login-otp-code, mfa-otp-code,
phone-verify-code — each ≤160 chars, app name first, code second, no links (link-in-SMS trains
users to tap phishing).

Rules: MJML → HTML + plaintext, i18n keys not hardcoded strings, ⚑ no secrets in the subject line
(OTP codes especially — subjects appear in lock-screen previews),
⚑ links built from config origin with a short TTL stated in the body, one-click cancel/revoke where
applicable, suppression list honored, bounces and complaints fed back to mark addresses
undeliverable. Delivery is queued and retried — a mail-provider outage must not fail registration.

---

## 13. Client integration

### 13.1 Mode choice
Same-site web app → **cookie mode** (no token in JS, XSS can't exfiltrate). Mobile/desktop/native or
cross-origin SPA → **bearer mode**: access token in memory only, refresh token in Keychain/Keystore
(never `localStorage`).

### 13.2 Browser SDK (`auth-client`)
`login`, `loginWithOtp({ request, verify })`, `loginWithPasskey`, `verifyMfa`, `sendMfaOtp`,
`logout`, `refresh`, `me`, `hasPermission`, `onAuthStateChange`. Keeps the access token in a closure
(not on `window`), decodes only `exp`, and schedules a proactive refresh at ~80% of TTL so requests
rarely see a 401 at all.

### 13.3 Single-flight refresh (mandatory, not an optimization)
⚑ Concurrent 401s must trigger **one** refresh; every other caller awaits the same promise and then
replays its request. Without this, parallel requests rotate the chain in parallel and trip your own
reuse detection (§5.5.4), logging the user out for no reason. Implementation:

```ts
let inflight: Promise<string> | null = null
async function getFreshToken() {
  if (inflight) return inflight                       // 1. same-tab coalescing
  inflight = navigator.locks                           // 2. cross-tab leader election
    ? navigator.locks.request('auth-refresh', doRefresh)
    : withLocalStorageMutex('auth-refresh', doRefresh) // 3. fallback for older browsers
  try { return await inflight } finally { inflight = null }
}
```

Followers are notified of the new token via `BroadcastChannel('auth')` rather than each refreshing.
On `409 REFRESH_IN_PROGRESS`, wait 200 ms and retry **once**, then treat as logged out.
⚑ Test this with 4 tabs and a forced-expired token — it's the single most common production bug in
rotating-refresh implementations.

### 13.3a OTP and 2FA client flows
- OTP login is two states: request → "we sent a code to a•••@example.com" with a resend timer driven
  by the server's `resendAfter` (⚑ never a client-side guess), then a 6-box code input with paste and
  autofill support (`autocomplete="one-time-code"`, `inputmode="numeric"`).
- Show `attemptsRemaining` from the verify response; on challenge exhaustion, route back to request
  rather than leaving a dead code box on screen.
- 2FA challenge screen renders from `availableMethods` in the challenge token — no hardcoded method
  list, so enabling a channel server-side needs no client release.
- ⚑ The trusted-device checkbox is unchecked by default and labeled with the real duration.

### 13.4 React bindings
`<AuthProvider>`, `useAuth()`, `useSession()`, `<RequireAuth>`, `<RequirePermission perm="...">`,
`useStepUp()` (renders the re-auth modal on `REAUTH_REQUIRED`). SSR: read session server-side from
the cookie, pass an initial state to avoid the login flash.

### 13.5 Reference UI screens
Login (password + "email me a code" + "continue with…"), OTP code entry, register, verify-email
pending, forgot/reset password, 2FA challenge (method picker), 2FA setup (QR + secret + recovery
codes), recovery-code entry, passkey enrollment, trusted-devices list, account settings (profile,
password, sessions/devices, factors, linked accounts), org switcher, members & invites, roles editor,
API keys, audit log viewer, step-up modal. Shipped unstyled/headless with a Tailwind reference theme.

---

## 14. Testing strategy

### 14.1 Layers
- **Unit** (fast, no I/O): use-cases against `auth-testing` in-memory adapters + fake clock.
  Target ≥90% branch coverage in `auth-core`; **100%** on refresh rotation, policy evaluation,
  one-time-token consumption, and OTP attempt accounting — the four places where an off-by-one is a
  vulnerability rather than a bug.
- **Integration**: real Postgres + Redis via testcontainers; every repository, every migration
  up **and** down, concurrency tests (parallel refresh, parallel one-time-token consume, parallel
  OTP attempts against one challenge, parallel invite accept) that must show zero double-spend.
- **Contract**: one shared suite executed against *every* adapter (pg, Prisma, in-memory), so
  adapters can't diverge. Same for HTTP adapters against the same request/response fixtures.
- **E2E**: Playwright against `auth-playground` — full journeys including email (Mailpit), TOTP
  (generated codes), passkeys (CDP virtual authenticator), OAuth (mock OIDC provider).

### 14.2 Security test suite (must-pass gate, not optional)

**Refresh & session** — the full 22-case matrix in §5.5.10, plus session revocation on password
change and the §5.5.7 revocation-trigger table (one test per row).

**OTP** — code guessing stops at the cap (parallel and sequential); challenge dies at the cap;
expired code rejected; consumed code rejected; second live challenge invalidates the first;
cross-client redemption blocked when `bindToClient`; resend throttle honored server-side;
enumeration parity between existing and non-existent destinations (body **and** timing);
code-distribution χ² test over 100k generated codes (catches modulo bias);
`allowSignup: false` returns a response byte-identical to a wrong code;
`excludeRoles` prevents OTP-only login for an owner account.

**2FA** — TOTP replay in the same timestep; ±1 drift accepted, ±2 rejected; attempt cap destroys the
challenge; unconfirmed factor cannot satisfy a challenge; recovery code single-use; regeneration
invalidates the old set; email OTP rejected as second factor when it was also the first (`amr`
distinctness); challenge token rejected on any endpoint other than `/auth/mfa/verify`; challenge
token rejected from a different UA/IP; enforcement quarantine allows exactly the enrollment routes
and nothing else; trusted-device cookie ignored for step-up; trusted device invalidated by password
change, factor change, and `logout-all`; forged/expired trusted-device cookie rejected; 2FA disable
refused under org policy.

**Tokens & transport** — JWT `alg=none` / HS-vs-EdDSA confusion / wrong-`kid` / external-`jku`
rejection; expired and `nbf`-future tokens; CSRF absent or mismatched; cross-origin rejection.

**Flow-level** — enumeration timing on login/register/forgot (statistical, 200 samples); lockout
behavior; open-redirect payload set (~20); host-header injection in reset links; magic-link reuse and
prefetch; invite role-escalation after inviter demotion; unlinking the last remaining credential.

**Authorization & data** — cross-tenant IDOR matrix; privilege escalation via client-supplied
`roles`/`org`/`perms` fields; log-redaction assertion (no password, code, token, or secret ever
appears in any log line, asserted over a captured transcript); SQL-injection fuzz on all string
inputs.

### 14.3 Automation in CI
`zod` schema → OpenAPI diff check, dependency-cruiser layering check, `npm audit`/OSV scan,
gitleaks, Semgrep with the OWASP + JWT rulesets, and a k6 load profile (login p99 < 400 ms at
target RPS, refresh p99 < 100 ms) so Argon2 cost stays honest under concurrency.

---

## 15. Compliance & data protection

- **GDPR**: lawful basis documented per field; `/gdpr/export` (JSON bundle: profile, sessions,
  identities, audit slice) and `/gdpr/erase` (soft → grace → anonymize). ⚑ Erasure preserves audit
  and financial records — for an invoicing product, retention obligations override erasure for those,
  and the export/erase response must state that.
- **Data map**: users (PII incl. optional phone), audit (PII + IP), login attempts (hashed email +
  IP), OTP challenges (⚑ hashed destination only — no raw email or phone), trusted devices (IP +
  user-agent string). Retention: OTP challenges purged 1 d after expiry, login attempts 30 d,
  trusted devices 30 d max, audit 400 d default (configurable, jurisdiction-driven), soft-deleted
  users 30 d grace.
- **Phone numbers** are collected only if the SMS channel is enabled, are optional, and are erasable
  independently of the account (`DELETE /auth/me/phone`) — a phone number given for 2FA must not
  become permanently sticky data.
- **IP handling**: `audit.ipPrecision: 'masked'` truncates to /24 and /48 for privacy-strict
  deployments.
- **OWASP ASVS L2** mapping maintained as a checklist (V2 authentication, V3 session management,
  V4 access control, V6 crypto, V7 logging, V8 data protection). Every unchecked item is either
  implemented or written down as an accepted risk with an owner.
- **NIST 800-63B**: AAL1 by default; AAL2 with TOTP/passkeys; no password expiry, no
  knowledge-based-answer recovery, no SMS as a promoted factor.
- **SOC 2 relevant**: audit immutability, access reviews via the members/roles export, key-rotation
  evidence, and alerting on `security.*` events.
- **Not in scope**: PCI DSS (no card data touches this module), HIPAA.

---

## 16. Observability & operations

**Metrics** (Prometheus/OTel): `auth_login_total{result,method}`,
`auth_login_duration_seconds` (histogram), `auth_refresh_total{result}`,
`auth_refresh_reuse_detected_total`, `auth_refresh_concurrent_total`,
`auth_mfa_total{type,result}`, `auth_mfa_enrolled_ratio`,
`auth_otp_total{channel,purpose,result}`, `auth_otp_delivery_duration_seconds`,
`auth_otp_challenge_exhausted_total`, `auth_trusted_device_used_total`,
`auth_password_reset_total{stage}`, `auth_active_sessions`, `auth_rate_limited_total{endpoint}`,
`auth_lockouts_total`, `auth_mail_send_total{template,result}`,
`auth_hash_duration_seconds`, `auth_jwks_key_age_days`, `auth_signup_total{provider}`.

**Alerts**: any `refresh_reuse_detected` (page — likely token theft); `refresh_concurrent_total`
spike (a client single-flight regression, §13.3 — silently degrades every user's session);
OTP verify-failure ratio > 30% for 10 min (guessing campaign, or delivery is broken and users are
typing stale codes); OTP delivery p95 > 30 s (users abandon at ~30 s, so this is a conversion
incident as much as a security one); `otp_challenge_exhausted` spike; login-failure ratio > 40% for
5 min (credential stuffing); lockouts > 3σ above baseline; mail failure rate > 5%; JWKS active key
age > rotation SLO; limiter backend down; p99 login > 1 s; audit-write failures (⚑ if audit writes
fail, security-critical operations should fail too — that's a deliberate choice to record, not a
silent degradation).

**Runbooks**: suspected token theft (reuse alarm triage); mass credential stuffing; OTP delivery
outage (⚑ decision tree: switch provider, or temporarily fall back to password login — never extend
the OTP TTL, which is the tempting wrong answer); **user lost their 2FA device** (identity proof →
audited admin factor reset → forced re-enrollment, and what evidence is required); trusted-device
mass revocation; refresh-storm / single-flight regression; emergency key rotation; "locked out of my
account" support flow; mail provider outage; Redis outage (limiter fail-closed implications);
rollback of an auth deploy (⚑ migrations must be backward-compatible for one release so N-1 pods
keep serving); bulk session revocation.

**Ops CLI**: `auth keys rotate|list`, `auth user find|suspend|unlock|reset-mfa`,
`auth sessions revoke --user`, `auth devices revoke --user`, `auth otp status --destination`,
`auth audit export`, `auth migrate up|down|status`,
`auth doctor` (validates config, keys, DB, mailer, limiter and prints a readiness report).

**Background jobs**: purge expired one-time tokens, OTP challenges, and login attempts (hourly),
expire and prune trusted devices (daily), retire old signing keys (daily),
anonymize past-grace deletions (daily), send trial/renewal-adjacent security digests (optional),
audit archive to cold storage (monthly).

---

## 17. Adoption path for an existing project

1. Run migrations into a separate schema (`auth`), so nothing collides.
2. Backfill users; import legacy hashes as `password_algo='bcrypt'` (or `sha1`/`md5` with a
   `legacy_` prefix and a forced-reset flag). ⚑ Lazily rehash to Argon2id on first successful login;
   report the remaining-legacy count as a metric and force-reset the tail after a deadline.
3. Run both auth systems side by side behind a flag; route login through the new module for an
   allowlist of users, then a percentage, then all.
4. Move authorization last: keep legacy role checks reading from the new tables via a compatibility
   view until every call site uses `can()`.
5. Delete the legacy path only after the legacy-hash count reaches zero and one full audit-retention
   window has passed.

---

## 18. Delivery phases

Sizing is relative effort for one experienced dev; treat it as sequencing, not a schedule commitment.

| Phase | Scope | Exit criteria |
|---|---|---|
| **0 — Foundations** (M) | Monorepo, config validation, ports, error model, crypto pkg, Postgres migrations + repos, audit, in-memory test adapters, CI (lint/layering/scan) | `auth doctor` green; contract suite runs against pg + in-memory; migrations up/down clean |
| **1 — Core password auth + refresh** (L) | Register, verify, login, logout, **the full §5.5 refresh flow — rotation, reuse detection, family revocation, guard row**, sessions/device list, password reset/change, `/me`, email pipeline, cookie + bearer modes, rate limiting | Happy path green; **the entire §5.5.10 matrix passes, including 4-concurrent-refresh with zero false alarms**; §14.2 groups *refresh & session*, *tokens & transport*, *flow-level* pass; p99 login < 400 ms, p99 refresh < 100 ms; **this is the usable MVP** |
| **2 — Authorization & tenancy** (L) | Orgs, memberships, roles, permission registry, policy hook, invites, org switching, `can()` + guards, cross-tenant IDOR matrix, admin endpoints | Cross-tenant test matrix all 403/404; default-deny proven; role change reflected within one TTL |
| **3 — OTP engine & login by code** (M) | `auth_otp_challenges`, request/verify, email channel, enumeration parity, client binding, resend throttle, single-active-challenge, `allowSignup` + `excludeRoles`, SMS adapter behind a flag, OTP UI | χ² code-distribution test passes; parallel guessing cannot exceed the cap; enumeration parity proven in **body and timing**; OTP delivery p95 < 10 s |
| **4 — 2FA, trusted devices & step-up** (L) | TOTP enroll/confirm, recovery codes, email OTP as second factor (reuses Phase 3), challenge object + `availableMethods`, enforcement policy + quarantine session, trusted devices, step-up guard + `REAUTH_REQUIRED`, account-security UI | Timestep replay blocked; challenge dies at the cap; `amr` distinctness enforced; quarantine reaches only enrollment routes; route-table test proves every sensitive endpoint is step-up-gated |
| **5 — Federated & magic links** (M) | OAuth (Google/Microsoft/GitHub/Apple + generic OIDC), PKCE, linking rules, magic links | Open-redirect and unverified-email-linking tests pass; mock-OIDC e2e green |
| **6 — Passkeys** (M) | WebAuthn register/login, sign-count enforcement, passkey-as-2FA | Virtual-authenticator e2e green; passkey login satisfies 2FA policy on its own |
| **7 — Machine & enterprise** (L) | API keys + scopes, service tokens, SAML/OIDC SSO per org, SCIM provisioning, domain capture | Enterprise tenant can SSO + auto-provision + deprovision; key rotation for SSO certs documented |
| **8 — Hardening & ops** (M) | Key rotation automation, anomaly detection (new device/country), impersonation, GDPR endpoints, dashboards/alerts, runbooks, load tests, docs site | Alerts fire in a game-day drill; runbooks executed once each; ASVS L2 checklist complete or risk-accepted |

**Sequencing note:** Phase 3 lands before Phase 4 deliberately — the OTP engine (generate → deliver →
attempt-capped verify) is the *same* machinery whether the code is a primary factor or a second one,
so building it once for login means email 2FA is nearly free in Phase 4. If 2FA matters more to you
than passwordless login, swap the two: Phase 4 then ships TOTP + recovery codes only, and email OTP
as a second factor waits for the engine.

Deferred candidates, explicitly out of the phases above: acting as an OAuth2/OIDC **provider** for
third-party apps (device code, client credentials, consent screens), risk-based/adaptive auth
scoring, and hardware-attested device trust.

---

## 19. Open decisions I need from you

These don't block Phase 0, but they do block the phase named beside each.

1. **Build vs buy** (blocks everything) — assumption A10 says build. If a managed provider is
   acceptable, the plan collapses dramatically.
2. **Stack** (blocks Phase 0) — TypeScript/Node assumed. If this project is .NET, Laravel, Django,
   or Go, §3/§6 need rewriting; §4, §5, §8–§11, §14–§16 carry over almost unchanged.
3. **Tenancy** (blocks Phase 2) — an invoicing product usually needs orgs with per-org roles. Confirm
   whether one user must belong to multiple orgs (assumed yes) and whether orgs can nest (assumed no).
4. **OTP as *primary* login** (blocks Phase 3) — assumed **yes for customer-portal accounts, no for
   owners/admins** (`excludeRoles`). Confirm, because it's the difference between "anyone with the
   mailbox can see every invoice" and a slightly higher-friction login.
5. **Signup via OTP** (blocks Phase 3) — `allowSignup` assumed **false** (accounts are created by
   invitation or registration, not by anyone who can receive a code). Flip it only if you want
   self-serve passwordless signup.
6. **SMS channel** (blocks Phase 3 scope) — assumed **off**. Turning it on means picking a provider
   (Twilio/MessageBird/SNS), budgeting per-message cost, and accepting SIM-swap risk plus
   international deliverability pain. Is there a customer actually asking?
7. **2FA enforcement** (blocks Phase 4) — assumed `'admins'` with a 7-day grace period. Options are
   optional-for-all, admins-only, or all users.
8. **Trusted devices** (blocks Phase 4) — assumed **off**. Enabling it trades a real security
   reduction for real convenience; for a billing product handling money, I'd leave it off for
   admin roles at minimum.
9. **Enterprise SSO / SCIM** (blocks Phase 7) — real customer demand, or defer indefinitely?
10. **Frontend shape** (blocks Phase 1 transport choice) — same-site web app only (cookie mode), or
    also mobile/third-party clients (bearer mode)? This also sets the §5.5.8 TTL row you start from.
11. **Refresh TTLs** (blocks Phase 1) — the §5.5.8 defaults (10 min / 30 d / 90 d) assume a normal
    web app. A finance product may want the admin-console row (5 min / 12 h / 7 d) as the default
    instead.
12. **Audit retention** (blocks Phase 0 schema decisions) — 400 days assumed; confirm against your
    jurisdiction and any customer contracts.
```
