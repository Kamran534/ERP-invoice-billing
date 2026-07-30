CREATE TABLE "auth_api_keys" (
	"id" uuid PRIMARY KEY NOT NULL,
	"org_id" uuid,
	"created_by" uuid,
	"name" text NOT NULL,
	"prefix" text NOT NULL,
	"key_hash" "bytea" NOT NULL,
	"scopes" text[] DEFAULT '{}'::text[] NOT NULL,
	"last_used_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth_audit_events" (
	"id" uuid PRIMARY KEY NOT NULL,
	"occurred_at" timestamp with time zone DEFAULT now() NOT NULL,
	"org_id" uuid,
	"actor_user_id" uuid,
	"actor_type" text DEFAULT 'user' NOT NULL,
	"event" text NOT NULL,
	"target_type" text,
	"target_id" text,
	"session_id" uuid,
	"ip" "inet",
	"user_agent" text,
	"outcome" text DEFAULT 'success' NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth_identities" (
	"id" uuid PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"provider" text NOT NULL,
	"provider_user_id" text NOT NULL,
	"email" "citext",
	"email_verified" boolean DEFAULT false NOT NULL,
	"profile" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_login_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "auth_login_attempts" (
	"id" uuid PRIMARY KEY NOT NULL,
	"email_hash" "bytea",
	"ip" "inet",
	"success" boolean NOT NULL,
	"reason" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth_memberships" (
	"id" uuid PRIMARY KEY NOT NULL,
	"org_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"role_id" uuid NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"invited_by" uuid,
	"joined_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "auth_mfa_factors" (
	"id" uuid PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"type" text NOT NULL,
	"label" text,
	"secret_enc" "bytea",
	"confirmed_at" timestamp with time zone,
	"last_used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth_one_time_tokens" (
	"id" uuid PRIMARY KEY NOT NULL,
	"user_id" uuid,
	"purpose" text NOT NULL,
	"token_hash" "bytea" NOT NULL,
	"payload" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	"requested_ip" "inet",
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth_orgs" (
	"id" uuid PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"slug" "citext" NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"settings" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth_otp_challenges" (
	"id" uuid PRIMARY KEY NOT NULL,
	"user_id" uuid,
	"purpose" text NOT NULL,
	"channel" text NOT NULL,
	"destination_hash" "bytea" NOT NULL,
	"code_hash" "bytea" NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"max_attempts" integer DEFAULT 5 NOT NULL,
	"resend_count" integer DEFAULT 0 NOT NULL,
	"client_binding" "bytea",
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	"last_sent_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth_password_history" (
	"id" uuid PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"password_hash" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth_recovery_codes" (
	"id" uuid PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"code_hash" "bytea" NOT NULL,
	"used_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "auth_refresh_tokens" (
	"id" uuid PRIMARY KEY NOT NULL,
	"session_id" uuid NOT NULL,
	"token_hash" "bytea" NOT NULL,
	"issued_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"replaced_by_id" uuid,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "auth_role_permissions" (
	"role_id" uuid NOT NULL,
	"permission" text NOT NULL,
	CONSTRAINT "auth_role_permissions_role_id_permission_pk" PRIMARY KEY("role_id","permission")
);
--> statement-breakpoint
CREATE TABLE "auth_roles" (
	"id" uuid PRIMARY KEY NOT NULL,
	"org_id" uuid,
	"key" text NOT NULL,
	"name" text NOT NULL,
	"is_system" boolean DEFAULT false NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth_sessions" (
	"id" uuid PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"org_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"idle_expires_at" timestamp with time zone NOT NULL,
	"absolute_expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"revoked_reason" text,
	"amr" text[] DEFAULT '{}'::text[] NOT NULL,
	"mfa_satisfied_at" timestamp with time zone,
	"ip" "inet",
	"user_agent" text,
	"device_label" text,
	"impersonated_by" uuid
);
--> statement-breakpoint
CREATE TABLE "auth_signing_keys" (
	"kid" text PRIMARY KEY NOT NULL,
	"alg" text NOT NULL,
	"public_jwk" jsonb NOT NULL,
	"private_key_enc" "bytea" NOT NULL,
	"status" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"activated_at" timestamp with time zone,
	"retired_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "auth_trusted_devices" (
	"id" uuid PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"token_hash" "bytea" NOT NULL,
	"label" text,
	"ip" "inet",
	"user_agent" text,
	"mfa_satisfied_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"last_used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth_users" (
	"id" uuid PRIMARY KEY NOT NULL,
	"email" "citext",
	"email_verified_at" timestamp with time zone,
	"phone" text,
	"phone_verified_at" timestamp with time zone,
	"password_hash" text,
	"password_algo" text,
	"password_updated_at" timestamp with time zone,
	"status" text DEFAULT 'pending' NOT NULL,
	"name" text,
	"avatar_url" text,
	"locale" text,
	"timezone" text,
	"profile" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"mfa_required_at" timestamp with time zone,
	"failed_login_count" integer DEFAULT 0 NOT NULL,
	"locked_until" timestamp with time zone,
	"last_login_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "auth_webauthn_credentials" (
	"id" uuid PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"credential_id" "bytea" NOT NULL,
	"public_key" "bytea" NOT NULL,
	"sign_count" bigint DEFAULT 0 NOT NULL,
	"transports" text[],
	"aaguid" uuid,
	"backed_up" boolean,
	"label" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_used_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "auth_api_keys" ADD CONSTRAINT "auth_api_keys_org_id_auth_orgs_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."auth_orgs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_api_keys" ADD CONSTRAINT "auth_api_keys_created_by_auth_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."auth_users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_identities" ADD CONSTRAINT "auth_identities_user_id_auth_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."auth_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_memberships" ADD CONSTRAINT "auth_memberships_org_id_auth_orgs_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."auth_orgs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_memberships" ADD CONSTRAINT "auth_memberships_user_id_auth_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."auth_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_memberships" ADD CONSTRAINT "auth_memberships_role_id_auth_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."auth_roles"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_memberships" ADD CONSTRAINT "auth_memberships_invited_by_auth_users_id_fk" FOREIGN KEY ("invited_by") REFERENCES "public"."auth_users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_mfa_factors" ADD CONSTRAINT "auth_mfa_factors_user_id_auth_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."auth_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_one_time_tokens" ADD CONSTRAINT "auth_one_time_tokens_user_id_auth_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."auth_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_otp_challenges" ADD CONSTRAINT "auth_otp_challenges_user_id_auth_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."auth_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_password_history" ADD CONSTRAINT "auth_password_history_user_id_auth_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."auth_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_recovery_codes" ADD CONSTRAINT "auth_recovery_codes_user_id_auth_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."auth_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_refresh_tokens" ADD CONSTRAINT "auth_refresh_tokens_session_id_auth_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_refresh_tokens" ADD CONSTRAINT "auth_refresh_tokens_replaced_by_id_auth_refresh_tokens_id_fk" FOREIGN KEY ("replaced_by_id") REFERENCES "public"."auth_refresh_tokens"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_role_permissions" ADD CONSTRAINT "auth_role_permissions_role_id_auth_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."auth_roles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_roles" ADD CONSTRAINT "auth_roles_org_id_auth_orgs_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."auth_orgs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_sessions" ADD CONSTRAINT "auth_sessions_user_id_auth_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."auth_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_sessions" ADD CONSTRAINT "auth_sessions_org_id_auth_orgs_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."auth_orgs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_sessions" ADD CONSTRAINT "auth_sessions_impersonated_by_auth_users_id_fk" FOREIGN KEY ("impersonated_by") REFERENCES "public"."auth_users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_trusted_devices" ADD CONSTRAINT "auth_trusted_devices_user_id_auth_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."auth_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_webauthn_credentials" ADD CONSTRAINT "auth_webauthn_credentials_user_id_auth_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."auth_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "uq_api_keys_prefix" ON "auth_api_keys" USING btree ("prefix");--> statement-breakpoint
CREATE INDEX "idx_api_keys_org" ON "auth_api_keys" USING btree ("org_id") WHERE revoked_at IS NULL;--> statement-breakpoint
CREATE INDEX "idx_audit_org_time" ON "auth_audit_events" USING btree ("org_id","occurred_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "idx_audit_actor_time" ON "auth_audit_events" USING btree ("actor_user_id","occurred_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "idx_audit_event_time" ON "auth_audit_events" USING btree ("event","occurred_at" DESC NULLS LAST);--> statement-breakpoint
CREATE UNIQUE INDEX "uq_identities_provider_subject" ON "auth_identities" USING btree ("provider","provider_user_id");--> statement-breakpoint
CREATE INDEX "idx_identities_user" ON "auth_identities" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_login_attempts_email_time" ON "auth_login_attempts" USING btree ("email_hash","created_at");--> statement-breakpoint
CREATE INDEX "idx_login_attempts_ip_time" ON "auth_login_attempts" USING btree ("ip","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_memberships_org_user" ON "auth_memberships" USING btree ("org_id","user_id");--> statement-breakpoint
CREATE INDEX "idx_memberships_user" ON "auth_memberships" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_mfa_factors_user" ON "auth_mfa_factors" USING btree ("user_id") WHERE confirmed_at IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "uq_ott_hash" ON "auth_one_time_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "idx_ott_user_purpose" ON "auth_one_time_tokens" USING btree ("user_id","purpose") WHERE consumed_at IS NULL;--> statement-breakpoint
CREATE INDEX "idx_ott_expiry" ON "auth_one_time_tokens" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_orgs_slug" ON "auth_orgs" USING btree ("slug");--> statement-breakpoint
CREATE INDEX "idx_otp_destination_purpose" ON "auth_otp_challenges" USING btree ("destination_hash","purpose") WHERE consumed_at IS NULL;--> statement-breakpoint
CREATE INDEX "idx_otp_expiry" ON "auth_otp_challenges" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "idx_password_history_user" ON "auth_password_history" USING btree ("user_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_recovery_codes_user" ON "auth_recovery_codes" USING btree ("user_id") WHERE used_at IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "uq_refresh_token_hash" ON "auth_refresh_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "idx_refresh_session" ON "auth_refresh_tokens" USING btree ("session_id");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_refresh_active_per_session" ON "auth_refresh_tokens" USING btree ("session_id") WHERE used_at IS NULL AND revoked_at IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "uq_roles_org_key" ON "auth_roles" USING btree ("org_id","key");--> statement-breakpoint
CREATE INDEX "idx_sessions_user_live" ON "auth_sessions" USING btree ("user_id") WHERE revoked_at IS NULL;--> statement-breakpoint
CREATE INDEX "idx_sessions_expiry" ON "auth_sessions" USING btree ("absolute_expires_at") WHERE revoked_at IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "uq_trusted_device_hash" ON "auth_trusted_devices" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "idx_trusted_devices_user" ON "auth_trusted_devices" USING btree ("user_id") WHERE revoked_at IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "uq_users_email" ON "auth_users" USING btree ("email");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_users_phone" ON "auth_users" USING btree ("phone");--> statement-breakpoint
CREATE INDEX "idx_users_status_live" ON "auth_users" USING btree ("status") WHERE deleted_at IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "uq_webauthn_credential_id" ON "auth_webauthn_credentials" USING btree ("credential_id");--> statement-breakpoint
CREATE INDEX "idx_webauthn_user" ON "auth_webauthn_credentials" USING btree ("user_id");