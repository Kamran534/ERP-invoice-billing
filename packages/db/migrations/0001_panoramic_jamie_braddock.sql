ALTER TABLE "auth_mfa_factors" ADD COLUMN "last_used_timestep" bigint;--> statement-breakpoint
ALTER TABLE "auth_one_time_tokens" ADD COLUMN "attempts" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "auth_one_time_tokens" ADD COLUMN "max_attempts" integer DEFAULT 5 NOT NULL;