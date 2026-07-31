ALTER TABLE "auth_orgs" ADD COLUMN "legal_name" text;--> statement-breakpoint
ALTER TABLE "auth_orgs" ADD COLUMN "tax_id" text;--> statement-breakpoint
ALTER TABLE "auth_orgs" ADD COLUMN "email" "citext";--> statement-breakpoint
ALTER TABLE "auth_orgs" ADD COLUMN "phone" text;--> statement-breakpoint
ALTER TABLE "auth_orgs" ADD COLUMN "website" text;--> statement-breakpoint
ALTER TABLE "auth_orgs" ADD COLUMN "logo_url" text;--> statement-breakpoint
ALTER TABLE "auth_orgs" ADD COLUMN "address" jsonb;--> statement-breakpoint
ALTER TABLE "auth_orgs" ADD COLUMN "timezone" text;--> statement-breakpoint
ALTER TABLE "auth_orgs" ADD COLUMN "locale" text;--> statement-breakpoint
ALTER TABLE "auth_orgs" ADD COLUMN "currency" text;--> statement-breakpoint
ALTER TABLE "auth_orgs" ADD COLUMN "profile" jsonb DEFAULT '{}'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "auth_orgs" ADD COLUMN "updated_at" timestamp with time zone DEFAULT now() NOT NULL;