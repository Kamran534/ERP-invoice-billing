ALTER TABLE "auth_users" ADD COLUMN "username" "citext";--> statement-breakpoint
ALTER TABLE "auth_users" ADD COLUMN "org_scope_id" uuid;--> statement-breakpoint
ALTER TABLE "auth_users" ADD CONSTRAINT "auth_users_org_scope_id_auth_orgs_id_fk" FOREIGN KEY ("org_scope_id") REFERENCES "public"."auth_orgs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "uq_users_org_username" ON "auth_users" USING btree ("org_scope_id","username");--> statement-breakpoint
ALTER TABLE "auth_users" ADD CONSTRAINT "ck_users_username_scoped" CHECK ((username IS NULL) = (org_scope_id IS NULL));--> statement-breakpoint
ALTER TABLE "auth_users" ADD CONSTRAINT "ck_users_has_identity" CHECK (email IS NOT NULL OR username IS NOT NULL);