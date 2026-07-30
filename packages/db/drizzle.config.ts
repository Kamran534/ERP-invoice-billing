import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  dialect: 'postgresql',
  schema: './src/schema.ts',
  out: './migrations',
  // Drizzle emits snake_case column names from camelCase fields, matching the
  // explicit names in schema.ts.
  casing: 'snake_case',
  dbCredentials: {
    url: process.env['DATABASE_URL'] ?? 'postgres://app:app_dev_password@localhost:5432/billing',
  },
  // Keep generated SQL reviewable — this is a security-relevant schema, so the
  // diff gets read by a human before it is applied.
  verbose: true,
  strict: true,
});
