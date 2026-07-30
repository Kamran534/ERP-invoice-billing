/**
 * Postgres column types Drizzle doesn't ship built-in.
 */

import { customType } from 'drizzle-orm/pg-core';

/**
 * bytea — every hashed secret in the schema (token hashes, code hashes,
 * destination hashes). Stored as bytes, surfaced as Uint8Array so the
 * application never accidentally string-compares a secret.
 */
export const bytea = customType<{ data: Uint8Array; driverData: Buffer }>({
  dataType() {
    return 'bytea';
  },
  toDriver(value: Uint8Array): Buffer {
    return Buffer.from(value);
  },
  fromDriver(value: Buffer): Uint8Array {
    return new Uint8Array(value);
  },
});

/**
 * citext — case-insensitive text. UNIQUE(email) on citext means one account per
 * address regardless of typed case, with no LOWER() wrapper on every lookup
 * (which would also defeat the index).
 */
export const citext = customType<{ data: string; driverData: string }>({
  dataType() {
    return 'citext';
  },
});
