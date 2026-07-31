/**
 * Authenticated encryption for secrets at rest (AUTH-MODULE-PLAN.md §4.3, §7.2).
 *
 * Used for TOTP secrets and, later, signing keys. These differ from passwords and
 * tokens: we must be able to *read them back*, so hashing is not an option. They
 * are encrypted under a key-encryption key held outside the database, so a dump of
 * the tables alone does not yield a working second factor.
 *
 * AES-256-GCM, fresh 96-bit IV per encryption, 128-bit tag. The purpose string is
 * bound in as additional authenticated data, so a ciphertext written for one use
 * cannot be replayed into another — a TOTP secret cannot be decrypted as if it were
 * a signing key even by someone who can write to the column.
 *
 * Layout, stored as bytea:
 *
 *   [version:1][iv:12][tag:16][ciphertext:n]
 *
 * The version byte exists so a second key can be introduced later without
 * guesswork about what an old row was encrypted with.
 */

import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from 'node:crypto';

const VERSION = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;

export type AeadPurpose = 'totp-secret' | 'signing-key';

export class DecryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DecryptionError';
  }
}

export interface Aead {
  encrypt(plaintext: string, purpose: AeadPurpose): Uint8Array;
  decrypt(payload: Uint8Array, purpose: AeadPurpose): string;
}

/**
 * @param kekBase64 32 bytes of base64. Validated at boot by the env schema, but
 *                  re-checked here because this is the last line of defence
 *                  against a silently truncated key.
 */
export function createAead(kekBase64: string): Aead {
  const key = Buffer.from(kekBase64, 'base64');
  if (key.length !== KEY_BYTES) {
    throw new Error(`AUTH_KEK must decode to ${KEY_BYTES} bytes, got ${key.length}`);
  }

  return {
    encrypt(plaintext: string, purpose: AeadPurpose): Uint8Array {
      const iv = randomBytes(IV_BYTES);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      cipher.setAAD(Buffer.from(purpose, 'utf8'));
      const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
      const tag = cipher.getAuthTag();
      return new Uint8Array(Buffer.concat([Buffer.from([VERSION]), iv, tag, ciphertext]));
    },

    decrypt(payload: Uint8Array, purpose: AeadPurpose): string {
      const buffer = Buffer.from(payload);
      if (buffer.length < 1 + IV_BYTES + TAG_BYTES) {
        throw new DecryptionError('ciphertext is too short to be well-formed');
      }
      // Constant-time on the version byte is pointless, but a clear error is not:
      // an unknown version means the row predates a key rotation we do not support.
      if (buffer[0] !== VERSION) {
        throw new DecryptionError(`unsupported ciphertext version ${buffer[0]}`);
      }

      const iv = buffer.subarray(1, 1 + IV_BYTES);
      const tag = buffer.subarray(1 + IV_BYTES, 1 + IV_BYTES + TAG_BYTES);
      const ciphertext = buffer.subarray(1 + IV_BYTES + TAG_BYTES);

      const decipher = createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAAD(Buffer.from(purpose, 'utf8'));
      decipher.setAuthTag(tag);
      try {
        return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
      } catch {
        // GCM's final() throws on any tampering — wrong key, wrong purpose, flipped
        // bit. Deliberately one message for all of them: distinguishing them would
        // tell an attacker which part of the payload they got right.
        throw new DecryptionError('ciphertext failed authentication');
      }
    },
  };
}

/** Constant-time compare for anything derived from a secret. */
export function secretsEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
