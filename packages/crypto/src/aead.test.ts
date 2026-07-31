/**
 * AEAD for secrets at rest (AUTH-MODULE-PLAN.md §4.3).
 *
 * The properties that matter are not "it round-trips" — they are the ones that
 * hold when something has gone wrong: a leaked table, a tampered row, a reused
 * ciphertext, a rotated key.
 */

import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import { createAead, DecryptionError, secretsEqual } from './aead.js';

const kek = () => randomBytes(32).toString('base64');

describe('round trip', () => {
  it('recovers exactly what was encrypted', () => {
    const aead = createAead(kek());
    for (const secret of ['JBSWY3DPEHPK3PXP', '', 'a'.repeat(4096), 'pässwörd 🔐 日本語']) {
      expect(aead.decrypt(aead.encrypt(secret, 'totp-secret'), 'totp-secret')).toBe(secret);
    }
  });

  it('produces a different ciphertext every time', () => {
    const aead = createAead(kek());
    // A deterministic ciphertext would leak that two users share a secret.
    const a = aead.encrypt('JBSWY3DPEHPK3PXP', 'totp-secret');
    const b = aead.encrypt('JBSWY3DPEHPK3PXP', 'totp-secret');
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    expect(aead.decrypt(a, 'totp-secret')).toBe(aead.decrypt(b, 'totp-secret'));
  });

  it('never stores the plaintext in the payload', () => {
    const aead = createAead(kek());
    const payload = Buffer.from(aead.encrypt('JBSWY3DPEHPK3PXP', 'totp-secret'));
    expect(payload.toString('utf8')).not.toContain('JBSWY3DPEHPK3PXP');
    expect(payload.toString('hex')).not.toContain(Buffer.from('JBSWY3DPEHPK3PXP').toString('hex'));
  });

  it('stamps a version byte so a future key rotation can be staged', () => {
    const aead = createAead(kek());
    expect(Buffer.from(aead.encrypt('x', 'totp-secret')).at(0)).toBe(1);
  });
});

describe('rejects anything not exactly right', () => {
  it('rejects the wrong key', () => {
    const payload = createAead(kek()).encrypt('secret', 'totp-secret');
    // The whole point: a database dump without the KEK is inert.
    expect(() => createAead(kek()).decrypt(payload, 'totp-secret')).toThrow(DecryptionError);
  });

  it('rejects a ciphertext decrypted under a different purpose', () => {
    const aead = createAead(kek());
    const payload = aead.encrypt('secret', 'totp-secret');
    // ⚑ Purpose is bound in as AAD, so a row cannot be moved between columns and
    // read as something it was never meant to be.
    expect(() => aead.decrypt(payload, 'signing-key')).toThrow(DecryptionError);
  });

  it('rejects a tampered ciphertext, tag or IV', () => {
    const aead = createAead(kek());
    const original = Buffer.from(aead.encrypt('secret-value', 'totp-secret'));

    for (const index of [1, 13, 20, original.length - 1]) {
      const tampered = Buffer.from(original);
      tampered[index] = (tampered.at(index) ?? 0) ^ 0x01;
      expect(() => aead.decrypt(tampered, 'totp-secret'), `byte ${index}`).toThrow(DecryptionError);
    }
  });

  it('rejects a truncated payload without throwing something untyped', () => {
    const aead = createAead(kek());
    for (const payload of [new Uint8Array(0), new Uint8Array(5), new Uint8Array(28)]) {
      expect(() => aead.decrypt(payload, 'totp-secret')).toThrow(DecryptionError);
    }
  });

  it('rejects an unknown version byte with a message that says why', () => {
    const aead = createAead(kek());
    const payload = Buffer.from(aead.encrypt('secret', 'totp-secret'));
    payload[0] = 9;
    expect(() => aead.decrypt(payload, 'totp-secret')).toThrow(/unsupported ciphertext version 9/);
  });

  it('gives one message for every failure mode', () => {
    // Distinguishing "wrong key" from "tampered" tells an attacker which half they
    // got right.
    const aead = createAead(kek());
    const payload = Buffer.from(aead.encrypt('secret', 'totp-secret'));
    const tampered = Buffer.from(payload);
    tampered[tampered.length - 1] = (tampered.at(-1) ?? 0) ^ 0x01;

    const wrongKey = (() => {
      try {
        createAead(kek()).decrypt(payload, 'totp-secret');
      } catch (e) {
        return (e as Error).message;
      }
    })();
    const wrongBytes = (() => {
      try {
        aead.decrypt(tampered, 'totp-secret');
      } catch (e) {
        return (e as Error).message;
      }
    })();

    expect(wrongKey).toBe(wrongBytes);
  });
});

describe('key validation', () => {
  it('refuses a key that is not 32 bytes', () => {
    // A truncated KEK would otherwise silently weaken every secret in the table.
    expect(() => createAead(randomBytes(16).toString('base64'))).toThrow(/32 bytes/);
    expect(() => createAead(randomBytes(31).toString('base64'))).toThrow(/32 bytes/);
    expect(() => createAead('')).toThrow(/32 bytes/);
  });

  it('accepts exactly 32 bytes', () => {
    expect(() => createAead(randomBytes(32).toString('base64'))).not.toThrow();
  });
});

describe('secretsEqual', () => {
  it('compares content, and handles length mismatch without throwing', () => {
    expect(secretsEqual(Buffer.from('abc'), Buffer.from('abc'))).toBe(true);
    expect(secretsEqual(Buffer.from('abc'), Buffer.from('abd'))).toBe(false);
    // node's timingSafeEqual throws on unequal lengths; ours must not.
    expect(secretsEqual(Buffer.from('abc'), Buffer.from('abcd'))).toBe(false);
  });
});
