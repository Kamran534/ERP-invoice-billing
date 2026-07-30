/**
 * Random + hashing primitives (AUTH-MODULE-PLAN.md §5.11.1, §8.7).
 *
 * Everything security-relevant here uses the CSPRNG. The two easy-to-get-wrong
 * pieces are called out inline: OTP digit generation (modulo bias) and any
 * equality check on a secret (timing).
 */

import { randomBytes, randomUUID, createHash, timingSafeEqual } from 'node:crypto';
import type { RandomSource } from '@auth/core';

// ── UUIDv7 ──────────────────────────────────────────────────────────────────
// Time-ordered ids: inserts land at the right edge of the B-tree instead of
// scattering across it, which keeps index writes and range scans cheap as tables
// grow. Postgres 18 has uuidv7() natively; we generate app-side so the code
// works on 17 too.

let lastMs = 0;
let seq = 0;

export function uuidv7(): string {
  const now = Date.now();
  if (now === lastMs) {
    seq = (seq + 1) & 0xfff; // 12-bit monotonic counter within the same ms
  } else {
    lastMs = now;
    seq = 0;
  }

  const bytes = randomBytes(16);

  // 48-bit big-endian timestamp
  bytes[0] = (now / 2 ** 40) & 0xff;
  bytes[1] = (now / 2 ** 32) & 0xff;
  bytes[2] = (now / 2 ** 24) & 0xff;
  bytes[3] = (now / 2 ** 16) & 0xff;
  bytes[4] = (now / 2 ** 8) & 0xff;
  bytes[5] = now & 0xff;

  // version 7 + 12-bit sequence
  bytes[6] = 0x70 | ((seq >> 8) & 0x0f);
  bytes[7] = seq & 0xff;

  // RFC 4122 variant
  bytes[8] = 0x80 | (bytes[8]! & 0x3f);

  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// ── OTP codes ───────────────────────────────────────────────────────────────

/**
 * Numeric OTP via **rejection sampling**.
 *
 * ⚑ `randomBytes(1)[0] % 10` is biased: 256 is not a multiple of 10, so digits
 * 0–5 come up ~1.6% more often than 6–9. Over 6 digits that measurably shrinks
 * the search space. We discard bytes in the biased tail instead.
 */
export function randomDigits(length: number): string {
  if (length < 1 || length > 12) throw new Error(`Unsupported OTP length: ${length}`);
  const out: number[] = [];
  const limit = 250; // largest multiple of 10 <= 255; reject 250..255
  while (out.length < length) {
    const chunk = randomBytes(Math.max(16, length * 2));
    for (const byte of chunk) {
      if (byte >= limit) continue; // biased tail — discard
      out.push(byte % 10);
      if (out.length === length) break;
    }
  }
  return out.join('');
}

// ── Opaque secrets ──────────────────────────────────────────────────────────

/** 256-bit opaque secret for refresh tokens, one-time tokens, device cookies. */
export function randomSecret(prefix?: string): string {
  const secret = randomBytes(32).toString('base64url');
  return prefix ? `${prefix}_${secret}` : secret;
}

/** Recovery codes: readable, 128-bit, no ambiguous characters. */
const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no I, O, 0, 1
export function randomRecoveryCode(): string {
  const chars: string[] = [];
  const limit = 256 - (256 % RECOVERY_ALPHABET.length);
  while (chars.length < 20) {
    for (const byte of randomBytes(32)) {
      if (byte >= limit) continue;
      chars.push(RECOVERY_ALPHABET[byte % RECOVERY_ALPHABET.length]!);
      if (chars.length === 20) break;
    }
  }
  return `${chars.slice(0, 5).join('')}-${chars.slice(5, 10).join('')}-${chars.slice(10, 15).join('')}-${chars.slice(15, 20).join('')}`;
}

// ── Hashing (for lookups, not for passwords) ────────────────────────────────

/**
 * Tokens are stored as sha256, never plaintext — a DB leak must not yield usable
 * credentials. sha256 (not argon2) is correct here: the input is already 256 bits
 * of entropy, so there is nothing to brute-force and we need the lookup to be
 * fast and deterministic for the index.
 */
export function sha256(input: string | Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(input).digest());
}

/** Destination hashing so Redis keys and OTP rows hold no raw email/phone. */
export function hashDestination(destination: string): Uint8Array {
  return sha256(destination.trim().toLowerCase());
}

/** OTP code hash is salted by the challenge id, so identical codes differ per challenge. */
export function hashOtpCode(code: string, challengeId: string): Uint8Array {
  return sha256(`${code}:${challengeId}`);
}

/** Binds an OTP challenge to its requester: UA + /24 (IPv4) or /48 (IPv6). */
export function clientBinding(userAgent: string | undefined, ip: string | undefined): Uint8Array {
  return sha256(`${userAgent ?? ''}|${coarsenIp(ip)}`);
}

export function coarsenIp(ip: string | undefined): string {
  if (!ip) return '';
  if (ip.includes(':')) {
    // IPv6 → /48
    return ip.split(':').slice(0, 3).join(':') + '::';
  }
  const parts = ip.split('.');
  return parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0` : ip;
}

/** ⚑ Every secret comparison goes through here. Never use `===`. */
export function timingSafeEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export const nodeRandom: RandomSource = {
  bytes: (n: number) => new Uint8Array(randomBytes(n)),
  uuid: uuidv7,
  digits: randomDigits,
};

export { randomUUID };
