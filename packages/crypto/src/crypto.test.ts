/**
 * Tests for the primitives whose correctness the security model actually rests
 * on. These need no database and no containers — that is the point of keeping
 * `core` and `crypto` free of I/O.
 *
 * Corresponds to the "OTP" and "Refresh & session" groups in AUTH-MODULE-PLAN.md
 * §14.2.
 */

import { describe, it, expect } from 'vitest';
import {
  randomDigits,
  randomSecret,
  randomRecoveryCode,
  uuidv7,
  sha256,
  hashDestination,
  hashOtpCode,
  timingSafeEquals,
  clientBinding,
  coarsenIp,
  nodeRandom,
} from './random.js';
import { Semaphore, QueueTimeoutError } from './semaphore.js';

describe('randomDigits (OTP generation, §5.11.1)', () => {
  it('returns exactly the requested length, digits only', () => {
    for (const length of [4, 6, 8]) {
      const code = randomDigits(length);
      expect(code).toMatch(new RegExp(`^\\d{${length}}$`));
    }
  });

  it('rejects absurd lengths rather than silently truncating', () => {
    expect(() => randomDigits(0)).toThrow();
    expect(() => randomDigits(99)).toThrow();
  });

  /**
   * The reason rejection sampling exists. `randomBytes(1)[0] % 10` biases digits
   * 0–5 upward by ~1.6% each, because 256 is not a multiple of 10. A chi-squared
   * test over a large sample catches a regression to modulo.
   *
   * χ² critical value for 9 degrees of freedom at p=0.001 is 27.88. A uniform
   * generator exceeds that roughly 1 run in 1000; a modulo-biased one exceeds it
   * essentially always at this sample size.
   */
  it('produces a uniform digit distribution', () => {
    const counts = new Array<number>(10).fill(0);
    const samples = 60_000;
    for (let i = 0; i < samples / 6; i += 1) {
      for (const ch of randomDigits(6)) {
        const digit = Number(ch);
        counts[digit] = (counts[digit] ?? 0) + 1;
      }
    }

    const expected = samples / 10;
    const chiSquared = counts.reduce((acc, observed) => acc + (observed - expected) ** 2 / expected, 0);

    expect(chiSquared).toBeLessThan(27.88);
    // No digit should be wildly absent either — a cheap sanity net.
    for (const count of counts) expect(count).toBeGreaterThan(expected * 0.9);
  });

  it('does not repeat codes at a detectable rate', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 5_000; i += 1) seen.add(randomDigits(6));
    // 5k draws from 1e6 → expect ~12 collisions by birthday paradox; allow slack.
    expect(seen.size).toBeGreaterThan(4_950);
  });
});

describe('uuidv7 (time-sortable ids)', () => {
  it('is a valid v7 UUID', () => {
    expect(uuidv7()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it('sorts lexicographically in generation order', () => {
    // This is the whole justification for v7 over v4: index locality on insert.
    const ids = Array.from({ length: 2_000 }, () => uuidv7());
    expect([...ids].sort()).toEqual(ids);
  });

  it('never collides within a single millisecond', () => {
    const ids = new Set(Array.from({ length: 4_000 }, () => uuidv7()));
    expect(ids.size).toBe(4_000);
  });
});

describe('secret generation', () => {
  it('produces 256-bit url-safe refresh secrets with a prefix', () => {
    const secret = randomSecret('rt');
    expect(secret.startsWith('rt_')).toBe(true);
    expect(secret.slice(3)).toMatch(/^[A-Za-z0-9_-]{43}$/); // 32 bytes base64url
  });

  it('produces recovery codes without ambiguous characters', () => {
    const code = randomRecoveryCode();
    expect(code).toMatch(/^[A-Z2-9]{5}(-[A-Z2-9]{5}){3}$/);
    // O/0 and I/1 are the classic transcription failures.
    expect(code).not.toMatch(/[OI01]/);
  });
});

describe('hashing and comparison', () => {
  it('salts the OTP code hash per challenge', () => {
    const a = hashOtpCode('123456', 'challenge-a');
    const b = hashOtpCode('123456', 'challenge-b');
    // Same code, different challenge → different hash, so one leaked hash does
    // not reveal the code for any other challenge.
    expect(timingSafeEquals(a, b)).toBe(false);
    expect(timingSafeEquals(a, hashOtpCode('123456', 'challenge-a'))).toBe(true);
  });

  it('compares in constant time and handles length mismatch', () => {
    expect(timingSafeEquals(sha256('x'), sha256('x'))).toBe(true);
    expect(timingSafeEquals(sha256('x'), sha256('y'))).toBe(false);
    // Different lengths must return false, not throw — timingSafeEqual does throw.
    expect(timingSafeEquals(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
  });
});

describe('hashDestination', () => {
  it('normalizes case and whitespace, so one mailbox is one bucket', () => {
    // The destination hash keys both the OTP row and the rate-limit bucket. If
    // "Ada@Example.com " and "ada@example.com" hashed differently, an attacker
    // could reset the throttle just by changing the case.
    const canonical = hashDestination('ada@example.com');
    expect(timingSafeEquals(hashDestination('  Ada@Example.COM  '), canonical)).toBe(true);
    expect(timingSafeEquals(hashDestination('other@example.com'), canonical)).toBe(false);
  });
});

describe('clientBinding (§5.11.2)', () => {
  it('is stable for the same agent and network, and differs otherwise', () => {
    const binding = clientBinding('Mozilla/5.0', '203.0.113.42');
    // Same /24, different final octet — a mobile client that changed address
    // within its network must still be able to redeem its code.
    expect(timingSafeEquals(clientBinding('Mozilla/5.0', '203.0.113.99'), binding)).toBe(true);
    // Different network, or different browser: not the requester.
    expect(timingSafeEquals(clientBinding('Mozilla/5.0', '198.51.100.42'), binding)).toBe(false);
    expect(timingSafeEquals(clientBinding('curl/8.0', '203.0.113.42'), binding)).toBe(false);
  });

  it('handles missing agent or address without throwing', () => {
    expect(() => clientBinding(undefined, undefined)).not.toThrow();
    expect(clientBinding(undefined, undefined)).toHaveLength(32);
  });
});

describe('nodeRandom (the RandomSource port adapter)', () => {
  it('returns the requested number of bytes', () => {
    expect(nodeRandom.bytes(32)).toBeInstanceOf(Uint8Array);
    expect(nodeRandom.bytes(32)).toHaveLength(32);
    expect(nodeRandom.bytes(1)).toHaveLength(1);
  });

  it('does not repeat', () => {
    const a = Buffer.from(nodeRandom.bytes(32)).toString('hex');
    const b = Buffer.from(nodeRandom.bytes(32)).toString('hex');
    expect(a).not.toBe(b);
  });

  it('delegates uuid and digits to the vetted implementations', () => {
    expect(nodeRandom.uuid()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-/);
    expect(nodeRandom.digits(6)).toMatch(/^\d{6}$/);
  });
});

describe('coarsenIp (OTP client binding, §5.11.2)', () => {
  it('truncates IPv4 to /24 so a mobile client changing address still verifies', () => {
    expect(coarsenIp('203.0.113.42')).toBe('203.0.113.0');
    expect(coarsenIp('203.0.113.42')).toBe(coarsenIp('203.0.113.199'));
    expect(coarsenIp('203.0.113.42')).not.toBe(coarsenIp('203.0.114.42'));
  });

  it('truncates IPv6 to /48', () => {
    expect(coarsenIp('2001:db8:1234:5678::1')).toBe('2001:db8:1234::');
  });

  it('treats a missing address as empty rather than throwing', () => {
    expect(coarsenIp(undefined)).toBe('');
  });
});

describe('Semaphore (Argon2 admission control)', () => {
  it('runs up to the permit count concurrently and queues the rest', async () => {
    const gate = new Semaphore(2, 1_000);
    let active = 0;
    let peak = 0;

    const task = () =>
      gate.run(async () => {
        active += 1;
        peak = Math.max(peak, active);
        await new Promise((r) => setTimeout(r, 20));
        active -= 1;
      });

    await Promise.all(Array.from({ length: 6 }, task));

    expect(peak).toBe(2); // never more than the cap — this is the RAM guarantee
    expect(gate.available).toBe(2); // all permits returned
    expect(gate.queueDepth).toBe(0);
  });

  it('sheds instead of queueing forever', async () => {
    const gate = new Semaphore(1, 30);
    // Hold the only permit longer than the queue timeout.
    const held = gate.run(() => new Promise((r) => setTimeout(r, 200)));

    await expect(gate.run(async () => 'never runs')).rejects.toBeInstanceOf(QueueTimeoutError);
    expect(gate.stats.shed).toBe(1);

    await held;
    expect(gate.available).toBe(1);
  });

  it('releases the permit even when the task throws', async () => {
    const gate = new Semaphore(1, 100);
    await expect(gate.run(async () => { throw new Error('boom'); })).rejects.toThrow('boom');
    // A leaked permit here would permanently reduce login capacity.
    expect(gate.available).toBe(1);
  });

  it('refuses a nonsensical permit count', () => {
    expect(() => new Semaphore(0, 100)).toThrow();
  });
});
