/**
 * Password hashing (AUTH-MODULE-PLAN.md §8.1).
 *
 * Deliberately low cost parameters here: these tests verify *behaviour*, and real
 * parameters would make the suite take minutes. The production cost is asserted
 * separately by measuring it (README "Performance"), because a cost figure only
 * means something on the hardware you actually deploy to.
 */

import { describe, it, expect } from 'vitest';
import { createArgon2Hasher } from './password.js';
import { isAuthError } from '@auth/core';

// ~8 MiB / t=1 keeps each hash at a few milliseconds.
const fast = {
  memoryCost: 8_192,
  timeCost: 1,
  parallelism: 1,
  maxConcurrency: 4,
  queueTimeoutMs: 1_000,
};

describe('hash and verify', () => {
  const hasher = createArgon2Hasher(fast);

  it('produces an argon2id PHC string, not a bare digest', () => {
    return hasher.hash('correct horse battery staple').then(({ hash, algo }) => {
      expect(algo).toBe('argon2id');
      // The variant matters: argon2i is side-channel-hardened but weaker against
      // GPUs, argon2d the reverse. Only the id hybrid is recommended for passwords.
      expect(hash).toMatch(/^\$argon2id\$v=19\$m=8192,t=1,p=1\$/);
    });
  });

  it('salts every hash, so identical passwords do not collide', async () => {
    const [a, b] = await Promise.all([hasher.hash('same-password'), hasher.hash('same-password')]);
    expect(a.hash).not.toBe(b.hash);
    // …and both still verify.
    expect(await hasher.verify('same-password', a.hash)).toBe(true);
    expect(await hasher.verify('same-password', b.hash)).toBe(true);
  });

  it('accepts the right password and rejects everything else', async () => {
    const { hash } = await hasher.hash('right');
    expect(await hasher.verify('right', hash)).toBe(true);
    expect(await hasher.verify('wrong', hash)).toBe(false);
    expect(await hasher.verify('Right', hash)).toBe(false); // case-sensitive
    expect(await hasher.verify('right ', hash)).toBe(false); // no trimming
    expect(await hasher.verify('', hash)).toBe(false);
  });

  it('handles unicode and long passwords without truncating', async () => {
    // bcrypt silently truncates at 72 bytes; argon2 must not.
    const long = `${'a'.repeat(150)}-tail`;
    const { hash } = await hasher.hash(long);
    expect(await hasher.verify(long, hash)).toBe(true);
    expect(await hasher.verify('a'.repeat(150), hash)).toBe(false);

    const emoji = 'pässwörd-🔐-日本語';
    const { hash: h2 } = await hasher.hash(emoji);
    expect(await hasher.verify(emoji, h2)).toBe(true);
  });

  it('reads a malformed stored hash as "wrong password", not as a 500', async () => {
    // A corrupt row must not turn into an internal error that reveals it exists.
    expect(await hasher.verify('anything', 'not-a-hash')).toBe(false);
    expect(await hasher.verify('anything', '')).toBe(false);
    expect(await hasher.verify('anything', '$argon2id$v=19$garbage')).toBe(false);
  });
});

describe('needsRehash (lazy migration, §5.3 step 5 / §17)', () => {
  const hasher = createArgon2Hasher(fast);

  it('is false when the stored parameters match the configured ones', async () => {
    const { hash } = await hasher.hash('pw');
    expect(hasher.needsRehash(hash)).toBe(false);
  });

  it('is true for a legacy bcrypt hash', () => {
    expect(hasher.needsRehash('$2b$12$C6UzMDM.H6dfI/f/IKcEe.uSZ8n6L1eBpvGkQ6Xk7GhZ0.uKGDl3q')).toBe(
      true,
    );
  });

  it('is true when the cost has been raised since the hash was written', async () => {
    const { hash } = await hasher.hash('pw');
    const stronger = createArgon2Hasher({ ...fast, memoryCost: 19_456 });
    // This is what upgrades the whole user base without a mass reset: the next
    // successful login rewrites the hash at the new cost.
    expect(stronger.needsRehash(hash)).toBe(true);
    // And the old hash still verifies in the meantime.
    expect(await stronger.verify('pw', hash)).toBe(true);
  });

  it('is true for an unrecognised format, so unknown legacy hashes get upgraded', () => {
    expect(hasher.needsRehash('5f4dcc3b5aa765d61d8327deb882cf99')).toBe(true); // md5
    expect(hasher.needsRehash('$argon2i$v=19$m=8192,t=1,p=1$abc$def')).toBe(true); // wrong variant
  });
});

describe('verifyDummy (timing parity, §5.3 step 2)', () => {
  const hasher = createArgon2Hasher(fast);

  it('always returns false', async () => {
    expect(await hasher.verifyDummy('anything')).toBe(false);
  });

  // Timing-sensitive by nature, so it takes the *minimum* of several runs rather
  // than the mean: the minimum approximates the uncontended cost and barely moves
  // when the machine is busy, whereas a mean swings wildly when the full suite
  // runs three projects at once. The retry covers the residual case where even
  // the fastest run was descheduled.
  it('costs about as much as a real verification', { retry: 2 }, async () => {
    const { hash } = await hasher.hash('real-password');
    // Warm up so JIT and the lazily-computed dummy hash are settled for both paths.
    await hasher.verify('real-password', hash);
    await hasher.verifyDummy('x');

    const fastestOf = async (runs: number, fn: () => Promise<unknown>): Promise<number> => {
      let fastest = Number.POSITIVE_INFINITY;
      for (let i = 0; i < runs; i += 1) {
        const started = performance.now();
        await fn();
        fastest = Math.min(fastest, performance.now() - started);
      }
      return fastest;
    };

    const real = await fastestOf(7, () => hasher.verify('wrong-password', hash));
    const dummy = await fastestOf(7, () => hasher.verifyDummy('wrong-password'));

    // Not a statistical proof — that lives in the §14.2 security suite. The
    // load-bearing assertion is the lower bound: it catches the regression where
    // verifyDummy is stubbed out and returns instantly, which would reopen the
    // enumeration oracle. The upper bound is a loose sanity check that it is
    // doing comparable work, not an order of magnitude more.
    expect(dummy, 'verifyDummy is too cheap — the unknown-user path would be detectably faster')
      .toBeGreaterThan(real * 0.5);
    expect(dummy).toBeLessThan(real * 4);
  });
});

describe('admission control (§8.1)', () => {
  it('never exceeds the configured concurrency', async () => {
    const hasher = createArgon2Hasher({ ...fast, maxConcurrency: 2, queueTimeoutMs: 5_000 });
    // 10 concurrent hashes with a cap of 2. Without the cap this would be
    // 10 × memoryCost of simultaneous allocation.
    const results = await Promise.all(Array.from({ length: 10 }, () => hasher.hash('pw')));
    expect(results).toHaveLength(10);
    expect(hasher.stats().peakQueueDepth).toBeGreaterThan(0); // queueing did happen
    expect(hasher.stats().shed).toBe(0); // but nothing was dropped
  });

  it('sheds with a retryable 503 instead of exhausting memory', async () => {
    const hasher = createArgon2Hasher({
      ...fast,
      memoryCost: 65_536, // slow enough that the queue cannot drain in 1ms
      maxConcurrency: 1,
      queueTimeoutMs: 1,
    });

    const results = await Promise.allSettled(
      Array.from({ length: 8 }, () => hasher.hash('pw')),
    );
    const rejected = results.filter((r) => r.status === 'rejected');
    expect(rejected.length).toBeGreaterThan(0);

    const error = (rejected[0] as PromiseRejectedResult).reason;
    expect(isAuthError(error)).toBe(true);
    expect(error.code).toBe('SERVICE_UNAVAILABLE');
    // Retry-After is what makes this a load-balancer-retryable failure rather
    // than a lost login.
    expect(error.retryAfter).toBe(1);
    expect(hasher.stats().shed).toBeGreaterThan(0);
  });

  it('reports stats for tuning the cap from real data', () => {
    const hasher = createArgon2Hasher(fast);
    expect(hasher.stats()).toEqual({ queueDepth: 0, peakQueueDepth: 0, shed: 0 });
  });
});
