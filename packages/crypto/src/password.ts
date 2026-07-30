/**
 * Argon2id password hasher (AUTH-MODULE-PLAN.md §8.1) with three properties the
 * naive implementation misses:
 *
 *  1. **Non-blocking.** @node-rs/argon2's async API runs the native work on the
 *     libuv threadpool, so the event loop stays free. A JS worker pool (piscina)
 *     would be redundant — but UV_THREADPOOL_SIZE (default 4) then becomes the
 *     real concurrency limit, and it is shared with DNS and fs. Set it >= the
 *     hashing cap or logins queue behind unrelated I/O.
 *
 *  2. **Bounded.** memoryCost × concurrency is real RAM. See ./semaphore.ts.
 *
 *  3. **Constant-ish time on the unknown-user path.** verifyDummy() burns the
 *     same work as a real verify so response timing doesn't leak account
 *     existence (§5.3 step 2).
 */

import { hash as argonHash, verify as argonVerify, type Algorithm } from '@node-rs/argon2';
import { AuthError, type PasswordHasher, type HashResult } from '@auth/core';
import { Semaphore, QueueTimeoutError } from './semaphore.js';

/**
 * @node-rs/argon2 declares `Algorithm` as an ambient `const enum`, which cannot
 * be imported as a value under `verbatimModuleSyntax`. The numeric values are
 * part of the Argon2 spec, not an implementation detail: 0=Argon2d, 1=Argon2i,
 * 2=Argon2id. We want Argon2id — the hybrid that resists both GPU and
 * side-channel attacks, and the only variant OWASP recommends for passwords.
 */
const ARGON2ID = 2 as Algorithm;

export interface Argon2Options {
  memoryCost: number; // KiB
  timeCost: number;
  parallelism: number;
  maxConcurrency: number;
  queueTimeoutMs: number;
}

/** Parsed from a stored hash so we can detect params drifting from config. */
function parseArgonParams(stored: string): { m: number; t: number; p: number } | null {
  // $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
  const match = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$/.exec(stored);
  if (!match) return null;
  return { m: Number(match[1]), t: Number(match[2]), p: Number(match[3]) };
}

export function createArgon2Hasher(opts: Argon2Options): PasswordHasher & {
  stats(): { queueDepth: number; peakQueueDepth: number; shed: number };
  verifyDummy(plain: string): Promise<false>;
} {
  const gate = new Semaphore(opts.maxConcurrency, opts.queueTimeoutMs);

  const params = {
    memoryCost: opts.memoryCost,
    timeCost: opts.timeCost,
    parallelism: opts.parallelism,
    algorithm: ARGON2ID,
  } as const;

  /**
   * A real Argon2id hash of a fixed string, computed once at startup with the
   * configured params. Verifying against it costs the same as verifying a real
   * user, which is the point.
   */
  let dummyHash: string | null = null;
  const dummyReady = argonHash('timing-equalizer-not-a-secret', params).then((h) => {
    dummyHash = h;
    return h;
  });

  const shedToHttp = (e: unknown): never => {
    if (e instanceof QueueTimeoutError) {
      throw new AuthError('SERVICE_UNAVAILABLE', 'Server busy — retry shortly', {
        retryAfter: 1,
        cause: e,
      });
    }
    throw e;
  };

  return {
    async hash(plain: string): Promise<HashResult> {
      try {
        const h = await gate.run(() => argonHash(plain, params));
        return { hash: h, algo: 'argon2id' };
      } catch (e) {
        return shedToHttp(e);
      }
    },

    async verify(plain: string, stored: string): Promise<boolean> {
      try {
        // bcrypt/legacy hashes are handled by a separate verifier during
        // migration (plan §17); argon2 verify rejects them outright.
        return await gate.run(() => argonVerify(stored, plain));
      } catch (e) {
        if (e instanceof QueueTimeoutError) return shedToHttp(e);
        // A malformed stored hash must read as "wrong password", not a 500.
        return false;
      }
    },

    /** ⚑ Call on the no-such-user path so timing matches the real path. */
    async verifyDummy(plain: string): Promise<false> {
      try {
        const h = dummyHash ?? (await dummyReady);
        await gate.run(() => argonVerify(h, plain));
      } catch {
        /* result is irrelevant — we only want the work done */
      }
      return false;
    },

    needsRehash(stored: string): boolean {
      const parsed = parseArgonParams(stored);
      if (!parsed) return true; // bcrypt or unknown legacy → rehash on next login
      return (
        parsed.m !== opts.memoryCost || parsed.t !== opts.timeCost || parsed.p !== opts.parallelism
      );
    },

    stats: () => gate.stats,
  };
}
