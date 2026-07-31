/**
 * Have I Been Pwned range check (AUTH-MODULE-PLAN.md §5.1 step 2, §8.1).
 *
 * ⚑ k-anonymity: we send the **first five hex characters** of the SHA-1 and
 * nothing else. HIBP returns every suffix sharing that prefix — several hundred
 * of them — and the comparison happens here. The password never leaves the
 * process, and neither does enough of its hash to identify it.
 *
 * SHA-1 is not a mistake here. It is not being used as a password hash; it is the
 * index HIBP publishes, and the security of this check does not rest on it.
 */

import { createHash } from 'node:crypto';
import type { BreachChecker } from '@auth/core';

export interface HibpOptions {
  /** Overridable so a test can point at a local stub. */
  endpoint?: string;
  /**
   * ⚑ Short on purpose. This sits in the signup and password-change path, and a
   * third-party outage must degrade to "control unavailable" rather than to a
   * signup form that hangs. The use-case fails open and logs.
   */
  timeoutMs?: number;
  userAgent?: string;
}

export function createHibpBreachChecker(options: HibpOptions = {}): BreachChecker {
  const endpoint = options.endpoint ?? 'https://api.pwnedpasswords.com/range';
  const timeoutMs = options.timeoutMs ?? 1_500;
  const userAgent = options.userAgent ?? 'auth-module';

  return {
    async isBreached(plain: string): Promise<boolean> {
      const digest = createHash('sha1').update(plain, 'utf8').digest('hex').toUpperCase();
      const prefix = digest.slice(0, 5);
      const suffix = digest.slice(5);

      const response = await fetch(`${endpoint}/${prefix}`, {
        headers: {
          'user-agent': userAgent,
          // Pads every response to a uniform size, so an observer cannot infer
          // the prefix from the response length.
          'add-padding': 'true',
        },
        signal: AbortSignal.timeout(timeoutMs),
      });

      // ⚑ Throw rather than return false. "We could not check" and "we checked and
      // it is clean" are different facts, and only the caller can decide whether
      // to proceed — it does, loudly (see `assertPasswordAcceptable`).
      if (!response.ok) {
        throw new Error(`HIBP returned ${response.status}`);
      }

      const body = await response.text();
      for (const line of body.split('\n')) {
        const [candidate, count] = line.trim().split(':');
        // A padded response carries real suffixes with a count of 0; treating a
        // padding row as a hit would reject arbitrary passwords.
        if (candidate === suffix) return Number(count ?? 0) > 0;
      }
      return false;
    },
  };
}
