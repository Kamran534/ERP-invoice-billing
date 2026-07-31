/**
 * The HIBP range check against the real service (§5.1 step 2).
 *
 * An integration test rather than a unit test because the thing worth verifying
 * is the protocol — the padding rows, the count semantics, the response shape —
 * and a stub of HIBP would only assert that our stub matches our reading of the
 * docs. The reading is what could be wrong.
 *
 * ⚑ Needs outbound internet, unlike the other integration tests which need only
 * Docker. A failure here is more likely to be the network than the code; the
 * assertions say which.
 */

import { describe, it, expect } from 'vitest';
import { createHibpBreachChecker } from './breach.js';

const hibp = createHibpBreachChecker({ timeoutMs: 8_000 });

describe('the range check', () => {
  it('recognises a password from the breach corpus', async () => {
    // In the corpus tens of millions of times over. If this ever returns false,
    // either the protocol changed or we are parsing the response wrong.
    expect(await hibp.isBreached('password')).toBe(true);
  });

  it('recognises a long but common passphrase', async () => {
    // ⚑ The case that justifies the check existing: 28 characters, passes every
    // length and composition rule, and is in the corpus because it is the example
    // everyone uses.
    expect(await hibp.isBreached('correct horse battery staple')).toBe(true);
  });

  it('passes a password nobody has ever used', async () => {
    const unique = `unlikely-${Math.random().toString(36)}-${Date.now()}-passphrase`;
    expect(await hibp.isBreached(unique)).toBe(false);
  });

  it('⚑ does not treat a padding row as a hit', async () => {
    // Padded responses include real suffixes with a count of 0. Reading presence
    // rather than count would reject arbitrary unbreached passwords — and would
    // look like the check working, which is the dangerous part.
    const results = await Promise.all(
      Array.from({ length: 5 }, (_, i) =>
        hibp.isBreached(`padding-probe-${i}-${Date.now()}-${Math.random()}`),
      ),
    );
    expect(results).toEqual([false, false, false, false, false]);
  });

  it('throws rather than reporting "clean" when it cannot reach the service', async () => {
    const unreachable = createHibpBreachChecker({
      endpoint: 'http://127.0.0.1:9/range',
      timeoutMs: 300,
    });
    // ⚑ "Could not check" must not be indistinguishable from "checked, and it is
    // fine". The caller fails open deliberately and logs; it must get to make
    // that choice.
    await expect(unreachable.isBreached('password')).rejects.toThrow();
  });
});
