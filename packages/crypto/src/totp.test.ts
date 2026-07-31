/**
 * TOTP (AUTH-MODULE-PLAN.md §5.4.3).
 *
 * The first block checks our wiring against the **published RFC 6238 test
 * vectors**, so a library swap or a misconfigured digit count is caught by the
 * specification rather than by a value we recorded from our own output.
 */

import { describe, it, expect } from 'vitest';
import { createTotpService } from './totp.js';

const service = createTotpService({ digits: 6, period: 30, window: 1 });

// RFC 6238 Appendix B uses the ASCII seed "12345678901234567890" for SHA-1.
// Base32 of that seed:
const RFC_SECRET = { base32: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' };

describe('RFC 6238 test vectors', () => {
  // The published vectors are 8-digit; ours are the last 6 of each, which is how
  // truncation works — a 6-digit code is the low-order 6 digits.
  const vectors: Array<[number, string]> = [
    [59, '287082'],
    [1_111_111_109, '081804'],
    [1_111_111_111, '050471'],
    [1_234_567_890, '005924'],
    [2_000_000_000, '279037'],
  ];

  it.each(vectors)('at t=%i produces %s', (seconds, expected) => {
    expect(service.generate(RFC_SECRET, new Date(seconds * 1000))).toBe(expected);
  });

  it('accepts its own generated code', () => {
    const at = new Date(1_111_111_109 * 1000);
    expect(service.verify(RFC_SECRET, '081804', at).valid).toBe(true);
  });
});

describe('secrets', () => {
  it('generates 160-bit base32 secrets', () => {
    const { base32 } = service.generateSecret();
    // 20 bytes → 32 base32 characters, no padding.
    expect(base32).toMatch(/^[A-Z2-7]{32}$/);
  });

  it('does not repeat', () => {
    const seen = new Set(Array.from({ length: 200 }, () => service.generateSecret().base32));
    expect(seen.size).toBe(200);
  });

  it('builds a provisioning URI an authenticator can scan', () => {
    const secret = service.generateSecret();
    const uri = service.provisioningUri(secret, 'ada@example.com', 'Acme Billing');
    expect(uri.startsWith('otpauth://totp/')).toBe(true);
    expect(uri).toContain(`secret=${secret.base32}`);
    expect(uri).toContain('issuer=Acme%20Billing');
    expect(uri).toContain('digits=6');
    expect(uri).toContain('period=30');
    // SHA1 is what every mainstream authenticator assumes; anything else silently
    // produces codes that never match.
    expect(uri).toContain('algorithm=SHA1');
  });
});

describe('verification', () => {
  const secret = { base32: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' };
  const now = new Date(1_700_000_000 * 1000);

  it('accepts the current code', () => {
    const code = service.generate(secret, now);
    expect(service.verify(secret, code, now)).toEqual({
      valid: true,
      timestep: service.timestepAt(now),
    });
  });

  it('accepts one step of drift either side, and reports which step matched', () => {
    // A phone clock is rarely exact; ±1 step is the standard tolerance.
    const previous = new Date(now.getTime() - 30_000);
    const next = new Date(now.getTime() + 30_000);

    const fromPast = service.verify(secret, service.generate(secret, previous), now);
    expect(fromPast.valid).toBe(true);
    expect(fromPast.timestep).toBe(service.timestepAt(previous));

    const fromFuture = service.verify(secret, service.generate(secret, next), now);
    expect(fromFuture.valid).toBe(true);
    expect(fromFuture.timestep).toBe(service.timestepAt(next));
  });

  it('rejects two steps of drift', () => {
    const tooOld = new Date(now.getTime() - 90_000);
    expect(service.verify(secret, service.generate(secret, tooOld), now).valid).toBe(false);
  });

  it('reports the matched timestep so replay can be blocked', () => {
    // ⚑ Without this the ±1 window is a 90-second replay window: the same code
    // works repeatedly until it expires. The caller records (user, factor, step).
    const code = service.generate(secret, now);
    const first = service.verify(secret, code, now);
    const later = service.verify(secret, code, new Date(now.getTime() + 20_000));
    expect(first.valid && later.valid).toBe(true);
    expect(later.timestep).toBe(first.timestep); // same step ⇒ the caller must reject the second
  });

  it('rejects a code from a different secret', () => {
    const other = service.generateSecret();
    expect(service.verify(secret, service.generate(other, now), now).valid).toBe(false);
  });

  it('rejects malformed input as invalid rather than throwing', () => {
    for (const code of ['', '12345', '1234567', 'abcdef', '12 34 56', '   ', '-12345']) {
      expect(() => service.verify(secret, code, now)).not.toThrow();
      expect(service.verify(secret, code, now).valid, code).toBe(false);
    }
  });

  it('returns a null timestep whenever it rejects', () => {
    expect(service.verify(secret, '000000', new Date(0)).timestep).toBeNull();
    expect(service.verify(secret, 'nope', now).timestep).toBeNull();
  });
});

describe('configuration', () => {
  it('honours an 8-digit setting', () => {
    const eight = createTotpService({ digits: 8, period: 30, window: 1 });
    expect(eight.generate(RFC_SECRET, new Date(59 * 1000))).toBe('94287082');
  });

  it('honours a zero window, accepting only the current step', () => {
    const strict = createTotpService({ digits: 6, period: 30, window: 0 });
    const now = new Date(1_700_000_000 * 1000);
    const previous = new Date(now.getTime() - 30_000);
    expect(strict.verify(RFC_SECRET, strict.generate(RFC_SECRET, now), now).valid).toBe(true);
    expect(strict.verify(RFC_SECRET, strict.generate(RFC_SECRET, previous), now).valid).toBe(false);
  });

  it('computes timesteps from the configured period', () => {
    expect(service.timestepAt(new Date(59_000))).toBe(1);
    expect(service.timestepAt(new Date(60_000))).toBe(2);
  });
});
