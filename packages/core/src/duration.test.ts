/**
 * Every TTL in the config goes through this parser. A silent unit
 * misinterpretation here would set a 90-day refresh token to 90 milliseconds, or
 * a 10-minute access token to 10 hours — so it must reject anything ambiguous
 * rather than guess.
 */

import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import { parseDuration, duration, seconds } from './duration.js';

describe('parseDuration', () => {
  it('converts each supported unit to milliseconds', () => {
    expect(parseDuration('500ms')).toBe(500);
    expect(parseDuration('30s')).toBe(30_000);
    expect(parseDuration('10m')).toBe(600_000);
    expect(parseDuration('24h')).toBe(86_400_000);
    expect(parseDuration('90d')).toBe(7_776_000_000);
  });

  it('matches the TTLs the plan specifies', () => {
    expect(parseDuration('10m')).toBe(parseDuration(600_000)); // access token
    expect(parseDuration('30d')).toBe(parseDuration('720h')); // refresh idle
    expect(parseDuration('15m')).toBe(parseDuration('900s')); // step-up window
  });

  it('passes numbers through as milliseconds', () => {
    expect(parseDuration(1_234)).toBe(1_234);
    expect(parseDuration(0)).toBe(0);
  });

  it('tolerates surrounding whitespace', () => {
    expect(parseDuration('  10m  ')).toBe(600_000);
  });

  it('rejects a bare numeric string rather than guessing the unit', () => {
    // '600' could be ms, seconds or minutes. Guessing is how a 10-minute token
    // becomes a 600-millisecond one.
    expect(() => parseDuration('600')).toThrow(/Invalid duration/);
  });

  it('rejects unknown units, fractions and negatives', () => {
    expect(() => parseDuration('1w')).toThrow(/Invalid duration/);
    expect(() => parseDuration('1y')).toThrow(/Invalid duration/);
    expect(() => parseDuration('1.5h')).toThrow(/Invalid duration/);
    expect(() => parseDuration('-5m')).toThrow(/Invalid duration/);
    expect(() => parseDuration(-1)).toThrow(/Invalid duration/);
    expect(() => parseDuration('')).toThrow(/Invalid duration/);
    expect(() => parseDuration('10 m')).toThrow(/Invalid duration/);
    expect(() => parseDuration('m10')).toThrow(/Invalid duration/);
  });

  it('rejects non-finite numbers', () => {
    expect(() => parseDuration(Number.NaN)).toThrow();
    expect(() => parseDuration(Number.POSITIVE_INFINITY)).toThrow();
  });

  it('names the accepted format in the error, so the fix is obvious', () => {
    expect(() => parseDuration('1w')).toThrow(/500ms, 30s, 10m, 24h, 90d/);
  });
});

describe('duration zod schema', () => {
  it('accepts both string and numeric input and always yields ms', () => {
    expect(duration.parse('10m')).toBe(600_000);
    expect(duration.parse(600_000)).toBe(600_000);
  });

  it('surfaces a readable issue instead of throwing raw', () => {
    const result = duration.safeParse('nope');
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toMatch(/Invalid duration/);
    }
  });

  it('composes inside an object schema', () => {
    const schema = z.object({ ttl: duration });
    expect(schema.parse({ ttl: '1h' })).toEqual({ ttl: 3_600_000 });
  });
});

describe('seconds', () => {
  it('floors to whole seconds, as JWT exp requires', () => {
    expect(seconds(600_000)).toBe(600);
    expect(seconds(1_999)).toBe(1);
    expect(seconds(999)).toBe(0);
  });
});
