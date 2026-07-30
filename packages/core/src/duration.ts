/**
 * Durations in config are written the way humans read them ('10m', '90d') and
 * held in memory as milliseconds. One parser, used by every config field, so
 * there is never an ambiguous bare number whose unit you have to guess.
 */

import { z } from 'zod';

const PATTERN = /^(\d+)(ms|s|m|h|d)$/;

const MULTIPLIER: Record<string, number> = {
  ms: 1,
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
};

export function parseDuration(input: string | number): number {
  if (typeof input === 'number') {
    if (!Number.isFinite(input) || input < 0) throw new Error(`Invalid duration: ${input}`);
    return Math.floor(input);
  }
  const match = PATTERN.exec(input.trim());
  if (!match) throw new Error(`Invalid duration: "${input}" (expected e.g. 500ms, 30s, 10m, 24h, 90d)`);
  const [, value, unit] = match;
  return Number(value) * (MULTIPLIER[unit as string] ?? 1);
}

/** Zod schema that accepts '10m' | 600000 and always yields milliseconds. */
export const duration = z
  .union([z.string(), z.number()])
  .transform((v, ctx) => {
    try {
      return parseDuration(v);
    } catch (e) {
      ctx.addIssue({ code: 'custom', message: (e as Error).message });
      return z.NEVER;
    }
  });

export const seconds = (ms: number): number => Math.floor(ms / 1000);
