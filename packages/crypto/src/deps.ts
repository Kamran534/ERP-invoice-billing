/**
 * The real implementation of `CryptoDeps` — the handful of pure primitives the
 * use-cases need that are not ports.
 *
 * This adapter exists only to shape the signatures: core speaks `string | null`
 * (what an HTTP header actually gives you) while the primitives below were written
 * against `string | undefined`. Doing the conversion once here beats doing it at
 * every call site, and beats loosening the primitives.
 */

import type { CryptoDeps } from '@auth/core';
import { clientBinding, randomSecret, sha256 } from './random.js';

export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

export const nodeCryptoDeps: CryptoDeps = {
  sha256: (input: string) => sha256(input),
  newSecret: (prefix?: string) => randomSecret(prefix),
  clientBinding: (request) => clientBinding(request.userAgent ?? undefined, request.ip ?? undefined),
  hex: toHex,
};
