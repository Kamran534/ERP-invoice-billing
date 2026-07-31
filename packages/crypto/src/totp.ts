/**
 * TOTP (RFC 6238) — the authenticator-app second factor (AUTH-MODULE-PLAN.md §5.4).
 *
 * Backed by `otpauth` rather than hand-rolled. TOTP itself is a short algorithm,
 * but base32 handling and dynamic truncation are where implementations quietly go
 * wrong, and a second factor that accepts the wrong code is worse than no second
 * factor. The tests check our wiring against the RFC 6238 published vectors, so we
 * are not simply trusting the library either.
 *
 * ⚑ Drift tolerance is a replay window. Accepting ±1 step means a code stays valid
 * for ~90 seconds, so `verify` reports **which** timestep matched and the caller
 * records it — see the consumed-timestep check in the MFA use-case. Without that,
 * a shoulder-surfed code can be reused for the rest of its window.
 */

import { TOTP, Secret } from 'otpauth';

export interface TotpOptions {
  digits: 6 | 8;
  /** Seconds per step. 30 is universal; changing it breaks most authenticators. */
  period: number;
  /** Steps of drift accepted either side. 1 = ±30s. */
  window: number;
}

export interface TotpSecret {
  /** Base32, what the user types if they cannot scan the QR code. */
  base32: string;
}

export interface TotpVerification {
  valid: boolean;
  /**
   * The absolute timestep the code matched, or null. Must be recorded so the same
   * code cannot be replayed inside its own drift window.
   */
  timestep: number | null;
}

export interface TotpService {
  generateSecret(): TotpSecret;
  provisioningUri(secret: TotpSecret, account: string, issuer: string): string;
  verify(secret: TotpSecret, code: string, at?: Date): TotpVerification;
  /** Exposed for tests and for showing the user what their app should display. */
  generate(secret: TotpSecret, at?: Date): string;
  timestepAt(at?: Date): number;
}

export function createTotpService(options: TotpOptions): TotpService {
  const build = (secret: TotpSecret, account = 'account', issuer = 'issuer'): TOTP =>
    new TOTP({
      issuer,
      label: account,
      algorithm: 'SHA1', // what every authenticator app assumes
      digits: options.digits,
      period: options.period,
      secret: Secret.fromBase32(secret.base32),
    });

  const timestepAt = (at?: Date): number =>
    Math.floor((at ? at.getTime() : Date.now()) / 1000 / options.period);

  return {
    generateSecret(): TotpSecret {
      // 160 bits, the RFC 4226 recommendation and what authenticator apps expect.
      return { base32: new Secret({ size: 20 }).base32 };
    },

    provisioningUri(secret, account, issuer) {
      return build(secret, account, issuer).toString();
    },

    generate(secret, at) {
      return build(secret).generate({ timestamp: at ? at.getTime() : Date.now() });
    },

    verify(secret, code, at) {
      // A malformed code should be a plain rejection, never an exception that the
      // route layer has to translate.
      if (!/^\d+$/.test(code) || code.length !== options.digits) {
        return { valid: false, timestep: null };
      }

      const timestamp = at ? at.getTime() : Date.now();
      // `delta` is the offset in steps from the current one: 0 = now, -1 = previous.
      const delta = build(secret).validate({ token: code, window: options.window, timestamp });
      if (delta === null) return { valid: false, timestep: null };

      return { valid: true, timestep: timestepAt(at) + delta };
    },

    timestepAt,
  };
}
