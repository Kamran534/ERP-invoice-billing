/**
 * The few primitives use-cases need that are not ports.
 *
 * Kept separate from `AuthContext` because these are pure functions with no
 * lifecycle — the app passes the real ones from `@auth/crypto`, a test passes
 * deterministic ones, and neither needs constructing.
 */

export interface CryptoDeps {
  /** Hash for storage and lookup. Never for passwords — that is the hasher port. */
  sha256(input: string): Uint8Array;
  /** 256 bits of url-safe randomness for refresh tokens and one-time links. */
  newSecret(prefix?: string): string;
  /**
   * `sha256(userAgent ‖ ip/24)` — the client fingerprint an OTP or MFA challenge is
   * bound to (§5.4.2, §5.11.2).
   *
   * ⚑ A /24 rather than the exact address: mobile clients change IP mid-flow often
   * enough that exact matching would reject real users, and the point is to defeat
   * "read me the code you just received", not to pin a route.
   */
  clientBinding(request: { userAgent: string | null; ip: string | null }): Uint8Array;
  /** Lowercase hex — for putting a digest in a JSON payload. */
  hex(bytes: Uint8Array): string;
}
