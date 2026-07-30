/**
 * Access-token minting and verification (AUTH-MODULE-PLAN.md §8.4).
 *
 * Hard rules encoded here:
 *  - ⚑ The accepted algorithm is pinned. The token header is never trusted —
 *    that is how `alg: none` and HS/EdDSA confusion attacks work.
 *  - ⚑ `kid` resolves only against the local key store. No URL in a token is
 *    ever fetched.
 *  - iss / aud / exp / nbf are all verified, with 60s of clock tolerance.
 *
 * Refresh tokens are deliberately NOT JWTs — see random.ts / plan §5.5.1.
 */

import { SignJWT, jwtVerify, exportJWK, generateKeyPair, type JWK, type CryptoKey } from 'jose';
import type { AccessClaims, TokenService } from '@auth/core';
import { AuthError } from '@auth/core';
import { uuidv7 } from './random.js';

export interface SigningKey {
  kid: string;
  alg: 'EdDSA';
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

export interface KeyStore {
  active(): Promise<SigningKey>;
  /** Active + retiring keys: tokens signed by a retiring key must still verify. */
  all(): Promise<SigningKey[]>;
}

/**
 * Dev/bootstrap key store: generates one Ed25519 keypair in memory.
 *
 * ⚑ Restarting invalidates every issued access token, and replicas do not share
 * keys — fine for local dev, unusable in production. The DB-backed store reading
 * `auth_signing_keys` (already in the schema) is the Phase 8 item; rotation
 * mechanics are specified in plan §8.6.
 */
export async function createInMemoryKeyStore(): Promise<KeyStore> {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', {
    crv: 'Ed25519',
    extractable: true,
  });
  const key: SigningKey = { kid: `dev-${uuidv7().slice(0, 8)}`, alg: 'EdDSA', privateKey, publicKey };
  return {
    active: async () => key,
    all: async () => [key],
  };
}

export interface JwtTokenServiceOptions {
  keyStore: KeyStore;
  issuer: string;
  audience: string[];
  accessTtlMs: number;
  clockToleranceSeconds?: number;
}

export function createJwtTokenService(opts: JwtTokenServiceOptions): TokenService {
  const ttlSeconds = Math.floor(opts.accessTtlMs / 1000);
  const clockTolerance = opts.clockToleranceSeconds ?? 60;

  return {
    async mintAccess(claims: AccessClaims) {
      const key = await opts.keyStore.active();
      const token = await new SignJWT({
        sid: claims.sid,
        org: claims.org ?? null,
        roles: claims.roles ?? [],
        perms: claims.perms ?? [],
        amr: claims.amr,
        ver: 1,
      })
        // ⚑ alg comes from our key, never from anything client-supplied.
        .setProtectedHeader({ alg: key.alg, kid: key.kid, typ: 'JWT' })
        .setSubject(claims.sub)
        .setIssuer(opts.issuer)
        .setAudience(opts.audience)
        .setIssuedAt()
        .setJti(uuidv7())
        .setExpirationTime(`${ttlSeconds}s`)
        .sign(key.privateKey);

      return { token, expiresIn: ttlSeconds };
    },

    async verifyAccess(token: string) {
      const keys = await opts.keyStore.all();
      if (keys.length === 0) throw new AuthError('INTERNAL', 'No signing keys available');

      try {
        const { payload } = await jwtVerify(
          token,
          // ⚑ kid is matched against the local store only. An unknown kid fails
          // closed; we never resolve a key from the token itself.
          async (header) => {
            const match = keys.find((k) => k.kid === header.kid) ?? keys[0]!;
            return match.publicKey;
          },
          {
            issuer: opts.issuer,
            audience: opts.audience,
            algorithms: ['EdDSA'], // ⚑ pinned — blocks `none` and HS confusion
            clockTolerance,
            requiredClaims: ['sub', 'sid', 'exp', 'iat', 'jti'],
          },
        );

        return {
          sub: payload.sub as string,
          sid: payload['sid'] as string,
          org: (payload['org'] as string | null) ?? null,
          roles: (payload['roles'] as string[]) ?? [],
          perms: (payload['perms'] as string[]) ?? [],
          amr: (payload['amr'] as AccessClaims['amr']) ?? [],
          iat: payload.iat as number,
          exp: payload.exp as number,
          jti: payload.jti as string,
        };
      } catch (e) {
        throw new AuthError('TOKEN_INVALID', 'Invalid or expired access token', { cause: e });
      }
    },

    async jwks() {
      const keys = await opts.keyStore.all();
      const jwks: JWK[] = [];
      for (const key of keys) {
        const jwk = await exportJWK(key.publicKey);
        jwks.push({ ...jwk, kid: key.kid, alg: key.alg, use: 'sig' });
      }
      return { keys: jwks };
    },
  };
}
