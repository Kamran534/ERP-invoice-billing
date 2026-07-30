/**
 * Access-token minting and verification (AUTH-MODULE-PLAN.md §8.4).
 *
 * The forgery tests are the important ones. `alg: none`, algorithm confusion and
 * `kid`/`jku` injection are the three attacks that turn a JWT library into an
 * authentication bypass, and every one of them is a *configuration* mistake
 * rather than a cryptographic break — which is exactly why they need a test.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';
import { createInMemoryKeyStore, createJwtTokenService, type KeyStore } from './tokens.js';
import { isAuthError, type TokenService } from '@auth/core';

const ISSUER = 'https://auth.test';
const AUDIENCE = ['api.test'];

const claims = {
  sub: 'user-1',
  sid: 'session-1',
  org: 'org-1',
  roles: ['admin'],
  perms: ['invoice:write'],
  amr: ['pwd', 'otp'] as const,
};

let keyStore: KeyStore;
let tokens: TokenService;

beforeAll(async () => {
  keyStore = await createInMemoryKeyStore();
  tokens = createJwtTokenService({
    keyStore,
    issuer: ISSUER,
    audience: AUDIENCE,
    accessTtlMs: 600_000,
  });
});

describe('mintAccess', () => {
  it('round-trips every claim the authorization layer needs', async () => {
    const { token, expiresIn } = await tokens.mintAccess({ ...claims, amr: [...claims.amr] });
    expect(expiresIn).toBe(600);

    const verified = await tokens.verifyAccess(token);
    expect(verified.sub).toBe('user-1');
    expect(verified.sid).toBe('session-1');
    expect(verified.org).toBe('org-1');
    expect(verified.roles).toEqual(['admin']);
    expect(verified.perms).toEqual(['invoice:write']);
    expect(verified.amr).toEqual(['pwd', 'otp']);
    expect(verified.jti).toBeTruthy();
  });

  it('signs with EdDSA and names the key in the header', async () => {
    const { token } = await tokens.mintAccess({ ...claims, amr: ['pwd'] });
    const header = JSON.parse(Buffer.from(token.split('.')[0]!, 'base64url').toString()) as {
      alg: string;
      kid: string;
      typ: string;
    };
    expect(header.alg).toBe('EdDSA');
    expect(header.typ).toBe('JWT');
    expect(header.kid).toBe((await keyStore.active()).kid);
  });

  it('gives every token a unique jti', async () => {
    const minted = await Promise.all(
      Array.from({ length: 20 }, () => tokens.mintAccess({ ...claims, amr: ['pwd'] })),
    );
    const jtis = await Promise.all(
      minted.map(async ({ token }) => (await tokens.verifyAccess(token)).jti),
    );
    expect(new Set(jtis).size).toBe(20);
  });

  it('carries no secret material in the payload', async () => {
    const { token } = await tokens.mintAccess({ ...claims, amr: ['pwd'] });
    const payload = Buffer.from(token.split('.')[1]!, 'base64url').toString();
    // A JWT payload is base64, not encryption. Anything in here is public.
    expect(payload).not.toMatch(/password|secret|refresh|argon2/i);
  });

  it('tolerates a null org for single-tenant deployments', async () => {
    const { token } = await tokens.mintAccess({ sub: 'u', sid: 's', org: null, amr: ['pwd'] });
    const verified = await tokens.verifyAccess(token);
    expect(verified.org).toBeNull();
    expect(verified.roles).toEqual([]);
    expect(verified.perms).toEqual([]);
  });
});

describe('verifyAccess rejects forgeries', () => {
  it('rejects alg: none', async () => {
    // The classic: strip the signature, set alg to none, and hope the verifier
    // trusts the header.
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({ sub: 'attacker', sid: 's', iss: ISSUER, aud: AUDIENCE, exp: 9_999_999_999, iat: 1, jti: 'x' }),
    ).toString('base64url');
    await expectRejected(`${header}.${payload}.`);
  });

  it('rejects an HMAC-signed token (algorithm confusion)', async () => {
    // If the verifier accepted HS256, the *public* key becomes the HMAC secret
    // and anyone who can read the JWKS can mint tokens.
    const publicJwk = await exportJWK((await keyStore.active()).publicKey);
    const secret = new TextEncoder().encode(JSON.stringify(publicJwk));
    const forged = await new SignJWT({ sid: 's', amr: ['pwd'] })
      .setProtectedHeader({ alg: 'HS256', kid: (await keyStore.active()).kid })
      .setSubject('attacker')
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setIssuedAt()
      .setJti('forged')
      .setExpirationTime('1h')
      .sign(secret);
    await expectRejected(forged);
  });

  it('rejects a token signed by a key we do not know', async () => {
    const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
    const forged = await new SignJWT({ sid: 's', amr: ['pwd'] })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'attacker-key' })
      .setSubject('attacker')
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setIssuedAt()
      .setJti('forged')
      .setExpirationTime('1h')
      .sign(privateKey);
    // An unknown kid must fail closed, never fall back to fetching a key.
    await expectRejected(forged);
  });

  it('rejects a tampered payload', async () => {
    const { token } = await tokens.mintAccess({ ...claims, amr: ['pwd'] });
    const [header, payload, signature] = token.split('.');
    const decoded = JSON.parse(Buffer.from(payload!, 'base64url').toString()) as Record<string, unknown>;
    decoded['perms'] = ['*']; // privilege escalation attempt
    const repacked = Buffer.from(JSON.stringify(decoded)).toString('base64url');
    await expectRejected(`${header}.${repacked}.${signature}`);
  });

  it('rejects the wrong issuer and the wrong audience', async () => {
    const key = await keyStore.active();
    const base = () =>
      new SignJWT({ sid: 's', amr: ['pwd'] })
        .setProtectedHeader({ alg: 'EdDSA', kid: key.kid })
        .setSubject('u')
        .setIssuedAt()
        .setJti('x')
        .setExpirationTime('1h');

    await expectRejected(await base().setIssuer('https://evil.test').setAudience(AUDIENCE).sign(key.privateKey));
    await expectRejected(await base().setIssuer(ISSUER).setAudience(['other-api']).sign(key.privateKey));
  });

  it('rejects an expired token', async () => {
    const key = await keyStore.active();
    const expired = await new SignJWT({ sid: 's', amr: ['pwd'] })
      .setProtectedHeader({ alg: 'EdDSA', kid: key.kid })
      .setSubject('u')
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setIssuedAt(Math.floor(Date.now() / 1000) - 7_200)
      .setJti('x')
      .setExpirationTime(Math.floor(Date.now() / 1000) - 3_600)
      .sign(key.privateKey);
    await expectRejected(expired);
  });

  it('rejects a token missing the claims authorization depends on', async () => {
    const key = await keyStore.active();
    // No `sid` — so the session could never be revoked or looked up.
    const noSid = await new SignJWT({ amr: ['pwd'] })
      .setProtectedHeader({ alg: 'EdDSA', kid: key.kid })
      .setSubject('u')
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setIssuedAt()
      .setJti('x')
      .setExpirationTime('1h')
      .sign(key.privateKey);
    await expectRejected(noSid);
  });

  it('rejects structurally invalid input without throwing something untyped', async () => {
    for (const bad of ['', 'not.a.jwt', 'a.b', 'x'.repeat(500)]) {
      await expectRejected(bad);
    }
  });

  it('allows small clock skew, so a slightly fast client is not logged out', async () => {
    const key = await keyStore.active();
    const skewed = await new SignJWT({ sid: 's', amr: ['pwd'] })
      .setProtectedHeader({ alg: 'EdDSA', kid: key.kid })
      .setSubject('u')
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      // Issued 20s in the future — within the 60s tolerance.
      .setIssuedAt(Math.floor(Date.now() / 1000) + 20)
      .setNotBefore(Math.floor(Date.now() / 1000) + 20)
      .setJti('x')
      .setExpirationTime('1h')
      .sign(key.privateKey);
    await expect(tokens.verifyAccess(skewed)).resolves.toBeTruthy();
  });
});

describe('jwks', () => {
  it('publishes public key material only', async () => {
    const { keys } = await tokens.jwks();
    expect(keys).toHaveLength(1);
    const key = keys[0] as Record<string, unknown>;
    expect(key['kty']).toBe('OKP');
    expect(key['crv']).toBe('Ed25519');
    expect(key['alg']).toBe('EdDSA');
    expect(key['use']).toBe('sig');
    expect(key['kid']).toBeTruthy();
    // ⚑ `d` is the private scalar. Publishing it would hand over the signing key.
    expect(key).not.toHaveProperty('d');
  });
});

/** Every rejection must be a typed TOKEN_INVALID, never a raw library error. */
async function expectRejected(token: string): Promise<void> {
  await expect(tokens.verifyAccess(token)).rejects.toSatisfy((error: unknown) => {
    return isAuthError(error) && error.code === 'TOKEN_INVALID' && error.status === 401;
  });
}
