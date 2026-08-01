/**
 * Slug and host rules (AUTH-MODULE-PLAN.md §10.13).
 *
 * A slug is a DNS label here, not a URL segment, and `tenantFromHost` is the one
 * place a browser-supplied host turns into a tenant. Both are worth pinning down:
 * the first failure mode is a tenant nobody can resolve, the second is a tenant
 * somebody can invent.
 */

import { describe, it, expect } from 'vitest';
import { checkSlug, normaliseSlug, tenantFromHost } from './slug.js';

describe('normaliseSlug', () => {
  it('makes a label out of a display name', () => {
    expect(normaliseSlug('Acme Billing')).toBe('acme-billing');
    expect(normaliseSlug('  Ünïcode Ltd.  ')).toBe('unicode-ltd');
    expect(normaliseSlug('A & B')).toBe('a-b');
  });

  it('⚑ never leaves a trailing hyphen, even after truncation', () => {
    // The 63-character slice can land mid-separator, and `acme-` is not a legal
    // DNS label — the tenant would exist at an address that does not resolve.
    const long = `${'a'.repeat(62)} tail`;
    const slug = normaliseSlug(long);
    expect(slug.endsWith('-')).toBe(false);
    expect(checkSlug(slug)).toBeNull();
  });

  it('returns nothing when nothing survives', () => {
    expect(normaliseSlug('!!!')).toBe('');
    expect(normaliseSlug('日本語')).toBe('');
  });
});

describe('checkSlug', () => {
  it('accepts ordinary labels', () => {
    expect(checkSlug('acme')).toBeNull();
    expect(checkSlug('acme-billing-2')).toBeNull();
  });

  it('refuses what DNS refuses', () => {
    expect(checkSlug('')).toBe('empty');
    expect(checkSlug('-acme')).toBe('malformed');
    expect(checkSlug('acme-')).toBe('malformed');
    expect(checkSlug('ACME')).toBe('malformed');
    expect(checkSlug('a'.repeat(64))).toBe('malformed');
    expect(checkSlug('two words')).toBe('malformed');
  });

  it('⚑ refuses the hosts the product and its mail need', () => {
    for (const reserved of ['www', 'api', 'app', 'mail', 'admin', 'status']) {
      expect(checkSlug(reserved)).toBe('reserved');
    }
  });
});

describe('tenantFromHost', () => {
  const root = 'invoicer.test';

  it('reads one label below the apex', () => {
    expect(tenantFromHost('acme.invoicer.test', root)).toBe('acme');
    expect(tenantFromHost('ACME.Invoicer.Test', root)).toBe('acme');
  });

  it('treats the apex as no tenant', () => {
    expect(tenantFromHost('invoicer.test', root)).toBeNull();
    expect(tenantFromHost('', root)).toBeNull();
  });

  it('⚑ refuses more than one label', () => {
    // `a.b.root` is a host nobody provisioned. Treating it as tenant `a.b` would
    // let anyone holding a wildcard certificate invent tenants that look real.
    expect(tenantFromHost('a.b.invoicer.test', root)).toBeNull();
  });

  it('⚑ refuses a reserved or malformed label', () => {
    expect(tenantFromHost('www.invoicer.test', root)).toBeNull();
    expect(tenantFromHost('-bad.invoicer.test', root)).toBeNull();
  });

  it('keeps the port, because development has one', () => {
    expect(tenantFromHost('acme.localhost:5173', 'localhost:5173')).toBe('acme');
    // A port mismatch is a different origin, and must not resolve.
    expect(tenantFromHost('acme.localhost:3000', 'localhost:5173')).toBeNull();
  });
});
