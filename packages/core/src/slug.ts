/**
 * Organization slugs (AUTH-MODULE-PLAN.md §10.13).
 *
 * ⚑ A slug is a **DNS label**, not a URL segment. Every organization is reachable
 * at `<slug>.<root domain>`, which means the rules are the ones DNS imposes:
 * lowercase alphanumerics and hyphens, no leading or trailing hyphen, 63
 * characters at most. A slug that is merely URL-safe can be un-resolvable, and
 * nobody finds out until the tenant exists and its staff cannot reach it.
 */

/** DNS label limit. Not a preference — 64 is refused by resolvers. */
export const SLUG_MAX_LENGTH = 63;

export const SLUG_PATTERN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Hosts a tenant must never occupy.
 *
 * ⚑ This is not tidiness. Some of these are how the product itself is reached
 * (`app`, `api`, `www`), and some are how mail and certificates for the domain are
 * validated (`mail`, `smtp`, `mx`, `autodiscover`, `_acme-challenge` in spirit) —
 * a tenant sitting on one is an outage at best, and at worst a way to receive
 * somebody else's mail or pass somebody else's domain-control check.
 */
export const RESERVED_SLUGS: ReadonlySet<string> = new Set([
  'www', 'api', 'app', 'apps', 'admin', 'administrator', 'auth', 'login', 'logout',
  'signup', 'register', 'dashboard', 'billing', 'account', 'accounts', 'settings',
  'mail', 'email', 'smtp', 'imap', 'pop', 'mx', 'ns', 'ns1', 'ns2', 'dns',
  'autodiscover', 'autoconfig', 'webmail',
  'static', 'assets', 'cdn', 'media', 'files', 'download', 'downloads',
  'status', 'health', 'metrics', 'docs', 'doc', 'help', 'support', 'blog', 'news',
  'dev', 'staging', 'stage', 'test', 'testing', 'demo', 'sandbox', 'preview',
  'internal', 'private', 'public', 'secure', 'ssl', 'vpn', 'git', 'ci',
  'invoicer', 'invoice', 'invoices', 'pay', 'payments', 'checkout', 'webhook', 'webhooks',
]);

/**
 * A slug from a display name: lowercase, ASCII-ish, hyphen-separated.
 *
 * Returns `''` when nothing survives — a name of only punctuation or only
 * non-Latin script leaves no label, and the caller has to ask for one explicitly
 * rather than invent one.
 */
export function normaliseSlug(source: string): string {
  return source
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, SLUG_MAX_LENGTH)
    // The slice can leave a trailing hyphen behind, which is not a legal label.
    .replace(/-+$/g, '');
}

export type SlugProblem = 'empty' | 'malformed' | 'reserved';

/** Why this slug cannot be used, or `null` if it can. */
export function checkSlug(slug: string): SlugProblem | null {
  if (!slug) return 'empty';
  if (!SLUG_PATTERN.test(slug) || slug.length > SLUG_MAX_LENGTH) return 'malformed';
  if (RESERVED_SLUGS.has(slug)) return 'reserved';
  return null;
}

/**
 * The subdomain a host belongs to, or null for the apex.
 *
 * ⚑ Used by the *web app*, never by the API, which sits behind a proxy whose
 * `Host` is its own (§5.3.1). Exported here so both repositories agree on what
 * counts as a tenant host — including the port, which `localhost:5173` carries and
 * a production domain does not.
 */
export function tenantFromHost(host: string, rootDomain: string): string | null {
  const cleanHost = host.trim().toLowerCase();
  const cleanRoot = rootDomain.trim().toLowerCase();
  if (!cleanHost || !cleanRoot || cleanHost === cleanRoot) return null;

  const suffix = `.${cleanRoot}`;
  if (!cleanHost.endsWith(suffix)) return null;

  const label = cleanHost.slice(0, -suffix.length);
  // ⚑ One label only. `a.b.root` is not tenant `a.b` — it is a host nobody
  // provisioned, and treating it as a tenant would let a wildcard certificate
  // holder invent tenants that look real.
  if (!label || label.includes('.')) return null;

  return checkSlug(label) === null ? label : null;
}
