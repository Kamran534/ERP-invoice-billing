export * from './schema.js';
export * from './pool.js';
export * from './types.js';
export * from './repos/index.js';

/**
 * Re-exported so consumers write raw SQL through this package instead of taking
 * their own drizzle-orm dependency. Keeps the ORM choice swappable behind the
 * package boundary — the point of the layering (plan §3.2).
 */
export {
  sql,
  eq,
  and,
  or,
  not,
  isNull,
  isNotNull,
  lt,
  lte,
  gt,
  gte,
  inArray,
  desc,
  asc,
  count,
  getTableName,
} from 'drizzle-orm';
