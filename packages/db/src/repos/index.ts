/**
 * Composition of the Postgres adapters.
 *
 * One factory returning every repository, so the app wires persistence in a single
 * place and a test can hand the same shape to a use-case with any subset replaced.
 */

import type { Database } from '../pool.js';
import type { RepoDeps } from './deps.js';
import { createAuditRepo, createUserRepo } from './users.js';
import { createRefreshTokenRepo, createSessionRepo } from './sessions.js';
import { createOneTimeTokenRepo, createOtpChallengeRepo } from './tokens.js';
import { createMfaRepo, createTrustedDeviceRepo } from './mfa.js';
import { createMembershipRepo, createOrgRepo, createRoleRepo } from './orgs.js';

export * from './deps.js';
export * from './users.js';
export * from './sessions.js';
export * from './tokens.js';
export * from './mfa.js';
export * from './orgs.js';

export function createRepos(db: Database, deps: RepoDeps) {
  return {
    users: createUserRepo(db, deps),
    sessions: createSessionRepo(db, deps),
    refreshTokens: createRefreshTokenRepo(db, deps),
    oneTimeTokens: createOneTimeTokenRepo(db, deps),
    otpChallenges: createOtpChallengeRepo(db, deps),
    mfa: createMfaRepo(db, deps),
    trustedDevices: createTrustedDeviceRepo(db, deps),
    orgs: createOrgRepo(db, deps),
    memberships: createMembershipRepo(db, deps),
    roles: createRoleRepo(db),
    audit: createAuditRepo(db, deps),
  };
}

export type Repos = ReturnType<typeof createRepos>;
