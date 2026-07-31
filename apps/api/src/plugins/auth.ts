/**
 * The composition root for the auth module.
 *
 * `@auth/core` is written against ports and knows nothing about Fastify, Postgres
 * or environment variables. This is the one file that knows about all of them, and
 * it exists so that remains true: everything below is assembly, not decision.
 *
 * ⚑ It also runs `auditProductionConfig` at boot. A weakened setting is only a
 * problem if nobody notices it, and the natural time to notice is before the
 * process starts serving.
 */

import fp from 'fastify-plugin';
import {
  auditProductionConfig,
  defineAuthConfig,
  type AuthConfig,
  type AuthContext,
  type AuthDomainEvent,
  type CryptoDeps,
} from '@auth/core';
import { createRepos } from '@auth/db';
import {
  createHibpBreachChecker,
  nodeCryptoDeps,
  nodeRandom,
  uuidv7,
} from '@auth/crypto';
import type { Env } from '../env.js';

declare module 'fastify' {
  interface FastifyInstance {
    /** Everything a use-case needs, assembled once. */
    auth: AuthContext;
    /** The pure primitives use-cases take alongside the context. */
    authDeps: CryptoDeps;
  }
}

/**
 * Env is deployment shape; `AuthConfig` is policy. They are deliberately separate
 * types — most of the policy below has no env var at all, because a value nobody
 * should change per-environment should not be reachable per-environment.
 */
export function buildAuthConfig(env: Env): AuthConfig {
  return defineAuthConfig({
    appName: env.APP_NAME,
    urls: { appOrigin: env.APP_ORIGIN },
    tokens: {
      issuer: env.JWT_ISSUER,
      audience: env.JWT_AUDIENCE,
      accessTtl: env.ACCESS_TOKEN_TTL_S * 1_000,
      refresh: {
        idleTtl: env.REFRESH_IDLE_TTL_S * 1_000,
        absoluteTtl: env.REFRESH_ABSOLUTE_TTL_S * 1_000,
      },
    },
    cookies: {
      // ⚑ Must agree with HSTS and the CSP upgrade — one flag drives all of them
      // (ADR-0008), because a `Secure` cookie over plain HTTP is simply dropped
      // and the resulting "login does nothing" is unpleasant to diagnose.
      secure: env.HTTPS_ENABLED,
    },
    password: { checkBreached: env.PASSWORD_BREACH_CHECK },
    email: { fromAddress: env.MAIL_FROM },
  });
}

export const authPlugin = fp(
  async (app) => {
    const config = buildAuthConfig(app.env);

    const breachChecker = config.password.checkBreached
      ? createHibpBreachChecker({ timeoutMs: app.env.PASSWORD_BREACH_TIMEOUT_MS })
      : undefined;

    const problems = auditProductionConfig(config);

    // ⚑ The audit reads config, so it cannot see this: `checkBreached: true` with
    // nothing wired reads as "control enabled" while accepting every breached
    // password, because the use-case treats a missing checker as an outage and
    // fails open. That combination is worse than turning the check off honestly —
    // and it is what this app shipped with until an e2e test noticed.
    if (config.password.checkBreached && !breachChecker) {
      problems.push('password.checkBreached is true but no breach checker is wired');
    }

    if (problems.length > 0) {
      const message = `auth configuration weakens a default:\n${problems.map((p) => `  - ${p}`).join('\n')}`;
      // Fatal in production, loud everywhere else: a test fixture is allowed to
      // turn things off, a production deployment is not allowed to do it quietly.
      if (app.env.NODE_ENV === 'production') throw new Error(message);
      app.log.warn(message);
    }

    const context: AuthContext = {
      config,
      repos: createRepos(app.dbHandle.db, { uuid: uuidv7 }),
      clock: { now: () => new Date() },
      random: nodeRandom,
      hasher: app.hasher,
      tokens: app.tokens,
      mailer: app.mailer,
      breachChecker,
      events: {
        // Nothing subscribes yet. The port exists so a use-case never has to know
        // whether anything does — and `emit()` in core swallows handler failures,
        // so wiring a real bus here can never fail a login.
        async publish(event: AuthDomainEvent) {
          app.log.debug({ event: event.type }, 'auth event');
        },
      },
      logger: app.log,
    };

    app.decorate('auth', context);
    app.decorate('authDeps', nodeCryptoDeps);
  },
  { name: 'auth', dependencies: ['infra'] },
);
