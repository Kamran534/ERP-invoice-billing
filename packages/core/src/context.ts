/**
 * What every use-case is given.
 *
 * Use-cases take this and nothing else — no imports of a driver, a framework or a
 * clock. That is what lets them be unit-tested with in-memory doubles and a fake
 * clock, and it is why `packages/core` has no dependency but zod.
 *
 * `clock` in particular is not decoration: session expiry, OTP TTLs and TOTP drift
 * are all time arithmetic, and a test that cannot move time forward has to sleep.
 */

import type { AuthConfig } from './config.js';
import type {
  AuditRepo,
  BreachChecker,
  Clock,
  EventBus,
  Logger,
  Mailer,
  MfaRepo,
  OneTimeTokenRepo,
  OtpChallengeRepo,
  PasswordHasher,
  RandomSource,
  RefreshTokenRepo,
  SessionRepo,
  SmsSender,
  TokenService,
  TrustedDeviceRepo,
  UserRepo,
} from './ports.js';

export interface AuthRepos {
  users: UserRepo;
  sessions: SessionRepo;
  refreshTokens: RefreshTokenRepo;
  oneTimeTokens: OneTimeTokenRepo;
  otpChallenges: OtpChallengeRepo;
  mfa: MfaRepo;
  trustedDevices: TrustedDeviceRepo;
  audit: AuditRepo;
}

export interface AuthContext {
  config: AuthConfig;
  repos: AuthRepos;
  clock: Clock;
  random: RandomSource;
  hasher: PasswordHasher;
  tokens: TokenService;
  mailer: Mailer;
  sms?: SmsSender;
  /**
   * Optional on purpose. `password.checkBreached` can be on while this is absent
   * (air-gapped deployments, tests), and the policy check treats that as "control
   * unavailable" rather than failing every signup — see `assertPasswordAcceptable`.
   */
  breachChecker?: BreachChecker;
  events: EventBus;
  logger: Logger;
}

/** Where a request came from. Recorded on sessions and audit rows. */
export interface RequestContext {
  ip: string | null;
  userAgent: string | null;
}

export const systemClock: Clock = { now: () => new Date() };

/**
 * Publishes without ever letting a subscriber break the flow that emitted it.
 *
 * ⚑ A handler that throws must not fail a login. Events are notifications, not
 * part of the transaction — see the port contract in §6.
 */
export async function emit(
  ctx: AuthContext,
  type: string,
  payload: Record<string, unknown>,
): Promise<void> {
  try {
    await ctx.events.publish({ type, at: ctx.clock.now(), payload });
  } catch (error) {
    ctx.logger.error({ err: error, event: type }, 'event handler failed');
  }
}

/**
 * Audit writes are not best-effort: if we cannot record what happened, we have not
 * really done it safely. The caller decides whether to proceed, but the failure is
 * always loud (§16).
 */
export async function audit(
  ctx: AuthContext,
  event: Parameters<AuditRepo['append']>[0],
): Promise<void> {
  try {
    await ctx.repos.audit.append(event);
  } catch (error) {
    ctx.logger.error({ err: error, event: event.event }, 'audit write failed');
    throw error;
  }
}
