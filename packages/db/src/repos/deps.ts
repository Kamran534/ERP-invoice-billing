/**
 * What the Postgres adapters need from outside.
 *
 * ⚑ Id generation is injected rather than imported. `@auth/crypto` owns UUIDv7,
 * but a repository reaching for it directly would make one adapter depend on
 * another, and the one-directional rule (core ← adapters ← app) is the whole
 * reason the auth module is portable. The app passes `nodeRandom.uuid`; a test can
 * pass a counter and get deterministic ids.
 */

export interface RepoDeps {
  /** Time-sortable ids. See RandomSource.uuid in @auth/core. */
  uuid: () => string;
}
