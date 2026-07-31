/**
 * Runs the migrations against the throwaway database used by the integration
 * suite, rather than against the one you are working in.
 *
 * ⚑ Separate entry point rather than a flag on `migrate.ts`, because the two
 * differ in the only way that matters: this one is expected to point somewhere
 * disposable, and the other is expected not to. A flag would make it possible to
 * migrate the wrong database by getting one word wrong on a command line.
 */

process.env['MIGRATE_TARGET'] = 'test';
await import('./migrate.js');
