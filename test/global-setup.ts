/**
 * Global setup for the integration and e2e projects.
 *
 * Runs once per project, before any test file. Its only job is to turn "the
 * containers aren't up" into one actionable sentence instead of dozens of
 * connection timeouts that each look like a different failure.
 */

import { assertInfraReachable } from '@auth/testing';

export default async function setup(): Promise<void> {
  const startedAt = Date.now();
  await assertInfraReachable();
  console.log(`[test] infrastructure ready in ${Date.now() - startedAt}ms`);
}
