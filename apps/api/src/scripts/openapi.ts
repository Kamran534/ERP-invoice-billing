/**
 * Writes the OpenAPI document to disk without starting a server.
 *
 * Two uses:
 *  - client codegen (`openapi-typescript`, `orval`, whatever the frontend uses)
 *  - a CI contract check: regenerate and `git diff --exit-code`, so an
 *    accidental breaking change to a request or response shape fails the build
 *    instead of surprising a client at runtime.
 *
 *   pnpm --filter @app/api run openapi
 */

import { writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { loadEnv } from '../env.js';
import { buildApp } from '../app.js';

async function main(): Promise<void> {
  const env = loadEnv();
  const app = await buildApp({ ...env, LOG_LEVEL: 'warn', SWAGGER_ENABLED: true });

  const document = app.swagger();
  const outDir = path.resolve(process.cwd(), 'openapi');
  await mkdir(outDir, { recursive: true });
  const outFile = path.join(outDir, 'openapi.json');
  await writeFile(outFile, `${JSON.stringify(document, null, 2)}\n`, 'utf8');

  const paths = Object.keys((document as { paths?: Record<string, unknown> }).paths ?? {});
  console.log(`wrote ${outFile}`);
  console.log(`${paths.length} paths:`);
  for (const p of paths.sort()) console.log(`  ${p}`);

  await app.close();
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
