# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the pnpm monorepo.
#
# `pnpm fetch` populates the store from the lockfile ALONE, so the dependency
# layer is cached until pnpm-lock.yaml changes — editing source never re-downloads
# anything. Two independent install stages then run from that shared cache:
# one with dev dependencies (to compile) and one production-only (to ship).
#
# Why not `pnpm prune --prod` on the built tree: with pnpm's isolated node_modules
# layout, pruning leaves dangling symlinks into `.pnpm/`, and the app fails at
# runtime with ERR_MODULE_NOT_FOUND on packages that are genuinely production
# dependencies. A clean `--prod` install is correct by construction.

ARG NODE_VERSION=24-alpine

# ── base ─────────────────────────────────────────────────────────────────────
FROM node:${NODE_VERSION} AS base
# CI=true makes pnpm (and turbo) non-interactive. Without it, any install that
# has to replace node_modules aborts with ERR_PNPM_ABORTED_REMOVE_MODULES_DIR_NO_TTY
# because there is no TTY to confirm the purge.
ENV CI=true PNPM_HOME=/pnpm PATH=/pnpm:$PATH
RUN corepack enable && corepack prepare pnpm@11.9.0 --activate
# libc6-compat: @node-rs/argon2 needs the glibc shim on musl.
# dumb-init: correct PID 1 signal forwarding, so SIGTERM reaches Node and the
# graceful-shutdown path in src/index.ts actually runs.
RUN apk add --no-cache libc6-compat dumb-init
WORKDIR /app

# ── dependency fetch (cache key = lockfile only) ─────────────────────────────
FROM base AS fetch
COPY pnpm-lock.yaml pnpm-workspace.yaml ./
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm fetch

# ── compile ─────────────────────────────────────────────────────────────────
FROM fetch AS build
COPY . .
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile --offline
RUN pnpm run build

# ── production dependency tree ──────────────────────────────────────────────
FROM fetch AS prod-deps
COPY . .
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile --offline --prod

# ── runtime ─────────────────────────────────────────────────────────────────
FROM base AS runtime
ENV NODE_ENV=production \
    # Cap the old-space so the container OOMs predictably instead of thrashing.
    # Keep this under the compose memory limit (1G), leaving headroom for the
    # Argon2 working set (memoryCost × HASH_MAX_CONCURRENCY).
    NODE_OPTIONS="--max-old-space-size=640 --enable-source-maps" \
    # Native Argon2 runs on the libuv pool; the default of 4 throttles logins.
    UV_THREADPOOL_SIZE=8

# Copying the whole /app preserves pnpm's relative symlinks into .pnpm/, which a
# per-directory copy would break.
COPY --from=prod-deps --chown=node:node /app /app
# Then overlay the compiled output from the build stage.
COPY --from=build --chown=node:node /app/packages/core/dist   ./packages/core/dist
COPY --from=build --chown=node:node /app/packages/crypto/dist ./packages/crypto/dist
COPY --from=build --chown=node:node /app/packages/db/dist     ./packages/db/dist
COPY --from=build --chown=node:node /app/packages/mail/dist   ./packages/mail/dist
COPY --from=build --chown=node:node /app/apps/api/dist        ./apps/api/dist

USER node
EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=6 \
  CMD node -e "fetch('http://127.0.0.1:3000/health/live').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "apps/api/dist/index.js"]

# ── migrate (one-shot job image) ────────────────────────────────────────────
# Run migrations as a separate task before rolling out a new version:
#   docker compose run --rm --entrypoint "" api node packages/db/dist/migrate.js
FROM runtime AS migrate
CMD ["node", "packages/db/dist/migrate.js"]
