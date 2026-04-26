# Prisma OpenSSL Runtime Dependency Fix Design

## Goal

Prevent the production API container from crashing on Oracle ARM64 because Prisma resolves a
musl/OpenSSL 1.1 runtime that is unavailable in the current Alpine-based image.

## Root Cause

The API Docker image currently uses `node:20-alpine` for both builder and runner stages.
That causes Prisma to generate and load the `linux-musl-arm64-openssl-1.1.x` engine in
production. On the deployed Oracle VPS, that engine fails to start because
`libssl.so.1.1` is not present.

Observed production error:
- `PrismaClientInitializationError`
- `Error loading shared library libssl.so.1.1: No such file or directory`

## Recommended Fix

Move the API build and runtime images from Alpine to Debian slim and install OpenSSL
explicitly in both stages.

Why:
- Debian slim gives Prisma a glibc/OpenSSL 3 compatible runtime path on ARM64.
- Installing `openssl` and `ca-certificates` makes the runtime dependency explicit instead of
  relying on image defaults.
- The change is isolated to the API Docker image and does not affect application code or the
  web container.

## Scope

In scope:
- `apps/api/Dockerfile`
- Dockerfile regression tests under `test/github-actions`

Out of scope:
- Prisma package upgrades
- Compose topology changes
- Oracle network or firewall configuration

## Verification

Lock the fix with tests that assert:
- API Dockerfile no longer uses Alpine
- API Dockerfile uses `node:20-bookworm-slim`
- OpenSSL runtime packages are installed
- Existing API entrypoint regression still holds

Repository verification remains:
- `corepack pnpm lint`
- `corepack pnpm test`
- `corepack pnpm typecheck`
- `corepack pnpm build`
