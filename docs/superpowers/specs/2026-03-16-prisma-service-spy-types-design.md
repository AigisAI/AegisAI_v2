# PrismaService Spy Type Fix Design

**Issue**: `#24`
**Title**: `Fix: PrismaService e2e spy 타입 오류 수정`
**Date**: `2026-03-16`

## Goal

Keep the Prisma infrastructure branch buildable on a fresh workspace by ensuring API commands generate the Prisma client before TypeScript compilation or Jest evaluation.

## Root Cause

- `apps/api/src/prisma/prisma.service.ts` imports `PrismaClient` from `@prisma/client`.
- On a fresh workspace, `pnpm install --frozen-lockfile` does not leave a generated Prisma client available for the API package.
- Without generated client output, `PrismaClient` is missing from the package surface and the downstream `PrismaService` lifecycle methods disappear from the type system, which then breaks the spy assertions in `prisma.service.e2e-spec.ts`.
- In this Windows-based environment, package scripts also cannot rely on a bare `pnpm` binary being present on PATH, so the script contract needs `corepack pnpm` rather than `pnpm` alone.

## Design Choice

1. Keep the existing `PrismaService` implementation unchanged because the service contract is correct once the Prisma client exists.
2. Make the API package scripts (`build`, `dev`, `test`, `test:e2e`, `typecheck`) run `corepack pnpm prisma:generate` before invoking Nest, Jest, or TypeScript.
3. Add a repository regression test that locks this script contract so future workflow or package changes cannot silently remove the Prisma generation step.

## Non-Goals

- No schema changes or migration updates
- No Docker or workflow restructuring in this issue
- No runtime behavioral changes beyond guaranteeing Prisma client generation before API commands
