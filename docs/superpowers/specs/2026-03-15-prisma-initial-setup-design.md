# Prisma Initial Setup Design

**Issue**: `#17`  
**Title**: `Feat: Prisma 초기 설정`  
**Date**: `2026-03-15`

## Goal

Add the backend runtime infrastructure needed to consume the Prisma schema from `#16`
without yet wiring the full application bootstrap for auth, queues, or sessions.

## Scope

- Add backend configuration dependencies required for validated environment loading
- Create `apps/api/src/config/config.module.ts`
- Create `apps/api/src/config/config.service.ts`
- Create `apps/api/src/prisma/prisma.module.ts`
- Create `apps/api/src/prisma/prisma.service.ts`
- Add focused tests for config access and Prisma service lifecycle behavior

## Recommended Approach

Use a small infrastructure-only slice that matches `T009` exactly.

- `ConfigModule` wraps Nest config loading, validates required environment variables, and
  exports a typed local `ConfigService`
- `PrismaService` extends `PrismaClient`, implements Nest lifecycle hooks, and centralizes
  connect and disconnect behavior
- `PrismaModule` exports `PrismaService` so later modules can depend on it without
  rebuilding database plumbing

This keeps `#17` narrow, stackable on top of `#16`, and safe to merge independently from
the larger `AppModule` wiring work that belongs in later issues.

## Alternatives Considered

### 1. Wire `AppModule` immediately

- Pros: faster visible progress
- Cons: mixes `T009` with later infrastructure and raises setup complexity too early

### 2. Add Prisma only and defer config

- Pros: smaller change
- Cons: incomplete against the task and forces future rework around environment loading

## Non-Goals

- No `main.ts` session or Redis setup
- No auth, repo, scan, report, or queue module wiring
- No full app bootstrap environment enforcement beyond the config module itself

## Validation

- Targeted tests prove config reads and Prisma lifecycle hooks
- Workspace `lint`, `test`, and `typecheck` stay green
