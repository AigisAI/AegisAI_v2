# AegisAI Phase 1 Workspace Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bootstrap the pnpm monorepo workspace for the AegisAI MVP with minimal backend, frontend, shared package, and baseline verification scaffolding.

**Architecture:** Start from the approved MVP docs and create only the Phase 1 shell needed to unblock Phase 2 foundation work. Keep the backend, frontend, and shared package boundaries aligned with the spec, while limiting behavior to simple smoke-level entrypoints.

**Tech Stack:** Node.js, pnpm workspace, NestJS, React + Vite, TypeScript, Jest, Vitest, ESLint, Docker Compose

---

## Chunk 1: Root Workspace

### Task 1: Create root workspace and package manager files

**Files:**
- Create: `package.json`
- Create: `pnpm-workspace.yaml`
- Create: `.npmrc`
- Create: `docker-compose.yml`
- Create: `.env.example`
- Create: `.gitignore`
- Create: `tsconfig.base.json`
- Create: `eslint.config.mjs`

- [ ] Add the root workspace manifest, package manager settings, shared scripts, and workspace globs.
- [ ] Add Docker Compose services for PostgreSQL and Redis.
- [ ] Add baseline environment examples and ignore rules.
- [ ] Add shared TypeScript and ESLint defaults.

## Chunk 2: Package Scaffolding

### Task 2: Create minimal API, web, and shared package shells

**Files:**
- Create: `apps/api/package.json`
- Create: `apps/api/tsconfig.json`
- Create: `apps/api/tsconfig.build.json`
- Create: `apps/api/nest-cli.json`
- Create: `apps/api/.env.example`
- Create: `apps/api/src/main.ts`
- Create: `apps/api/src/app.module.ts`
- Create: `apps/api/src/app.controller.ts`
- Create: `apps/api/src/app.service.ts`
- Create: `apps/api/test/app.e2e-spec.ts`
- Create: `apps/api/test/jest-e2e.json`
- Create: `apps/web/package.json`
- Create: `apps/web/tsconfig.json`
- Create: `apps/web/tsconfig.node.json`
- Create: `apps/web/vite.config.ts`
- Create: `apps/web/.env.example`
- Create: `apps/web/index.html`
- Create: `apps/web/src/main.tsx`
- Create: `apps/web/src/App.tsx`
- Create: `apps/web/src/App.test.tsx`
- Create: `apps/web/src/test/setup.ts`
- Create: `packages/shared/package.json`
- Create: `packages/shared/tsconfig.json`
- Create: `packages/shared/src/index.ts`

- [ ] Create minimal backend app entrypoints and an e2e smoke test target.
- [ ] Create minimal frontend app entrypoints and a render smoke test target.
- [ ] Create the shared package entrypoint and export surface.

## Chunk 3: Verification

### Task 3: Verify local toolchain assumptions and document blockers

**Files:**
- Modify: `README.md`

- [ ] Check local Node and package manager availability.
- [ ] Attempt the first package-manager verification path that matches the environment.
- [ ] Record any install or network blockers before moving to Phase 2 work.
