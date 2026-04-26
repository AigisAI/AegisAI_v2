# Language And Analysis Abstraction Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the language handler and analysis client abstraction layers required before scan infrastructure can be implemented cleanly.

**Architecture:** Introduce a `language` plugin registry with a Java handler, plus a `client/analysis` module that exports the `IAnalysisApiClient` token bound to a deterministic `MockAnalysisApiClient`. Keep the implementation self-contained so the upcoming scan module can import both abstractions directly.

**Tech Stack:** NestJS, Jest, Prisma-compatible DTO types, TypeScript

---

## Chunk 1: Red Tests

### Task 1: Add failing coverage for language and analysis abstractions

**Files:**
- Create: `apps/api/test/language/java.language-handler.e2e-spec.ts`
- Create: `apps/api/test/language/language-handler.registry.e2e-spec.ts`
- Create: `apps/api/test/client/analysis/mock-analysis-api.client.e2e-spec.ts`
- Create: `apps/api/test/client/analysis/analysis-api.module.e2e-spec.ts`

- [ ] **Step 1: Write a failing Java handler test for metadata, extension support, and exclusion patterns.**
- [ ] **Step 2: Write a failing registry test for handler registration and unsupported language lookup.**
- [ ] **Step 3: Write a failing mock analysis test for derived totals and consensus-backed vulnerability output.**
- [ ] **Step 4: Write a failing module test for `IAnalysisApiClient` token resolution to the mock implementation.**
- [ ] **Step 5: Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/language test/client/analysis` and confirm the new cases fail for missing implementation files.**

## Chunk 2: Language Layer

### Task 2: Implement the language plugin abstraction

**Files:**
- Create: `apps/api/src/language/language-handler.interface.ts`
- Create: `apps/api/src/language/language-handler.registry.ts`
- Create: `apps/api/src/language/handlers/java.language-handler.ts`
- Create: `apps/api/src/language/language.module.ts`

- [ ] **Step 1: Add the `ILanguageHandler` interface with language metadata and `supports(path)` behavior.**
- [ ] **Step 2: Add the Java handler with MVP Java extension, exclusion, and size rules.**
- [ ] **Step 3: Add the registry and module registration flow.**
- [ ] **Step 4: Re-run `corepack pnpm --filter @aegisai/api test -- --runInBand test/language` and make the language tests pass.**

## Chunk 3: Analysis Layer

### Task 3: Implement the analysis abstraction and mock client

**Files:**
- Create: `apps/api/src/client/analysis/analysis-api-client.interface.ts`
- Create: `apps/api/src/client/analysis/analysis-api.dto.ts`
- Create: `apps/api/src/client/analysis/mock-analysis-api.client.ts`
- Create: `apps/api/src/client/analysis/analysis-api.module.ts`

- [ ] **Step 1: Add analysis request/result interfaces and DTO-compatible types aligned with the MVP spec.**
- [ ] **Step 2: Implement `MockAnalysisApiClient` with deterministic totals and vulnerability fixtures that preserve `consensusScore` and `modelResults`.**
- [ ] **Step 3: Add `AnalysisApiModule` that exports the `IAnalysisApiClient` token bound to the mock implementation.**
- [ ] **Step 4: Re-run `corepack pnpm --filter @aegisai/api test -- --runInBand test/client/analysis` and make the analysis tests pass.**

## Chunk 4: App Wiring And Verification

### Task 4: Export the abstractions for scan infrastructure

**Files:**
- Modify: `apps/api/src/app.module.ts`
- Verify: `apps/api/test/language/*.ts`
- Verify: `apps/api/test/client/analysis/*.ts`

- [ ] **Step 1: Import `LanguageModule` and `AnalysisApiModule` into `AppModule`.**
- [ ] **Step 2: Run `corepack pnpm lint`.**
- [ ] **Step 3: Run `corepack pnpm test`.**
- [ ] **Step 4: Run `corepack pnpm typecheck`.**
- [ ] **Step 5: Run `corepack pnpm build`.**
- [ ] **Step 6: Commit with `feat: implement language and analysis abstractions`.**
