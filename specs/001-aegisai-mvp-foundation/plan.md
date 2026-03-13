# Implementation Plan: AegisAI Platform MVP Foundation

**Branch**: `001-aegisai-mvp-foundation` | **Date**: 2026-03-13 | **Spec**: `/specs/001-aegisai-mvp-foundation/spec.md`  
**Input**: Feature specification from `/specs/001-aegisai-mvp-foundation/spec.md`

**Note**: This plan is the baseline implementation handoff for the repository. It is meant
to let coding agents start execution without needing to re-derive the MVP shape from
`spec 2.2.md`.

## Summary

Build the AegisAI MVP as a pnpm monorepo with a NestJS backend, React frontend, shared
TypeScript contracts, and an optional FastAPI integration path hidden behind
`IAnalysisApiClient`. The first deliverable is the complete user loop for provider auth,
repository connection, asynchronous Java scanning with mock analysis, vulnerability review,
dashboard visibility, and PDF report export.

## Technical Context

**Language/Version**: TypeScript 5.x for `apps/api`, `apps/web`, and `packages/shared`; Python 3.11+ only if the feature explicitly touches optional `apps/ai` integration  
**Primary Dependencies**: NestJS 10.x, React 18.x, Vite 5.x, Prisma 5.x, PostgreSQL 16, Redis 7, BullMQ 5.x, TanStack Query 5.x, Zustand 4.x, Tailwind CSS 3.4.x, Puppeteer 23.x  
**Storage**: PostgreSQL 16 for application data, Redis 7 for BullMQ and session storage, local report files for MVP PDF export unless the feature is explicitly roadmap work  
**Testing**: Jest, Supertest, `@testcontainers/postgresql`, `@testcontainers/redis` or equivalent Redis integration, Vitest, React Testing Library, MSW as needed  
**Target Platform**: Web SaaS application with NestJS API, React SPA, and optional FastAPI analysis service  
**Project Type**: pnpm workspace monorepo with backend, frontend, shared package, and optional AI service  
**Performance Goals**: Preserve the product targets from `spec 2.2.md`, including first repo connection plus scan request within 1 minute and first mock-backed scan result within 30 seconds for the reference workload  
**Constraints**: Default to MVP scope; Java-only analysis support; no direct source upload; backend orchestrates repository collection; analysis remains behind `IAnalysisApiClient`; shared contracts live in `packages/shared`; auth uses sessions plus CSRF protection  
**Scale/Scope**: Repository-wide baseline covering `apps/api`, `apps/web`, `packages/shared`, local development infrastructure, and the optional `apps/ai` integration boundary

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- PASS: Scope remains inside the MVP baseline and leaves roadmap work out of acceptance.
- PASS: Repository collection stays in the backend and analysis stays behind `IAnalysisApiClient`.
- PASS: Shared contracts, consensus fields, and Java-only language handling are preserved.
- PASS: Security requirements include sessions, CSRF, throttling, CORS, raw health behavior, and protected report flows.
- PASS: The plan includes backend, frontend, integration, queue, and security testing obligations for touched flows.

## Project Structure

### Documentation (this feature)

```text
specs/001-aegisai-mvp-foundation/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── analysis-api.md
│   └── mvp-openapi.yaml
├── checklists/
│   └── requirements.md
└── tasks.md
```

### Source Code (repository root)

```text
AegisAI/
├── apps/
│   ├── api/
│   │   ├── prisma/
│   │   ├── src/
│   │   │   ├── auth/
│   │   │   ├── client/
│   │   │   ├── common/
│   │   │   ├── config/
│   │   │   ├── dashboard/
│   │   │   ├── health/
│   │   │   ├── language/
│   │   │   ├── prisma/
│   │   │   ├── repo/
│   │   │   ├── report/
│   │   │   ├── scan/
│   │   │   └── vulnerability/
│   │   └── test/ or tests/
│   ├── web/
│   │   ├── src/
│   │   │   ├── api/
│   │   │   ├── components/
│   │   │   ├── hooks/
│   │   │   ├── pages/
│   │   │   ├── router.tsx
│   │   │   └── store/
│   │   └── tests/ or src/**/*.test.tsx
│   └── ai/                   # optional integration only
├── packages/
│   └── shared/
│       └── src/
└── specs/001-aegisai-mvp-foundation/
```

**Structure Decision**: Use the monorepo structure defined in `spec 2.2.md`. The backend,
frontend, and shared package are all MVP-critical. `apps/ai` remains optional and must stay
behind interfaces so the MVP succeeds without it.

## Phase 0 Research Summary

- Session auth plus Redis-backed sessions and CSRF header validation is the right default
  because the product is a browser-based SaaS with OAuth providers.
- BullMQ is the correct queue choice for scan and report workflows because both must return
  identifiers immediately while work continues asynchronously.
- Repository collection must use provider APIs plus a hybrid file retrieval strategy to
  support large repositories without giving the analysis service direct Git access.
- `MockAnalysisApiClient` is the MVP default because it preserves the architecture while
  avoiding any dependency on a production-grade analysis engine.

## Phase 1 Design Summary

- Shared contracts in `packages/shared` define the API surface consumed by both backend and
  frontend, while DTO classes in `apps/api` enforce runtime validation.
- `ScanService` handles request validation and job creation, while `ScanProcessor` performs
  token decryption, provider access, file collection, analysis delegation, and persistence.
- The frontend is organized around pages plus query-powered hooks, with Axios isolated under
  `apps/web/src/api` and auth state tracked in Zustand.
- PDF generation follows the same asynchronous queue pattern as scans to avoid blocking
  requests and to preserve consistent user experience.

## Implementation Strategy

1. Establish the workspace, shared contracts, infrastructure wiring, and testing harness.
2. Complete User Story 1 end to end so the product can authenticate, connect repositories,
   and finish a mock-backed scan.
3. Add vulnerability review and feedback flows.
4. Add dashboard summaries and PDF report generation.
5. Run cross-cutting security, regression, and quickstart validation before implementation
   shifts to roadmap work.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| None | N/A | The baseline plan stays within the constitution and `spec 2.2.md` |
