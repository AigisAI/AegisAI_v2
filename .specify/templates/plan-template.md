# Implementation Plan: [FEATURE]

**Branch**: `[###-feature-name]` | **Date**: [DATE] | **Spec**: [link]
**Input**: Feature specification from `/specs/[###-feature-name]/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/plan-template.md` for the execution workflow.

## Summary

[Extract from feature spec: primary requirement + technical approach from research]

## Technical Context

**Language/Version**: TypeScript 5.x for `apps/api`, `apps/web`, and `packages/shared`; Python 3.11+ only if the feature explicitly touches optional `apps/ai` integration  
**Primary Dependencies**: NestJS 10.x, React 18.x, Vite 5.x, Prisma 5.x, PostgreSQL 16, Redis 7, BullMQ 5.x, TanStack Query 5.x, Zustand 4.x, Tailwind CSS 3.4.x, Puppeteer 23.x  
**Storage**: PostgreSQL 16 for application data, Redis 7 for BullMQ and session storage, local report files for MVP PDF export unless the feature is explicitly roadmap work  
**Testing**: Jest, Supertest, `@testcontainers/postgresql`, `@testcontainers/redis` or equivalent Redis integration, Vitest, React Testing Library, MSW as needed  
**Target Platform**: Web SaaS application with NestJS API, React SPA, and optional FastAPI analysis service  
**Project Type**: pnpm workspace monorepo with backend, frontend, shared package, and optional AI service  
**Performance Goals**: Preserve the product targets from `spec 2.2.md` where relevant, including first repo connection plus scan request within 1 minute and first mock-backed scan result within 30 seconds for the reference workload  
**Constraints**: Default to MVP scope; Java-only analysis support; no direct source upload; backend orchestrates repository collection; analysis remains behind `IAnalysisApiClient`; shared contracts live in `packages/shared`; auth uses sessions plus CSRF protection  
**Scale/Scope**: Scope work to the affected app/package set and identify whether the feature is MVP, optional integration, or Phase 2/3 roadmap work

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- Does the feature stay inside MVP scope unless roadmap work is explicitly isolated?
- Does the design preserve repository collection in the backend and analysis behind `IAnalysisApiClient`?
- Are shared contracts, consensus fields, and Java-only language handling preserved where applicable?
- Are security requirements covered for auth, session, CSRF, throttling, CORS, and health/report behavior where relevant?
- Does the plan include the tests required by the constitution for touched flows?

## Project Structure

### Documentation (this feature)

```text
specs/[###-feature]/
├── plan.md              # This file (/speckit.plan command output)
├── research.md          # Phase 0 output (/speckit.plan command)
├── data-model.md        # Phase 1 output (/speckit.plan command)
├── quickstart.md        # Phase 1 output (/speckit.plan command)
├── contracts/           # Phase 1 output (/speckit.plan command)
└── tasks.md             # Phase 2 output (/speckit.tasks command - NOT created by /speckit.plan)
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
└── specs/[###-feature]/
```

**Structure Decision**: [Document the selected structure and reference the real
directories captured above]

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| [e.g., 4th project] | [current need] | [why 3 projects insufficient] |
| [e.g., Repository pattern] | [specific problem] | [why direct DB access insufficient] |
