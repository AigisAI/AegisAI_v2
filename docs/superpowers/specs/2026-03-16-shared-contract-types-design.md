# Shared Contract Types Design

**Issue**: `#27`
**Title**: `Feat: shared contract types 생성`
**Date**: `2026-03-16`

## Goal

Create the baseline `@aegisai/shared` type surface that both `apps/api` and `apps/web` can use as the single source of truth for MVP request and response contracts.

## Scope

- Add shared type modules under `packages/shared/src/types/`
- Cover the MVP contract areas: common, auth, repo, scan, vulnerability, dashboard, and report
- Re-export the shared type surface from `packages/shared/src/index.ts`
- Add regression coverage so the shared package cannot silently lose contract modules or root exports

## Design Choices

1. Keep this issue type-only. No runtime validators or schema libraries are introduced here.
2. Model contracts around API payloads and view-facing DTOs rather than Prisma entities, so backend and frontend stay decoupled from persistence details.
3. Use string union types for shared enums (`Provider`, `ScanStatus`, `Severity`, `VulnStatus`, `UserFeedback`, `ReportStatus`) to match the existing spec examples and keep interop simple across apps.
4. Include both offset and cursor pagination contracts in `common.ts` because repo and branch listings are explicitly cursor-based in the spec while scans and vulnerabilities are page-based.
5. Keep response aliases and request payload shapes close to their domains so later API client/controller work can import narrow, intention-revealing types.

## Non-Goals

- No API implementation or DTO validation logic
- No Prisma model generation or backend entity mapping helpers
- No subpath package exports beyond the package root in this issue

## Validation

- Shared type regression test passes
- `@aegisai/shared` build, lint, test, and typecheck pass
- Workspace `lint`, `test`, `typecheck`, and `build` still pass
