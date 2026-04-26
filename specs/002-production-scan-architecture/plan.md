# Implementation Plan: Production Scan Architecture

**Feature ID**: `002-production-scan-architecture`  
**Spec**: `specs/002-production-scan-architecture/spec.md`

## Summary

Re-baseline AegisAI around the DOCX production security scan architecture while preserving
the existing MVP package as legacy. The first implementation milestone adds documentation,
shared contracts, Prisma skeleton entities, and tests that enforce the new trust boundaries.

## Technical Context

- TypeScript contracts remain in `packages/shared`.
- NestJS backend and React frontend continue to import shared contracts.
- Prisma remains the persistence schema source for application data.
- Scanner runtime, sandbox runtime, and AI inference are deferred.

## Project Structure

```text
specs/002-production-scan-architecture/
  quickstart.md
  spec.md
  research.md
  data-model.md
  contracts/scan-architecture.md
  plan.md
  tasks.md
  checklists/requirements.md
packages/shared/src/
apps/api/prisma/schema.prisma
test/github-actions/
apps/api/test/architecture/
```

## Implementation Strategy

1. Add failing tests for active feature entrypoint, shared contracts, and Prisma skeleton.
2. Create the new feature package and update repo entrypoints.
3. Add shared production architecture contracts.
4. Extend Prisma with tenant-attributed skeleton entities.
5. Run lint, tests, typecheck, build, and Prisma validation.

## Architecture Notes

- The default future path is a scanner-first pipeline and deterministic-first.
- Token Broker is the future credential boundary for short-lived scan-scoped SCM access.
- Policy-as-code is the future decision boundary for dashboard, comment, warning, ticket,
  and block behavior.
- AI is advisory-only and receives reduced evidence.
- Oracle VPS deployment is dev/demo only.
- Production topology assumes separated Control, Scan, AI, and Data/Security planes.
