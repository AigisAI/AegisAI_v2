# Prisma Baseline Schema Design

**Issue**: `#16`
**Title**: `feat: create Prisma baseline schema and initial migration`
**Date**: `2026-03-15`

## Goal

Create the MVP baseline Prisma schema for AegisAI so later issues can add Prisma wiring, services, and application behavior without reworking the data model.

## Scope

- Add Prisma dependencies and package scripts needed to manage the schema and client
- Create `apps/api/prisma/schema.prisma`
- Define MVP enums and models for `User`, `OAuthToken`, `ConnectedRepo`, `Scan`, `Vulnerability`, and `Report`
- Generate the initial migration under `apps/api/prisma/migrations/`

## Design Choices

1. Use PostgreSQL with Prisma enums to keep provider, scan, severity, feedback, and report states type-safe at the database level.
2. Follow the richer schema from `spec 2.2.md` as the baseline instead of a narrower subset, so later issues do not need migration churn for core entities.
3. Keep application rules such as duplicate active scan prevention out of the schema when the spec says they belong in service-layer locking logic.
4. Preserve extensibility fields like `language`, `consensusScore`, and JSON result payloads now, even though mock analysis is the MVP default.

## Non-Goals

- No NestJS Prisma module/service wiring in this issue
- No shared TypeScript contract work in this issue
- No repository, scan, auth, or report runtime behavior in this issue

## Validation

- `prisma validate` succeeds against the new schema
- Initial migration is generated from the schema
- Workspace `lint`, `test`, and `typecheck` stay green
