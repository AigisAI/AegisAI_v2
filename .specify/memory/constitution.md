<!--
Sync Impact Report
- Version change: template -> 1.0.0
- Modified principles: established initial project constitution from spec 2.2.md
- Added sections: Technology Standards, Delivery Workflow
- Removed sections: none
- Templates requiring updates: .specify/templates/spec-template.md (updated), .specify/templates/plan-template.md (updated), .specify/templates/tasks-template.md (updated), .codex/prompts/speckit.constitution.md (updated), .codex/prompts/speckit.specify.md (updated), .codex/prompts/speckit.plan.md (updated), .codex/prompts/speckit.tasks.md (updated)
- Follow-up TODOs: keep this constitution and spec 2.2.md aligned when scope or architecture changes
-->

# AegisAI Constitution

## Core Principles

### I. MVP Scope Discipline
Features MUST default to the MVP scope defined in `spec 2.2.md`. Anything explicitly
labeled `Phase 2 roadmap`, `Phase 3 roadmap`, `optional integration`, or `future
expansion` is out of the default delivery scope unless the feature spec calls it out
as intentional follow-on work. New plans MUST distinguish between MVP acceptance
criteria and roadmap-only design notes.

### II. Decoupled Analysis Architecture
The SaaS backend MUST orchestrate repository access and job execution, but it MUST
NOT implement the vulnerability detection engine itself. Repository code is collected
by the NestJS backend through GitHub or GitLab APIs and passed to analysis via
`IAnalysisApiClient`. Direct source-file upload is out of scope. `apps/ai` is an
optional integration path, and the default Phase 1 behavior MUST remain compatible
with `MockAnalysisApiClient`. Language support MUST start with Java only and expand
through `ILanguageHandler` implementations rather than hard-coded language branches.

### III. Typed Monorepo Contracts
`apps/api`, `apps/web`, and `packages/shared` MUST use TypeScript, with shared API
types living in `packages/shared`. Runtime DTO validation belongs in `apps/api`.
External dependencies MUST be abstracted behind interfaces where the architecture
calls for replacement or provider-specific behavior. Consensus-related fields such as
`consensusScore` and `modelResults` MUST be preserved in schemas and responses even
when the initial implementation uses mock data.

### IV. Thin Controllers, Async Workers, Clear Boundaries
Controllers MUST stay focused on request and response handling. Business logic and
Prisma access belong in services and workers. `POST /api/scans` and report generation
flows MUST remain asynchronous, returning identifiers immediately while BullMQ workers
perform long-running work. Environment access MUST go through `ConfigService`, logging
MUST use `NestJS Logger`, and frontend data fetching MUST flow through dedicated
`api/` modules plus TanStack Query rather than direct Axios calls inside components.

### V. Security, Operability, and Test Gates
Session-based auth, CSRF protection, rate limiting, and CORS configuration are
non-negotiable for user-facing API work. `GET /api/health` MUST stay available for
basic uptime and dependency checks. Every feature plan and task list MUST include the
tests needed to protect critical flows, especially OAuth/session handling, queue-based
scan execution, repository integration, vulnerability retrieval, and PDF reporting
when relevant. Coverage expectations are at least 80% line coverage for service logic
and 70% for controller paths. Success criteria SHOULD map back to the product goals in
`spec 2.2.md`, including first-scan usability, turnaround time, and reviewer efficiency.

## Technology Standards

The default stack is Node.js 20 LTS, NestJS 10.x, React 18.x, TypeScript 5.x, Prisma
5.x, PostgreSQL 16, Redis 7, BullMQ 5.x, TanStack Query 5.x, Zustand 4.x, Tailwind
CSS 3.4.x, and Puppeteer 23.x. `apps/ai` is optional and uses Python 3.11+ with
FastAPI. Plans MUST assume a pnpm workspace monorepo with source rooted in
`apps/api`, `apps/web`, `apps/ai` (optional), and `packages/shared`.

## Delivery Workflow

When requirements are ambiguous, interpret project intent in this order:
`1. Project Overview -> 6. API Specification -> 8. Core Module Design -> 11. Development Tasks`
from `spec 2.2.md`. Feature specs MUST call out user-visible scope, explicit
non-goals, and any roadmap boundaries. Implementation plans MUST document affected
apps/packages, interfaces, data models, API contracts, security constraints, and test
coverage needs. Task lists MUST be execution-ordered, path-specific, and grouped so
the MVP can be delivered incrementally without accidentally pulling in roadmap work.

## Governance

This constitution overrides generic Spec Kit defaults for this repository. Every
generated spec, plan, and task list MUST be checked against both this file and
`spec 2.2.md`. Any intentional deviation requires an explicit justification in the
plan's complexity or tradeoff section. Amendments require updating this constitution,
the affected templates or prompt files, and any now-stale references in project docs.

**Version**: 1.0.0 | **Ratified**: 2026-03-13 | **Last Amended**: 2026-03-13
