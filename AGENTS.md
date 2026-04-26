# AegisAI Agent Start Guide

## Mandatory Start Path

1. Open the canonical execution entry point: [`specs/002-production-scan-architecture/quickstart.md`](./specs/002-production-scan-architecture/quickstart.md)
2. Follow the read order and execution flow defined there before touching code.
3. Use [`specs/002-production-scan-architecture/`](./specs/002-production-scan-architecture/) as the default implementation target unless a narrower active feature replaces it.

## Core References

- Canonical execution entry point: [`specs/002-production-scan-architecture/quickstart.md`](./specs/002-production-scan-architecture/quickstart.md)
- Primary product baseline: `C:\Users\권태욱\Desktop\Security Scan SaaS Final Specification.docx`
- Legacy product baseline: [`spec 2.2.md`](./spec%202.2.md)
- Repository constitution: [`.specify/memory/constitution.md`](./.specify/memory/constitution.md)
- Active implementation package: [`specs/002-production-scan-architecture/`](./specs/002-production-scan-architecture/)
- Legacy MVP package: [`specs/001-aegisai-mvp-foundation/`](./specs/001-aegisai-mvp-foundation/)

## Active Feature Baseline

- Feature id: `002-production-scan-architecture`
- Use this feature package as the default implementation target until a narrower feature spec replaces it.

## GitHub Workflow Convention

The repository-level GitHub workflow convention is documented in
[`docs/github-conventions.md`](./docs/github-conventions.md).

- Use `feat/<issue-number>-<short-feature>` for feature branches
- Use `fix/`, `refactor/`, `release/`, and `hotfix/` with the same issue-number pattern
- Use commit messages in the format `<type>: <description>`
- Keep issue titles and PR titles identical
- Treat `dev` as the default integration branch and `main` as the release-ready branch

## If You Need Spec Kit Scripts From GitHub-Style Branches

GitHub branch names do not need to match the spec directory name. In a PowerShell session, run:

```powershell
$env:SPECIFY_FEATURE = "002-production-scan-architecture"
```

This makes Spec Kit scripts resolve the active feature directory directly while you continue
working on GitHub-style branches such as `feat/<issue-number>-<short-feature>`.

## Document Precedence

1. `AGENTS.md` defines how agents enter the repository and the guardrails they must preserve.
2. `quickstart.md` defines the canonical read order, execution flow, and completion flow.
3. `Security Scan SaaS Final Specification.docx` is the highest-priority product, platform, security, and operations baseline.
4. The active feature package defines implementation-ready scope and task detail.
5. `spec 2.2.md` and `001-aegisai-mvp-foundation` remain legacy MVP references.
6. `.specify/memory/constitution.md` remains a repository guardrail reference.

## Agent Execution Policy

- Start from `quickstart.md`; do not begin directly from `tasks.md`.
- Treat `quickstart.md` as the single source of truth for execution order and validation flow.
- Use `README.md` as a lightweight landing page, not as an execution checklist.
- Return to supporting docs when a task touches contracts, entities, architecture boundaries, or guardrails.
- If implementation-ready docs and baseline docs appear to diverge on scope or acceptance, stop and resolve the mismatch before coding.

## Non-Negotiable Rules

- Stay inside the active production architecture milestone unless the current spec explicitly reclassifies deferred work.
- Keep user authentication separate from SCM integration credentials.
- Model GitHub Cloud repository access through GitHub App installation and GitLab Cloud access through scoped integration plus webhook flows.
- Keep Scan Plane, AI Plane, and Data/Security Plane boundaries explicit.
- Do not add direct source upload.
- Do not execute customer code, install packages, or build customer repositories.
- AI is advisory-only and must not create authoritative findings or override policy.
- Shared API contracts belong in `packages/shared`.
- Sessions, CSRF protection, throttling, health checks, and critical integration tests are required.

## Frontend Design Tooling

- When frontend design work is needed, use Stitch as the default design tool instead of designing screens manually inside the coding workflow.
- When using Stitch for frontend design generation, default supported model selection to `GEMINI_3_1_PRO`.
- Treat `GEMINI_3_FLASH` as opt-in only when the user explicitly asks for a faster draft-first pass.
- This rule applies to Stitch MCP or SDK flows that expose a `modelId` or equivalent model selector.

## Completion Gate

- Re-run the final validation path from [`quickstart.md`](./specs/002-production-scan-architecture/quickstart.md) before claiming completion.
- Re-check [`specs/001-aegisai-mvp-foundation/hardening-review.md`](./specs/001-aegisai-mvp-foundation/hardening-review.md) only when legacy MVP hardening or release-readiness is explicitly part of the task.
- Keep entrypoint docs synchronized whenever execution guidance changes.

