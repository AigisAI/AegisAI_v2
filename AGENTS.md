# AegisAI Agent Start Guide

## Mandatory Start Path

1. Open the canonical execution entry point: [`specs/001-aegisai-mvp-foundation/quickstart.md`](./specs/001-aegisai-mvp-foundation/quickstart.md)
2. Follow the read order and execution flow defined there before touching code.
3. Use [`specs/001-aegisai-mvp-foundation/`](./specs/001-aegisai-mvp-foundation/) as the default implementation target unless a narrower active feature replaces it.

## Core References

- Canonical execution entry point: [`specs/001-aegisai-mvp-foundation/quickstart.md`](./specs/001-aegisai-mvp-foundation/quickstart.md)
- Primary product baseline: [`spec 2.2.md`](./spec%202.2.md)
- Repository constitution: [`.specify/memory/constitution.md`](./.specify/memory/constitution.md)
- Baseline implementation package: [`specs/001-aegisai-mvp-foundation/`](./specs/001-aegisai-mvp-foundation/)

## Active Feature Baseline

- Feature id: `001-aegisai-mvp-foundation`
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
$env:SPECIFY_FEATURE = "001-aegisai-mvp-foundation"
```

This makes Spec Kit scripts resolve the active feature directory directly while you continue
working on GitHub-style branches such as `feat/<issue-number>-<short-feature>`.

## Document Precedence

1. `AGENTS.md` defines how agents enter the repository and the guardrails they must preserve.
2. `quickstart.md` defines the canonical read order, execution flow, and completion flow.
3. The active feature package defines implementation-ready scope and task detail.
4. `spec 2.2.md` and `.specify/memory/constitution.md` remain baseline constraints and architecture references.

## Agent Execution Policy

- Start from `quickstart.md`; do not begin directly from `tasks.md`.
- Treat `quickstart.md` as the single source of truth for execution order and validation flow.
- Use `README.md` as a lightweight landing page, not as an execution checklist.
- Return to supporting docs when a task touches contracts, entities, architecture boundaries, or guardrails.
- If implementation-ready docs and baseline docs appear to diverge on scope or acceptance, stop and resolve the mismatch before coding.

## Non-Negotiable Rules

- Stay inside MVP scope unless the current spec explicitly reclassifies roadmap work.
- Keep repository access in the NestJS backend and analysis behind `IAnalysisApiClient`.
- Do not add direct source upload.
- Java is the only MVP language, but extensibility must stay plugin-based through `ILanguageHandler`.
- Shared API contracts belong in `packages/shared`.
- Sessions, CSRF protection, throttling, health checks, and critical integration tests are required.

## Frontend Design Tooling

- When frontend design work is needed, use Stitch as the default design tool instead of designing screens manually inside the coding workflow.
- When using Stitch for frontend design generation, default supported model selection to `GEMINI_3_1_PRO`.
- Treat `GEMINI_3_FLASH` as opt-in only when the user explicitly asks for a faster draft-first pass.
- This rule applies to Stitch MCP or SDK flows that expose a `modelId` or equivalent model selector.

## Completion Gate

- Re-run the final validation path from [`quickstart.md`](./specs/001-aegisai-mvp-foundation/quickstart.md) before claiming completion.
- Re-check [`specs/001-aegisai-mvp-foundation/hardening-review.md`](./specs/001-aegisai-mvp-foundation/hardening-review.md) when Phase 6 hardening or release-readiness is part of the task.
- Keep entrypoint docs synchronized whenever execution guidance changes.
