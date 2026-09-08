# GitHub Conventions

## Workflow

This repository uses Git-flow with GitHub-based issue and PR operations.

- `main`: production-ready branch
- `dev`: integration branch for the next release
- `feat/*`: feature work
- `refactor/*`: non-functional code improvements
- `fix/*`: bug fixes
- `release/*`: release preparation
- `hotfix/*`: urgent production fixes

## Resuming Work and Updating Progress

Follow [the checkout reconciliation procedure](./resuming-development.md) before choosing
the next issue. A merged PR or an old branch must not be treated as an open implementation
task. Preserve local changes and compare them with current `dev` before porting anything.

Keep the issue checklist and PR description aligned with the actual final diff and
validation on that branch. Distinguish local checks, CI checks, merge state, and live
qualification evidence. Link a separate open operations issue when external execution
remains pending; a merged contract PR does not close that operational requirement.

## Branch Naming

Use the following format for working branches:

`<type>/<issue-number>-<short-feature>`

Examples:

- `feat/4-github-setup`
- `fix/21-auth-timeout`
- `refactor/34-scan-service-cleanup`

Rules:

- Create branches from the issue
- Use only the issue number, not `#13`
- Keep the feature name short and clear

## Commit Convention

Use the following format:

`<type>: <description>`

Types:

- `feat`
- `fix`
- `docs`
- `style`
- `refactor`
- `test`
- `chore`
- `ci`
- `build`

Issue references may be added in the footer when needed.

## Issue And PR Titles

- Issue title and PR title must be identical
- Use the same convention in both places, for example:

`feat: bootstrap AegisAI MVP workspace`

## Spec Kit Compatibility

The active implementation package lives under `specs/006-production-sast-runtime-design/`.
The completed `specs/005-production-deployment-operations/` package remains the
provider-neutral deployment operations contract baseline. The completed
`specs/004-production-runtime-infrastructure/` package remains the runtime
infrastructure baseline. The completed `specs/003-production-ai-inference-runtime/` package
remains the production AI inference baseline. The completed
`specs/002-production-scan-architecture/` package remains the production scan architecture
baseline. The previous `specs/001-aegisai-mvp-foundation/` package remains a legacy MVP baseline.

When you are working on a GitHub-style branch such as `feat/4-github-setup`, use
`SPECIFY_FEATURE` to point Spec Kit scripts at the active feature directory when needed:

```powershell
$env:SPECIFY_FEATURE = "006-production-sast-runtime-design"
```
