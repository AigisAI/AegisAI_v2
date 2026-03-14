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

## Branch Naming

Use the following format for working branches:

`<type>/<issue-number>-<short-feature>`

Examples:

- `feat/13-workspace-bootstrap`
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

The active implementation package still lives under `specs/001-aegisai-mvp-foundation/`.

When you are working on a GitHub-style branch such as `feat/13-workspace-bootstrap`, use
`SPECIFY_FEATURE` to point Spec Kit scripts at the active feature directory when needed:

```powershell
$env:SPECIFY_FEATURE = "001-aegisai-mvp-foundation"
```
