# AegisAI Agent Start Guide

## Start Here

- Primary product spec: `spec 2.2.md`
- Repository constitution: `.specify/memory/constitution.md`
- Baseline implementation package: `specs/001-aegisai-mvp-foundation/`
- Task entry point: `specs/001-aegisai-mvp-foundation/tasks.md`

## Active Feature Baseline

- Feature id: `001-aegisai-mvp-foundation`
- Use this feature package as the default implementation target until a narrower feature spec replaces it.

## If You Need Spec Kit Scripts Without Changing Branches

The current git branch is not a Spec Kit feature branch. In a PowerShell session, run:

```powershell
$env:SPECIFY_FEATURE = "001-aegisai-mvp-foundation"
```

This makes Spec Kit scripts resolve the baseline feature directory directly.

## Required Reading Order

1. `spec 2.2.md`
2. `.specify/memory/constitution.md`
3. `specs/001-aegisai-mvp-foundation/spec.md`
4. `specs/001-aegisai-mvp-foundation/plan.md`
5. `specs/001-aegisai-mvp-foundation/tasks.md`

## Non-Negotiable Rules

- Stay inside MVP scope unless the current spec explicitly reclassifies roadmap work.
- Keep repository access in the NestJS backend and analysis behind `IAnalysisApiClient`.
- Do not add direct source upload.
- Java is the only MVP language, but extensibility must stay plugin-based through `ILanguageHandler`.
- Shared API contracts belong in `packages/shared`.
- Sessions, CSRF protection, throttling, health checks, and critical integration tests are required.

## Recommended Execution Order

1. Complete setup and foundational tasks first.
2. Deliver User Story 1 end to end before touching later stories.
3. Add User Story 2 and User Story 3 incrementally.
4. Finish with cross-cutting hardening and quickstart validation.
