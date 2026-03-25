# Quickstart: AegisAI Platform MVP Foundation

## Goal

Use this feature package as the single starting point for implementation agents. Follow this
document first, then move through the linked docs in order instead of jumping straight to
`tasks.md`.

## Canonical Use

- Agents should arrive here from [`AGENTS.md`](../../AGENTS.md).
- This document is the single source of truth for execution order and completion flow.
- Use the feature package docs below to execute the MVP without reconstructing scope from
  scratch.

## Document Map

- `spec 2.2.md`: full product baseline and architecture source of truth
- `.specify/memory/constitution.md`: repository-level implementation guardrails
- `spec.md`: MVP scope, user stories, requirements, and success criteria
- `research.md`: key technical decisions and rejected alternatives
- `data-model.md`: entities, relationships, and state transitions
- `contracts/analysis-api.md`: backend-to-analysis integration boundary
- `plan.md`: implementation approach and project structure
- `tasks.md`: execution-ordered task list
- `checklists/requirements.md`: spec quality audit trail

## Required Read Order

1. `spec 2.2.md`
2. `.specify/memory/constitution.md`
3. `specs/001-aegisai-mvp-foundation/spec.md`
4. `specs/001-aegisai-mvp-foundation/research.md`
5. `specs/001-aegisai-mvp-foundation/data-model.md`
6. `specs/001-aegisai-mvp-foundation/contracts/analysis-api.md`
7. `specs/001-aegisai-mvp-foundation/plan.md`
8. `specs/001-aegisai-mvp-foundation/tasks.md`
9. `specs/001-aegisai-mvp-foundation/checklists/requirements.md`

## Execution Flow

1. Read the baseline and feature docs in the required order above.
2. Complete Phase 1 and Phase 2 tasks from `tasks.md` before starting user stories.
3. Deliver User Story 1 end to end and validate auth, repo connection, queued scan execution, and scan polling.
4. Add User Story 2 for vulnerability review and feedback.
5. Add User Story 3 for dashboard visibility and PDF export.
6. Finish with Phase 6 hardening, quickstart command validation, and documentation sync.

## Fast Path For Repeat Visitors

If you already know the MVP architecture and only need execution detail, re-read `spec.md`,
`plan.md`, and `tasks.md`, then use the supporting docs only when the task touches contracts,
entities, or architectural constraints.

## If You Want To Use Spec Kit Scripts On A GitHub-Style Branch

The repository may be checked out to a GitHub-style branch such as
`feat/<issue-number>-<short-feature>`. In the current PowerShell session, set:

```powershell
$env:SPECIFY_FEATURE = "001-aegisai-mvp-foundation"
```

This makes Spec Kit scripts resolve the baseline feature directory without forcing a branch
name change.

## Completion Gate

Before claiming the MVP baseline is ready:

1. Re-run the final validation and documentation tasks from `tasks.md`.
2. Re-check [`checklists/requirements.md`](./checklists/requirements.md) to confirm the implementation still matches the approved feature baseline.
3. Verify that the startup commands below still match the workspace reality.
4. Update `README.md` and `AGENTS.md` if the canonical execution path changed while implementing.

## First Commands Once The Workspace Exists

```powershell
corepack pnpm install
corepack pnpm dev
corepack pnpm lint
corepack pnpm test
```

## Implementation Notes

- Treat `MockAnalysisApiClient` as the default implementation target.
- Keep `apps/ai` optional and behind interfaces.
- Preserve `packages/shared` as the shared contract source of truth.
- Do not import roadmap work into MVP acceptance unless the spec changes.
- Return to `research.md`, `data-model.md`, and `contracts/analysis-api.md` whenever a task
  affects architecture boundaries or shared contracts.
