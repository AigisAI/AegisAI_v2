# Quickstart: AegisAI Platform MVP Foundation

## Goal

Use this feature package as the single starting point for implementation agents. The docs
here already condense `spec 2.2.md` into execution-ready artifacts.

## Read Order

1. `spec 2.2.md`
2. `.specify/memory/constitution.md`
3. `specs/001-aegisai-mvp-foundation/spec.md`
4. `specs/001-aegisai-mvp-foundation/plan.md`
5. `specs/001-aegisai-mvp-foundation/tasks.md`

## If You Want To Use Spec Kit Scripts On The Current Branch

The repository is not currently checked out to a `001-...` style feature branch. In the
current PowerShell session, set:

```powershell
$env:SPECIFY_FEATURE = "001-aegisai-mvp-foundation"
```

This makes Spec Kit scripts resolve the baseline feature directory without forcing a branch
switch.

## Recommended Execution Order

1. Complete Phase 1 and Phase 2 tasks from `tasks.md`.
2. Deliver User Story 1 end to end before touching later stories.
3. Validate auth, repo connection, queued scan execution, and scan polling.
4. Move to User Story 2 for vulnerability review and feedback.
5. Finish with dashboard plus PDF reporting in User Story 3.
6. Run the final validation and documentation tasks before starting roadmap work.

## First Commands Once The Workspace Exists

```powershell
pnpm install
pnpm dev
pnpm lint
pnpm test
```

## Implementation Notes

- Treat `MockAnalysisApiClient` as the default implementation target.
- Keep `apps/ai` optional and behind interfaces.
- Preserve `packages/shared` as the shared contract source of truth.
- Do not import roadmap work into MVP acceptance unless the spec changes.
