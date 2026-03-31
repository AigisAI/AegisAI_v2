# Completion Hardening And Documentation Sync Design

## Goal

Bring the repository entrypoint docs and MVP completion gates back into sync with the code that has already landed across US1, US2, and US3.

## Current Gaps

- `specs/001-aegisai-mvp-foundation/tasks.md` still shows several report and dashboard tasks as incomplete even though the implementation and tests already exist.
- `AGENTS.md` is missing the current frontend design tooling guardrail that the team now follows.
- `quickstart.md` describes the execution flow well, but its completion path does not explicitly anchor a hardening review artifact or the final validation command set.
- Completion status is currently inferred by humans instead of being backed by a small regression test that checks the canonical docs.

## Approach

1. Add a dedicated MVP hardening review document inside the feature package so the Phase 6 security and behavior review has a concrete artifact.
2. Update `README.md`, `AGENTS.md`, and `quickstart.md` so they all point to the same completion flow and validation commands.
3. Rewrite stale task descriptions in `tasks.md` to match the actual file boundaries that shipped, then mark the now-complete tasks accordingly.
4. Add a repository-level regression test that reads the canonical docs and fails if the completion gate drifts again.

## Acceptance Criteria

- Canonical entrypoint docs describe the same execution and completion flow.
- `tasks.md` reflects the current implementation state for report, dashboard, and Phase 6 completion work.
- The new hardening review doc covers sessions, CSRF, throttling, health responses, report expiry, queue recovery, provider errors, and frontend error states.
- A test fails if the completion docs lose the expected validation commands or hardening references.
