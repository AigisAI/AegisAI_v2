# #85 Scan Flow Guardrails And UX Polish Design

## Summary

This follow-up closes the usability gap between the repository connection workspace and the scan request/status workspace. The focus is not a new visual language. The focus is preserving the existing Stitch-led protected workspace tone while tightening user guidance around repository selection, branch readiness, active scan duplication, and empty-state recovery.

## Goals

- Preserve the current protected Stitch aesthetic and only apply minimal UX-driven adjustments.
- Reduce dead-end states between `/repos` and `/scan`.
- Prevent duplicate scan requests for the same repository branch when an active scan already exists.
- Make empty, branch-missing, active, failed, and idle scan states easier to understand.

## Non-Goals

- No new dashboard information architecture.
- No wizard-style scan creation flow.
- No backend contract changes unless a frontend edge case requires it.
- No broad redesign of the repository and scan pages beyond guardrail and polish work.

## UX Direction

### Repository To Scan Continuity

The branch insight area on `/repos` should now act as the last checkpoint before analysis. Once a connected repository is selected and its branch metadata is visible, the UI should expose an obvious `Open scan workspace` path into `/scan` using the selected repository as context.

### Scan Request Guardrails

The request area on `/scan` should distinguish four cases:

1. No repositories connected: show a connect-first empty state with a direct link back to `/repos`.
2. Repository has no branch metadata: disable the scan action and explain that repository metadata must be restored before queueing.
3. An active scan already exists for the selected branch: do not encourage another queue action. Offer a `View active scan` action instead.
4. Ready state: allow a normal Java scan request.

### Selected Scan Narrative

The selected scan status card should not only show structured data. It should also explain what the current status means:

- `PENDING`: queued and waiting for snapshot collection
- `RUNNING`: already in progress, duplication discouraged
- `DONE`: ready for follow-up review
- `FAILED`: requeue only after provider access is healthy again

## Testing Strategy

- Add a repository page regression that ensures the selected connected repository links into the scan workspace.
- Add scan page regressions for:
  - duplicate active scan handling
  - repository query-parameter bootstrapping
  - connect-first empty state recovery
  - missing branch metadata guardrail
  - switching away from a seeded repository context
  - ignoring stale repository query parameters

## Stitch Note

The guardrail pass keeps the existing Stitch-derived protected workspace tone intact. This issue does not request a fresh manual redesign. Changes should remain limited to CTA placement, state messaging, and structural polish necessary for the scan flow to feel coherent in production use.
