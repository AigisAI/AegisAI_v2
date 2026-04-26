# Accumulated PR Review Follow-ups Design

## Goal

Close the still-valid PR review findings that remain on `dev` after the merged feature work, without widening MVP scope.

## Scope

- Auth/session hardening
- Oracle CD workflow and bootstrap runbook hardening
- Git provider client correctness
- Scan/repo robustness
- Frontend auth bootstrap and OAuth link robustness
- Flaky environment-dependent test cleanup

## Non-Goals

- New user-facing features
- New deployment targets
- Re-architecting scan execution or auth flow beyond the reviewed defects

## Fix Areas

### Auth and Runtime

- Treat missing deserialized session users as anonymous instead of middleware errors.
- Ensure the session Redis client is disconnected during application shutdown.
- Use session throttling buckets only for authenticated requests.

### Deployment

- Keep the Oracle bootstrap runbook internally consistent.
- Pin SSH host verification through a secret-backed `known_hosts` entry.
- Always remove remote deploy secrets, even when rollout fails.

### Provider and Scan

- Detect truncated GitHub trees.
- Ignore GitLab submodule commit entries in tree results.
- Make scan duplicate protection resilient to concurrent requests.
- Mark scans as failed when enqueueing fails after persistence.
- Pin code collection to the resolved commit SHA.
- Detect repository duplicates using canonical provider repo ids.
- Reject malformed scan request payloads with 400s instead of 500s.

### Frontend

- Keep auth loading active until store hydration completes.
- Support relative API base URLs when building OAuth entrypoint links.

### Tests

- Remove environment-specific `/api/health` assertions that depend on local Redis state.
