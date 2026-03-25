# Scan Controller Request/Status Design

## Goal

Implement the User Story 1 scan API surface so authenticated users can request scans,
poll scan status, and view scan history for a connected repository.

## Scope

This issue covers:

- `POST /api/scans`
- `GET /api/scans/:scanId`
- `GET /api/repos/:repoId/scans`
- supporting `ScanService` query behavior needed by those endpoints
- tests for controller and service behavior

This issue does not cover:

- vulnerability listing endpoints
- frontend scan page and polling UX
- report generation

## API Shape

### `POST /api/scans`

- Requires an authenticated session.
- Accepts `{ repoId, branch }`.
- Returns HTTP `202` with `ScanRequestResponse`.
- Validates:
  - `repoId` is present
  - `branch` is present after trimming
  - the connected repo belongs to the current user
  - the branch exists in the provider before creating the scan row
  - no active scan already exists for the same repo/branch

Branch existence is verified through the provider client by resolving the connected repo,
provider token, and latest commit for the requested branch before the scan row is inserted.

### `GET /api/scans/:scanId`

- Requires an authenticated session.
- Returns a single `ScanDetail`.
- Enforces ownership through `scan -> connectedRepo -> userId`.
- Maps Prisma scan rows into the shared contract shape with severity summary fields.

### `GET /api/repos/:repoId/scans`

- Requires an authenticated session.
- Returns `PageResponse<ScanSummary>`.
- Uses fixed ordering `createdAt desc`.
- Enforces ownership through `ConnectedRepo.userId`.
- Supports `page` and `size` query params with the same validation style as repo endpoints.

## Service Design

`ScanService` remains the single scan application service for this phase.

New responsibilities:

- `createScan(...)`
  - trim and validate the branch
  - resolve connected repo ownership
  - verify branch existence through the provider client
  - reject duplicate active scans
  - create the scan row and enqueue the job
- `getScanDetail(...)`
  - fetch a scan scoped to the current user
  - return shared `ScanDetail`
- `listRepoScans(...)`
  - verify repo ownership
  - return paginated `ScanSummary` rows

Internal helpers should centralize:

- ownership-scoped scan mapping
- scan summary projection
- provider token resolution for branch validation

## Error Handling

- missing `repoId` or blank `branch` -> `400 BAD_REQUEST`
- branch not found in provider -> `400 BRANCH_NOT_FOUND`
- connected repo not found for user -> `404 REPO_NOT_FOUND`
- scan not found for user -> `404 SCAN_NOT_FOUND`
- active scan already exists -> existing `409 Conflict`
- provider token invalid / unavailable / rate limited -> reuse existing provider error mapping patterns

The controller should stay thin and let the existing global exception/response wiring wrap results.

## Testing Strategy

Add or extend:

- service tests for branch validation, scan detail mapping, and repo scan pagination
- controller e2e tests for:
  - `POST /api/scans` success and validation failure
  - `GET /api/scans/:scanId`
  - `GET /api/repos/:repoId/scans`

Tests should follow the existing `RepoController` and `ScanService` patterns and keep
queue/runtime behavior mocked at the service boundary.
