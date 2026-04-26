# Dashboard Backend Module Design

## Context

`#110` delivered the dashboard UI, but the web app was still stitching together connected repositories,
repo scan history, and report entry state client-side. `#112` moves that aggregation into the NestJS
backend so the dashboard becomes a single owned API contract instead of a frontend orchestration layer.

## Goal

Add a `GET /api/dashboard` endpoint that returns the exact workspace shape the current dashboard UI
consumes: connected repositories, recent scans, completed scans, severity summary, trend items, and
top-level counts.

## Design

### Backend module

- Add `apps/api/src/dashboard/dashboard.module.ts`
- Add `DashboardService` for aggregation logic
- Add `DashboardController` with `GET /api/dashboard`
- Wire `DashboardModule` into `AppModule`

### Aggregation strategy

- Source connected repositories from `ConnectedRepo` ordered by `connectedAt desc`
- Include the latest scan metadata per repository so the dashboard can show repository state
- Source recent scans from `Scan` ordered by `createdAt desc`, limited to the dashboard window
- Source trend data from recent completed scans ordered by `completedAt desc`, then bucket by UTC day
- Calculate severity summary from the recent scan window and reuse it for both `openVulnerabilities`
  and `severitySummary`
- Return `degraded: false` because this backend contract reads from local persisted data only

### Contract

- Promote the current frontend-only `DashboardWorkspaceData` shape into `packages/shared`
- Keep the existing dashboard UI shape stable so `DashboardPage` does not need layout changes
- Update the OpenAPI contract so `/dashboard` documents the richer workspace payload

### Frontend integration

- Replace the client-side fan-out logic in `apps/web/src/api/dashboard.ts`
- Make `getDashboardWorkspaceData()` a thin fetch wrapper over `/dashboard`
- Leave `DashboardPage.tsx` intact so Stitch-derived presentation stays unchanged

## Testing

- Add backend service tests for aggregation and empty-state behavior
- Add controller e2e coverage for wrapped `/api/dashboard` responses
- Rewrite the frontend dashboard API helper test to assert `/dashboard` usage
- Keep OpenAPI contract coverage updated for the new endpoint
