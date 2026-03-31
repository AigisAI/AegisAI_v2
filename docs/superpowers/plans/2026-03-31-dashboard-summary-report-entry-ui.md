# Dashboard Summary And Report Entry UI Plan

## Goal

Ship `/dashboard` as the first real User Story 3 surface by composing existing repo, scan, and
report APIs into a Stitch-aligned protected workspace.

## Steps

1. Add frontend report API helpers for request, detail, and download URL handling.
2. Add a dashboard aggregation helper that composes connected repositories and recent repo scan
   histories into a recent snapshot.
3. Replace the dashboard placeholder page with a real workspace UI:
   - hero
   - summary snapshot
   - severity trend
   - recent scans list
   - selected report entry panel
4. Add dashboard-specific styles while preserving the existing protected workspace tone.
5. Add regression coverage for:
   - dashboard aggregation
   - dashboard rendering
   - report request/download entry flow
6. Run frontend verification and then workspace-wide verification.

## Files

- `apps/web/src/api/dashboard.ts`
- `apps/web/src/api/reports.ts`
- `apps/web/src/pages/DashboardPage.tsx`
- `apps/web/src/pages/DashboardPage.test.tsx`
- `apps/web/src/api/dashboard.test.ts`
- `apps/web/src/styles.css`
