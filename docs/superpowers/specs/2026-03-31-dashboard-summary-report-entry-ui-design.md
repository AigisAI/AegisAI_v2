# Dashboard Summary And Report Entry UI Design

## Scope

Implement the protected `/dashboard` workspace for MVP User Story 3 using the existing Stitch
protected workspace direction as the visual baseline. The page should summarize recent scan signal,
show a light trend view, and let users request or download PDF reports from completed scans without
introducing a new backend dashboard module.

## Design Direction

- Preserve the trust-first editorial security tone already established in the protected Stitch
  screens.
- Reuse the same surface system, hero rhythm, warm neutrals, and restrained blue/brass accents from
  repository, scan, and review pages.
- Avoid introducing a new dashboard-only visual language. The page should feel like the next room in
  the same workspace.

## Data Strategy

- Use existing APIs instead of waiting for a dedicated dashboard endpoint.
- Aggregate dashboard data client-side from:
  - connected repositories
  - recent scan history per connected repository
  - report request/detail endpoints for report entry
- Treat the dashboard as a recent operational snapshot, not an all-time analytics surface.

## Information Architecture

### Hero

- Editorial dashboard headline that frames the page as an operational readout.
- Supporting copy clarifies that the view is based on recent scan activity and report readiness.

### Summary Snapshot

- Show connected repository count.
- Show tracked scan count from loaded repository scan histories.
- Show recent finding volume from the aggregated severity summary.
- Show how many recent scans are report-ready.

### Trend

- Render a compact date-grouped trend view using recent completed scans.
- Focus on critical/high/medium counts rather than decorative charting.

### Recent Scans

- Present recent scans as selectable cards.
- Keep the selected scan as the anchor for the report entry panel.
- Surface status, branch, finding count, and report readiness at card level.

### Report Entry

- Only allow report entry actions for completed scans.
- Support request -> generating -> ready -> download within the same panel.
- Keep vulnerability review as a sibling CTA for completed scans.

## State Model

- `loading`: full dashboard snapshot is being assembled
- `error`: no usable dashboard data could be loaded
- `empty`: no connected repositories
- `degraded`: partial scan history is available but one or more repository histories failed
- `ready`: dashboard snapshot and recent scans are available
- `report generating`: selected completed scan has an active report request
- `report ready`: selected completed scan has a downloadable PDF
- `report failed/expired`: allow a fresh report request from the same panel

## Testing Focus

- Client-side aggregation should sort recent scans correctly and preserve degraded state.
- Dashboard page should render summary/trend/recent scan sections.
- Report request should attach to the selected completed scan and expose download entry once ready.
- Empty and degraded states should remain explicit and actionable.
