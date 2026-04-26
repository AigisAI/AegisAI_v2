# Scan Request And Status Page Design

## Context

- Issue: `#83`
- Existing protected shell and route already exist at `/scan`
- Frontend design work must use Stitch as the primary design source
- Design context follows the established AegisAI editorial security direction from prior frontend issues
- Closest Stitch protected-screen reference:
  - Project: `projects/861350607109533974` (`AegisAI Login Auth UI`)
  - Source screen: `projects/861350607109533974/screens/3670ddbf00c14519a6b248b60f6e4b83` (`Repositories Workspace`)

## Stitch Usage Notes

- Fresh Stitch generation for a dedicated scan screen was attempted in the existing editorial project and in a new temporary project.
- Those generation calls returned invalid-argument and timeout failures.
- To preserve the mandatory Stitch-first workflow, the final page design uses the existing protected `Repositories Workspace` Stitch screen as the visual baseline and adapts its body composition into a scan orchestration workspace.

## Goals

- Replace the placeholder `/scan` page with a real request-and-status workspace
- Let a signed-in user:
  - choose a connected repository
  - choose a branch
  - queue a Java scan
  - inspect recent scan history
  - read the selected scan status without leaving the page
- Preserve the same calm editorial tone already established for login and repository connection

## Design Direction

- Keep the protected app shell unchanged
- Reuse the Stitch protected workspace composition language:
  - strong editorial hero
  - asymmetric main/aside layout
  - soft paper surfaces
  - restrained brass emphasis
- Shift the page body from repository connection to scan orchestration

## Page Structure

### Hero

- Kicker: `Scan orchestration`
- Headline centered on deliberate, controlled review flow
- Supporting copy about branch snapshot analysis and severity summaries
- Decorative side panel kept as a premium anchor

### Main Column

- Scan request section
  - connected repository selector
  - repository selector field
  - branch selector field
  - Java-first action hint
  - primary queue CTA
  - inline success and request-error states
- Recent scans section
  - latest scan history for the selected repository
  - selectable scan cards
  - severity chips and status pills

### Aside Column

- Selected scan status panel
  - branch
  - commit
  - files
  - lines
  - total findings
  - severity matrix
  - failed-scan message if present
- Privacy protocol panel
  - read-only repository access
  - branch-scoped Java analysis
  - no source-content exposure in the UI

## Runtime Behavior

- Connected repositories load on entry
- The first connected repository becomes the active repo by default
- Branches and recent scans follow the active repository
- The selected scan detail follows the active scan card
- New scan requests invalidate scan history and refresh detail state
- Active scans poll until they settle out of `PENDING` / `RUNNING`

## Constraints

- Keep the route at `/scan` to match the current protected app shell
- Do not introduce backend changes in this issue
- Keep Stitch as the visual source of truth, using the nearest protected workspace screen when fresh generation is unavailable
- Preserve accessible labels and programmatic pressed state for repository and scan selection controls
