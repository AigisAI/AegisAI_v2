# Repository Connection Page Design

## Context

- Issue: `#81`
- Frontend design work must use Stitch as the primary design source
- Existing protected shell from `#64` and `#79` remains the outer frame
- Stitch project: `projects/11276866576122067718` (`AegisAI Public Entry V2`)
- Source screens explored for this issue:
  - Mobile repository connection: `projects/11276866576122067718/screens/d6451bb934ca4788be72465093268bef`
  - Desktop repository connection: `projects/11276866576122067718/screens/6b8143ea99f843e098d9b0ef4c91ad94`
  - Connected-state exploration: `projects/11276866576122067718/screens/91016a2a38184a379dba7be1ff715662`

## Goals

- Turn `/repositories` into a real connection workspace instead of a placeholder
- Preserve the Stitch editorial tone and composition as much as possible
- Connect the screen to the existing repo APIs without redesigning the protected shell
- Make provider filtering, connect, disconnect, and branch insight legible in one surface

## Design Direction

- Keep the existing app shell chrome and transplant the Stitch repository experience into the page body
- Preserve the strongest Stitch motifs:
  - editorial hero copy
  - provider-driven connection surface
  - privacy and trust messaging
  - asymmetrical side content
- Remove only the parts that would duplicate the existing app shell, such as the extra left registry navigation

## Page Structure

### Hero

- Kicker: `Connection hub`
- Headline: `Begin the Archive`
- Supporting copy focused on read-only scanning and controlled access
- Decorative secured panel kept as a visual anchor

### Toolbar

- Provider filter buttons for GitHub and GitLab
- Secondary copy that explains the filtering behavior

### Main Column

- Connected repositories section
  - existing connections
  - selection state for branch insight
  - disconnect action
- Available repositories section
  - filtered by active provider
  - connected chip for already-linked sources
  - connect action for ready sources

### Aside Column

- Branch insight panel for the selected connected repository
- Privacy protocol panel that reinforces the trust model and non-persistence rules

## Runtime Behavior

- Connected repositories are loaded on page entry
- Available repositories are re-fetched when the provider filter changes
- Branch insight follows the selected connected repository
- Connect and disconnect actions invalidate the connected and available queries
- Empty, loading, and error states stay visible inside their relevant sections rather than through modals

## Constraints

- Do not redesign the app shell itself in this issue
- Do not introduce new backend endpoints
- Keep Stitch output as the visual source of truth and only make implementation-driven adjustments
- Preserve accessible button labels, section landmarks, and responsive behavior
