# Landing Page And Login Access Page V2 Design

## Context

- Issue: `#79`
- Baseline route structure already exists in `dev` from `#78`
- Frontend design work must use Stitch as the primary design source
- Stitch project: `projects/11276866576122067718` (`AegisAI Public Entry V2`)
- Source screens:
  - Landing: `projects/11276866576122067718/screens/7219b633e6164a708da23fb258d37270`
  - Login access: `projects/11276866576122067718/screens/a2a9f15a63e84cacaa5d6d758f23429f`

## Goals

- Align the public entry flow with the newer Stitch V2 editorial direction
- Preserve Stitch structure, composition, and visual tone as much as possible in code
- Keep existing auth behavior, route behavior, and provider CTA wiring intact

## Design Direction

- Landing page stays at `/` and becomes a clearer editorial product page
- Login access page stays at `/login` and becomes a compact secure access portal
- The public visual language should feel like a premium security publication rather than an admin dashboard
- Code changes should only diverge from Stitch where runtime behavior requires it

## Landing Page Structure

- Fixed public top navigation with brand, product links, login, and GitHub CTA
- Editorial hero with a stronger headline, supporting narrative, and dual provider CTAs
- Trust strip for brand credibility
- Three-step workflow section
- Security pull-quote section with supporting code sample panel
- Final CTA section and refined footer

## Login Access Page Structure

- Minimal top navigation with brand and lightweight public links
- Large editorial headline centered on secure provider access
- Central access card with GitHub and GitLab CTA rows
- Runtime-only states preserved inside the card:
  - loading
  - OAuth failure
  - session bootstrap failure
  - authenticated redirect
- Trust chips remain visible even when the auth state is neutral

## Constraints

- Do not redesign protected app shell screens in this issue
- Do not change backend auth or OAuth endpoints
- Keep `getProviderLoginUrl()` as the source of provider CTA destinations
- Keep accessibility and responsive behavior intact
- Keep Stitch output as the visual source of truth and only make implementation-driven adjustments
