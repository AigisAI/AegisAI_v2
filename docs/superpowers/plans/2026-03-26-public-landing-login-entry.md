# Public Landing Page And Login Entry Flow Plan

## Issue

- `#77` `Feat: public landing page and login entry flow 구현`

## Plan

1. Add landing page and router tests that describe the new public entry structure before changing implementation.
2. Implement a dedicated `LandingPage` and expose public `/` and `/login` routes while keeping protected routes behind the existing shell.
3. Refactor `LoginPage.tsx` and shared styles to match the approved landing-plus-access split.
4. Re-run targeted web tests, then run workspace validation (`lint`, `test`, `typecheck`, `build`).
