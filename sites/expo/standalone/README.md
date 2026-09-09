# Existing-domain deployment

The user selected the existing GitHub CI/CD deployment, so this adapter runs the same two React experiences on the existing Oracle Docker host. `/expo1` is version A and `/expo2` is version B. The Sites development preview and its D1 binding remain separate; this path does not publish to a Sites domain.

- Build: `corepack pnpm build:standalone`
- Validate: `corepack pnpm lint`, `corepack pnpm exec tsc --noEmit`, `corepack pnpm test`, `node tests/standalone-smoke.mjs`
- Container: `standalone/Dockerfile`, Node 24, non-root, port 3100; no public host port.
- Routing: existing web nginx proxies only `/expo1`, `/expo2`, `/expo-assets/`, and `/expo-api/` to `expo:3100`. Existing `/` and `/api/` keep their current handlers.
- Storage: `aegisai-app_expo-interest` Docker volume, `/data/interest.sqlite`, daily `expo_interest(day,count)` aggregate. No contact data or user identifiers; counts are expressions of interest, not unique visitors. Back up this volume if preserving exhibition totals is required.
- Write protection: configured public origin, fixed JSON body, 64-byte bound, same-site HttpOnly cookie, 120 attempts/minute global limiter and 10,000 accepted interests/day. No public aggregate read API.
- Health: `/expo-api/health`; deployment also checks both pages and the existing `/api/health`.

The normal `main` CD workflow builds the additional `aegisai-expo` image, applies the app Compose file and checks the routes. Only the exhibition service initializes its own SQLite table; it does not change scanner database schemas or integration credentials.

For rollback, redeploy the previous release's application image tags and nginx configuration using the established deployment procedure. Keep the exhibition volume so recorded aggregates are retained.
