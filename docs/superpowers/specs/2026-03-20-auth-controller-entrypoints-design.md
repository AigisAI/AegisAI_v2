# Auth Controller and OAuth Entrypoints Design

## Goal

Implement the backend auth entrypoints that turn the existing session foundation and OAuth
strategies into a usable login flow.

## Scope

- Add `AuthController` endpoints for:
  - `GET /api/auth/github`
  - `GET /api/auth/github/callback`
  - `GET /api/auth/gitlab`
  - `GET /api/auth/gitlab/callback`
  - `GET /api/auth/me`
  - `POST /api/auth/logout`
- Wire `main.ts` to initialize cookies, Redis-backed sessions, and Passport session support.
- Wire `AppModule` so the API bootstraps `ConfigModule`, `PrismaModule`, and `AuthModule`.
- Add auth integration coverage for `me`, `logout`, and OAuth callback redirect behavior.

## Out of Scope

- Repository, scan, dashboard, and report modules
- Frontend route or hook implementation
- Global response transform / exception filter work from later foundational tasks

## Architecture

`AuthController` stays thin and delegates identity loading to the existing session user
surface. OAuth start and callback routes rely on Passport provider guards, while callback
handlers are responsible only for issuing a CSRF cookie and redirecting to
`FRONTEND_URL/dashboard`.

`main.ts` becomes the runtime assembly point for session middleware ordering:
`session -> passport.initialize() -> passport.session()`. The session store uses Redis via
`connect-redis`, and request cookies are parsed through `cookie-parser` so `SessionAuthGuard`
can validate CSRF headers against the issued CSRF cookie.

## Data Flow

1. Browser hits `GET /api/auth/github` or `GET /api/auth/gitlab`.
2. Passport strategy redirects to the provider.
3. Provider callback authenticates and serializes the user into the server session.
4. Callback handler issues a CSRF cookie and redirects to `FRONTEND_URL/dashboard`.
5. `GET /api/auth/me` returns the current session user and refreshes the CSRF cookie.
6. `POST /api/auth/logout` requires `SessionAuthGuard`, destroys the session, clears cookies,
   and returns `null`.

## Testing Strategy

- Add `apps/api/test/auth/auth.e2e-spec.ts` for controller-level behavior.
- Cover:
  - unauthenticated `GET /api/auth/me` -> `401`
  - authenticated `GET /api/auth/me` -> session user + CSRF cookie
  - authenticated `POST /api/auth/logout` with matching CSRF -> `200` + cleared cookies
  - OAuth callback success path -> redirect to `FRONTEND_URL/dashboard` + CSRF cookie
- Keep provider strategies mocked/stubbed in tests so controller and middleware wiring are the
  focus.
