# Login Screen and Auth Flow UI Design

## Goal

Implement the first real frontend UI for the MVP by replacing the login placeholder with a
designed login screen that starts the GitHub and GitLab OAuth flows and clearly represents
auth bootstrap, success redirection, and error recovery states.

## Scope

This issue covers only the login screen and auth flow UI.

In scope:
- A designed `LoginPage`
- GitHub and GitLab login CTAs
- Auth bootstrap and redirect behavior on `/login`
- Friendly loading and retry states tied to `useAuth`
- Lightweight auth error messaging on the login page
- Focused frontend tests for login UI and route behavior

Out of scope:
- Repository connection UX
- Scan request/polling UX
- Dashboard visual redesign
- Cross-app design system expansion beyond what the login screen needs

## Recommended Approach

Use a single-screen hero layout with two provider CTA buttons, one short product value
statement, and a compact auth state panel. This keeps the UI intentional and branded without
starting a broader redesign too early.

Why this approach:
- It gives the first user-facing page a real visual identity.
- It matches the backend's existing OAuth entrypoints without introducing extra frontend
  state machines.
- It preserves the current `AppShell` and route foundation instead of rebuilding routing.

## User Flow

### Unauthenticated

When an unauthenticated user visits `/login`, the page shows:
- Product headline and short explanation
- GitHub login button
- GitLab login button
- Short note that repository access uses provider OAuth

Clicking a provider button sends the browser to:
- `/api/auth/github`
- `/api/auth/gitlab`

using the configured API base URL.

### Auth Bootstrap

When the app is still checking the current session:
- `/login` should show a deliberate loading state instead of the generic placeholder copy.
- Protected routes should continue to use the existing `ProtectedRoute` loading behavior.

### Already Authenticated

When the user already has a session and opens `/login`, redirect them to `/dashboard`
instead of leaving them on the login screen.

### Failure / Retry

The backend currently redirects successful OAuth callbacks to `/dashboard`.
This UI issue does not require backend callback changes, but the login page may passively
render a lightweight failure hint when a querystring such as `?error=oauth_failed` is
already present.

That means the frontend may:
- Read a querystring hint such as `?error=oauth_failed` when present
- Rendering a compact inline error message
- Leaving the same provider buttons available for retry

The frontend should not depend on a new backend error-redirect contract in this issue.

### Session Bootstrap Failure

When `GET /api/auth/me` fails because of a transient network or server problem:
- The login page should stop the spinner
- The provider CTAs should still remain available
- A lightweight inline message should explain that the existing session could not be
  verified and the user can try signing in again

## UI Structure

`LoginPage` will be split into focused blocks:
- Hero copy block
- Provider action card
- Small trust/info strip for session/repository access notes

Visual direction:
- Preserve the warm editorial palette already introduced in `styles.css`
- Make the login page feel more intentional than the placeholder
- Keep the rest of the application untouched

The page should remain mobile-safe and work well in one-column layouts.

## Component and Hook Changes

### `apps/web/src/pages/LoginPage.tsx`

Responsibilities:
- Render the login hero and provider CTAs
- Redirect authenticated users to `/dashboard`
- Display auth bootstrap loading and querystring error state

### `apps/web/src/hooks/useAuth.ts`

Enhancements:
- Expose enough query state for the login page to distinguish initial loading from ready state
- Keep existing logout and refresh behavior unchanged

### `apps/web/src/router.tsx`

Keep the route map simple:
- `/login` remains public
- Protected routes stay under `ProtectedRoute`
- No route tree expansion is needed for this issue

### `apps/web/src/styles.css`

Add only the styles needed for:
- Login hero layout
- Provider buttons
- Loading and error message presentation

## Testing Strategy

Add focused tests for:
- Login page renders provider CTAs
- Authenticated user on `/login` is redirected to `/dashboard`
- Unauthenticated user sees login UI
- Querystring error hint is rendered
- Loading state is rendered during auth bootstrap
- Session bootstrap failure is rendered as retry guidance instead of an endless loading state

Testing should stay close to the UI and router behavior rather than snapshot-heavy.

## Risks and Guardrails

- Do not let login-page styling spread into a premature redesign of dashboard/repos/scan pages.
- Do not add frontend-only auth state that conflicts with the existing session bootstrap flow.
- Keep provider URLs derived from the current API client/base URL conventions.
