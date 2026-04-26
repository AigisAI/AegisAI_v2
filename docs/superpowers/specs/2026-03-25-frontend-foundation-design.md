# Frontend Application Shell and API Foundation Design

## Goal

Implement the Phase 2 frontend foundation so the web app has routing, a protected shell,
typed API access, and shared auth state before feature-specific pages are built.

## Scope

This issue covers:

- React Router application entry and route tree
- Query client and provider setup
- shared Axios API client setup
- auth hook and auth store
- protected route behavior
- shell layout skeleton
- lightweight placeholder pages so the route graph is executable
- tests for the new foundation behavior

This issue does not cover:

- final UI styling
- real login page design
- repository connection UX
- scan request/polling UX

## Architecture

### App Entry

`main.tsx` should render a provider-wrapped `App`. `App` should stay thin and own:

- `QueryClientProvider`
- router rendering
- a minimal React error boundary

This keeps the app entry stable while feature pages expand later.

### Router

The route tree should separate public and authenticated areas:

- `/login` as the public route
- `/dashboard`, `/repos`, `/scan` behind a shared protected shell

For this issue, route targets can stay as lightweight placeholders. The shell and routing
contracts matter more than the final page content.

### Shell

`AppShell` provides:

- sidebar navigation links
- top header with app identity and current user summary
- `Outlet` rendering area

The shell should use minimal CSS only. No Tailwind or design-system work belongs here yet.

### API Foundation

`api/client.ts` should centralize:

- base URL resolution
- `withCredentials: true`
- CSRF header injection for mutating requests
- unauthorized redirect behavior for non-auth bootstrap requests

Feature API modules should depend on this client rather than creating their own instances.

### Auth State

Auth should be split into two layers:

- `auth.store.ts`: durable client-side auth state and helper actions
- `useAuth.ts`: query-powered backend synchronization via `GET /api/auth/me`

The hook should:

- return the current user or `null`
- expose loading state
- expose logout and refresh helpers
- sync query results into the store

### Placeholder Pages

Placeholder route components are acceptable here because the goal is application structure,
not final UX. They should make it obvious which real issue owns each later page.

## Error Handling

- `fetchCurrentUser` should treat backend `401` as unauthenticated state rather than a hard error.
- general API `401` responses should redirect to `/login` unless the current route is already
  `/login` or the request is the auth bootstrap endpoint.
- protected routes should show a simple loading state while auth initialization is in flight,
  then redirect unauthenticated users to `/login`.

## Testing Strategy

Add focused frontend tests for:

- `ProtectedRoute` redirect behavior
- `AppShell` rendering and navigation chrome
- `useAuth` initialization behavior
- API client CSRF injection and unauthorized redirect logic

Keep tests narrow and avoid full feature-page behavior, since those belong to later issues.
