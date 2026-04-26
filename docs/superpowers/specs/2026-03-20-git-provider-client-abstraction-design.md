# Git Provider Client Abstraction Design

## Goal

Implement the backend abstraction layer that normalizes GitHub and GitLab repository access
for later repo connection and scan workflows.

## Scope

- Add `IGitProviderClient` and related result types under `apps/api/src/client/git/`.
- Implement `GithubClient` and `GitlabClient`.
- Add `GitClientRegistry` and `GitClientModule` so later services can resolve provider clients
  through a single dependency.
- Support the provider operations required by the MVP specification:
  - repository listing
  - branch listing
  - latest commit SHA lookup
  - file tree lookup
  - file content lookup
  - optional tarball collection hook
- Add focused tests for provider response normalization, pagination handling, and error mapping.

## Out of Scope

- Repo controller or repo service endpoints
- Persisting `ConnectedRepo` records
- Scan orchestration, code collection, or language filtering
- Frontend provider integration

## Architecture

`GitClientModule` owns the provider-specific HTTP clients and exports a `GitClientRegistry`.
Consumers depend only on the registry and provider strings from `@aegisai/shared`.

Each provider client stays stateless and receives the OAuth access token per call. This keeps
provider access isolated from persistence concerns and lets repo or scan services decide how
tokens are loaded and refreshed.

The interface surface follows the MVP spec directly. That keeps later repo connection and scan
flows from redefining ad-hoc provider DTOs and preserves the backend contract boundary for file
collection.

## Provider Behavior

### GitHub

- Base API: `https://api.github.com`
- Repository listing uses the authenticated user repository endpoint and derives
  `hasNextPage` from the `Link` header.
- Branch listing uses the branches endpoint plus one repository metadata read to determine the
  default branch.
- File content uses the contents API and decodes base64 responses. If a provider response does
  not include a usable default branch or content body, the client throws a typed provider
  error instead of inventing fallback values.

### GitLab

- Base API: `https://gitlab.com/api/v4`
- Project references use URL-encoded full names so later callers can pass a normalized
  `fullName` consistently.
- Repository and branch pagination derives `hasNextPage` from `X-Next-Page`.
- File content uses the raw file endpoint.

## Error Handling

Provider HTTP failures are normalized into typed client errors so later repo and scan layers can
map them consistently to API responses.

- `401` -> token invalid or expired
- `404` -> repository or branch not found / inaccessible
- `403` or `429` -> provider rate limited, with reset metadata included when headers exist
- other failures -> provider unavailable

## Testing Strategy

- Add isolated tests for `GithubClient` and `GitlabClient` with mocked `HttpService`.
- Verify:
  - response normalization to spec result types
  - pagination parsing from provider-specific headers
  - branch default detection
  - file tree and file content mapping
  - typed error translation for auth, not found, and rate limit failures
- Add registry tests for provider lookup and unsupported provider rejection.
