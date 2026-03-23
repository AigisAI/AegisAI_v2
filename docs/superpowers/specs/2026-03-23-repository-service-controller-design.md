# Repository Service and Controller Design

## Goal

Implement the authenticated repository endpoints needed for the MVP connect-and-scan flow:
listing connected repositories, listing provider repositories, connecting a repository,
disconnecting a repository, and listing branches for a connected repository.

## Scope

- Add `RepoModule`, `RepoService`, and `RepoController`.
- Expose `GET /api/repos`, `GET /api/repos/available`, `POST /api/repos`,
  `DELETE /api/repos/:repoId`, and `GET /api/repos/:repoId/branches`.
- Resolve provider access tokens from persisted OAuth tokens and decrypt them before calling
  provider clients.
- Extend the git provider client interface with a direct repository metadata lookup used by
  `POST /api/repos`.
- Keep scan request/status endpoints out of scope for this issue.

## Design

### API shape

`GET /api/repos` returns connected repositories for the signed-in user, including the latest scan
timestamp and status when available. `GET /api/repos/available` follows the provider-scoped shape
from `spec 2.2.md`: `provider` is required and `page`/`size` are cursor-style pagination inputs.
`POST /api/repos` connects a repository by `provider` + `providerRepoId`, `DELETE /api/repos/:repoId`
returns `204 No Content`, and `GET /api/repos/:repoId/branches` returns provider branches for a
connected repository.

### Service responsibilities

`RepoService` owns five flows:

- `listConnectedRepos`
- `listAvailableRepos`
- `listBranches`
- `connectRepo`
- `disconnectRepo`

The service will fetch the user/provider OAuth token from Prisma, decrypt it with
`TokenCryptoUtil`, resolve the correct provider client from `GitClientRegistry`, and map provider
client errors into HTTP/domain exceptions.

### Provider integration

The current provider client abstraction can list repositories, but `POST /api/repos` needs an
exact repository lookup by `providerRepoId`. This issue extends `IGitProviderClient` with a
`getRepository` operation and implements it in both GitHub and GitLab clients so connection logic
does not depend on paginating through list endpoints.

### Validation and errors

- Unsupported or missing `provider` query/body values return `400`.
- Missing provider connection for the requested provider returns `403`.
- Unknown connected repositories return `404`.
- Duplicate repository connections return `409`.
- Provider 401/404/429/unavailable errors are normalized into structured API errors through the
  existing global exception filter.

## Testing Strategy

- Add service-level tests for token resolution, provider mapping, branch listing, duplicate
  prevention, and disconnect behavior.
- Add e2e coverage for the repository endpoints through the actual controller/runtime path,
  including wrapped success responses and raw `204` disconnect behavior.
- Update shared repo contracts only where the runtime endpoints need additional request/query
  shapes for frontend integration.
