# OAuth Strategies Design

## Goal

Add GitHub and GitLab Passport strategies on top of the existing session-based auth foundation so later auth controller endpoints can initiate OAuth and receive validated users without rebuilding provider-specific logic.

## Scope

This issue only covers:

- GitHub and GitLab Passport strategy classes
- provider profile normalization and persistence in `AuthService`
- `AuthModule` wiring for the new strategies
- focused tests for provider mapping and strategy validation

This issue does not cover:

- auth controller endpoints
- `main.ts` passport/session middleware wiring
- redirect handling after successful OAuth login

## Approach

`AuthService` will gain a provider-aware `findOrCreateUser` flow that:

1. normalizes GitHub/GitLab profile objects into a shared internal shape
2. upserts `User`
3. upserts the encrypted `OAuthToken`
4. returns the shared `AuthUser` session payload

Each strategy will stay thin:

- read credentials and callback URL from config
- enable OAuth `state`
- define provider scopes
- delegate provider profile handling to `AuthService`

## Testing

Tests will cover:

- GitHub profile normalization and persisted `AuthUser` mapping
- GitLab profile normalization and persisted `AuthUser` mapping
- strategy `validate()` delegation to `AuthService`
- strategy configuration expectations such as callback URL, state, and scopes
