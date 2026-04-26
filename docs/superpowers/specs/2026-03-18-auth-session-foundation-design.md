# Auth And Session Foundation Design

**Issue**: `#31`  
**Title**: `Feat: auth and session foundation ±¸Çö`  
**Date**: `2026-03-18`

## Goal

Add the backend auth/session core infrastructure needed before OAuth provider strategies and
full bootstrap wiring, while keeping the issue aligned to `T010` only.

## Scope

- Create `apps/api/src/auth/auth.module.ts`
- Create `apps/api/src/auth/auth.service.ts`
- Create `apps/api/src/auth/auth.serializer.ts`
- Create `apps/api/src/auth/guards/session-auth.guard.ts`
- Create `apps/api/src/auth/decorators/current-user.decorator.ts`
- Create `apps/api/src/auth/utils/token-crypto.util.ts`
- Add focused tests for serializer, session guard, and token crypto behavior

## Recommended Approach

Keep `#31` as a narrow auth infrastructure slice and defer OAuth strategies and global
middleware setup to later issues.

- `AuthModule` owns the auth runtime boundary and exports the reusable pieces needed by
  later controllers and strategies
- `AuthService` provides user lookup methods for session deserialization and a CSRF token
  helper for later controller integration
- `AuthSerializer` implements the required Passport session serializer/deserializer so later
  OAuth login can persist sessions correctly
- `SessionAuthGuard` centralizes session presence checks and CSRF validation for mutating
  requests
- `CurrentUser` exposes the authenticated user object from `req.user`
- `TokenCryptoUtil` encapsulates AES-256-GCM encryption and decryption for provider tokens

This gives the backend a clean auth/session core without pulling `main.ts` Redis session
store setup, OAuth strategies, or full app wiring into the same issue.

## Alternatives Considered

### 1. Include `main.ts` session middleware wiring now

- Pros: more visible progress toward login flow
- Cons: mixes `T010` with later bootstrap work and pulls Redis/session store concerns into
  the wrong issue boundary

### 2. Implement OAuth strategies together with auth core

- Pros: fewer follow-up issues before login works end to end
- Cons: collapses `T010` and `T011`, increases dependency surface, and makes review harder

## Non-Goals

- No GitHub or GitLab Passport strategies
- No `AuthController` endpoints yet
- No `main.ts` session middleware, Redis store, or Passport bootstrap wiring
- No `AppModule` integration beyond what later issues will handle

## Validation

- Targeted tests prove token encryption round-trips, serializer behavior, and CSRF/session
  guard decisions
- Workspace `lint`, `test`, `typecheck`, and `build` stay green
