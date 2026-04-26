# Common Backend Behavior Design

## Goal

Build the shared backend behavior primitives that the MVP API depends on: a consistent error
shape, a default response envelope, an explicit raw-response escape hatch, session-aware rate
limit tracking, and a health endpoint that reports API, database, and Redis status.

## Scope

This design covers T016:

- `apps/api/src/common/filters/global-exception.filter.ts`
- `apps/api/src/common/interceptors/response-transform.interceptor.ts`
- `apps/api/src/common/decorators/skip-transform.decorator.ts`
- `apps/api/src/common/guards/session-aware-throttler.guard.ts`
- `apps/api/src/health/health.controller.ts`

Additional supporting files are acceptable when needed for coherent boundaries:

- `apps/api/src/health/health.module.ts`
- targeted tests under `apps/api/test/common/` and `apps/api/test/health/`

Out of scope for this issue:

- `AppModule` registration of `APP_FILTER`, `APP_INTERCEPTOR`, `APP_GUARD`
- global `ThrottlerModule` configuration
- production CORS / trust-proxy tuning
- controller-level usage across the rest of the API

Those integration points stay with T026.

## Current Context

The backend already has:

- config loading with `DATABASE_URL`, `REDIS_URL`, and session settings
- `configureApp()` session / passport middleware setup
- Prisma and Redis dependencies
- shared `SuccessResponse` and `ErrorResponse` contracts in `packages/shared`

The current API still returns raw controller payloads and does not expose `/api/health`, so this
issue is about creating the reusable pieces and locking down their behavior with tests before
global wiring lands.

## Proposed Architecture

### GlobalExceptionFilter

`GlobalExceptionFilter` converts thrown errors into the shared `ErrorResponse` shape:

- `success: false`
- `data: null`
- `message`
- `errorCode`
- `timestamp`

`HttpException` payloads keep their status code and can provide a custom `errorCode`. Unknown
errors fall back to `500 INTERNAL_ERROR`. Server errors are logged with `Logger`.

### ResponseTransformInterceptor

`ResponseTransformInterceptor` wraps successful controller results in the shared `SuccessResponse`
shape:

- `success: true`
- `data`
- `message: null`
- `timestamp`

The interceptor skips wrapping when:

- the handler or controller has `@SkipTransform()`
- the HTTP status is `204`
- the handler returned `undefined`

This keeps health responses, empty responses, and future binary/file responses raw.

### SkipTransform Decorator

`SkipTransform()` is a small metadata decorator used by the interceptor. It exists so raw-response
routes are explicit in code rather than being hidden in interceptor heuristics.

### SessionAwareThrottlerGuard

`SessionAwareThrottlerGuard` extends Nest throttling behavior so the tracker key becomes:

- `req.sessionID` for authenticated/session-backed requests
- `req.ip` for unauthenticated requests

This matches the product requirement that signed-in users are rate-limited by session identity
instead of all sharing an IP bucket behind the same proxy.

### HealthController

`HealthController` exposes `GET /api/health` and always uses `@SkipTransform()`.

Response shape:

```json
{
  "status": "ok" | "degraded",
  "uptime": 123.45,
  "services": {
    "database": "up" | "down",
    "redis": "up" | "down"
  },
  "timestamp": "ISO-8601"
}
```

Behavior:

- Prisma health is checked with a lightweight query
- Redis health is checked with a short-lived client `PING`
- if either dependency is down, the response becomes `degraded`
- the endpoint remains `200` with raw JSON so orchestrators can read a stable contract

## File Responsibilities

- `global-exception.filter.ts`: error normalization and logging
- `response-transform.interceptor.ts`: success envelope wrapping and raw bypass logic
- `skip-transform.decorator.ts`: metadata marker only
- `session-aware-throttler.guard.ts`: tracker selection policy
- `health.controller.ts`: health response composition and dependency checks
- `health.module.ts`: controller wiring boundary for later import into `AppModule`

## Testing Strategy

Implementation will stay test-first:

- filter tests for `HttpException` and unexpected error normalization
- interceptor tests for wrapped success responses and raw bypass behavior
- throttler guard tests for session-vs-IP tracker selection
- health controller tests for `ok` vs `degraded` responses and raw contract shape

These tests can be run without global app wiring, which keeps T016 scoped to primitives while
still proving the intended behavior before T026 integrates them.
