# Backend Global Wiring Design

## Goal

Wire the backend modules and global middleware that were built in earlier issues into the
actual Nest application so runtime behavior matches the MVP contracts.

## Scope

- Register `ScanModule` and `HealthModule` in the application root.
- Add BullMQ root configuration for the scan queue.
- Add throttling module configuration for session-aware rate limiting.
- Register the global exception filter, response transform interceptor, and session-aware
  throttler guard through Nest `APP_*` providers.
- Preserve raw `/api/health` responses while wrapping standard API success responses in the
  shared envelope.
- Keep repository and scan controllers out of scope for this issue.

## Design

### App root wiring

`AppModule` becomes the place where cross-cutting runtime behavior is assembled. It will import
the existing auth, config, Prisma, provider-client, language, analysis, scan, and health
modules, then add `BullModule.forRootAsync` and `ThrottlerModule.forRoot`.

### Global behavior

The filter, interceptor, and guard already exist as focused units. This issue only attaches them
to the application globally:

- `GlobalExceptionFilter` normalizes framework and domain errors.
- `ResponseTransformInterceptor` wraps successful responses except opt-out routes.
- `SessionAwareThrottlerGuard` applies per-session tracking for authenticated users and per-IP
  tracking for anonymous users.

### Health behavior

`GET /api/health` must remain raw JSON even after global response wrapping is enabled. The
existing `@SkipTransform()` decorator stays the escape hatch for this route.

### Bootstrap concerns

`configureApp` remains the entry point for session, cookie-parser, and Passport setup. Any small
bootstrap cleanup required for proxy-aware cookies or consistent middleware ordering belongs
there, but application composition stays in `AppModule`.

## Testing Strategy

- Update app e2e coverage to assert the root route is wrapped in the shared success envelope.
- Add app e2e coverage to assert `/api/health` remains raw JSON.
- Update auth e2e coverage to assert unauthorized and authenticated auth responses flow through
  the global filter/interceptor correctly.
- Keep common unit-level tests intact as focused regressions for the individual components.
