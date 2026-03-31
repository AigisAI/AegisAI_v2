# MVP Hardening Review

## Purpose

This document records the security and behavior review that closes Phase 6 for the shipped MVP baseline. It anchors the completion gate to concrete code paths and regression coverage instead of relying on tribal knowledge.

## Sessions

- Session creation and storage are configured in `apps/api/src/bootstrap/configure-app.ts`.
- Runtime environments use Redis-backed sessions; non-runtime test environments fall back to `MemoryStore` to avoid false infrastructure coupling.
- Session cleanup is verified by `apps/api/test/bootstrap/configure-app.e2e-spec.ts`.
- Missing persisted users are downgraded to anonymous sessions instead of crashing the request lifecycle, covered by `apps/api/test/auth/auth.serializer.e2e-spec.ts`.

## CSRF

- Mutating authenticated routes are protected by `apps/api/src/auth/guards/session-auth.guard.ts`.
- The guard requires the CSRF cookie and `X-CSRF-Token` header to match before allowing state-changing requests.
- Browser requests attach the token in `apps/web/src/api/client.ts`.
- The happy and failure paths are covered by `apps/api/test/auth/session-auth.guard.e2e-spec.ts` and `apps/api/test/auth/auth.e2e-spec.ts`.

## Throttling

- Global throttling is wired through `apps/api/src/common/guards/session-aware-throttler.guard.ts`.
- Authenticated traffic uses `sessionID` as the tracker and anonymous traffic falls back to the request IP to avoid unstable session-based throttling.
- Regression coverage lives in `apps/api/test/common/session-aware-throttler.guard.e2e-spec.ts`.

## Raw Health Responses

- `GET /api/health` remains a raw response and bypasses the shared response envelope through `SkipTransform`.
- The controller lives in `apps/api/src/health/health.controller.ts` and returns `ok` or `degraded` based on database and Redis reachability.
- Regression coverage lives in `apps/api/test/health/health.controller.e2e-spec.ts` and `apps/api/test/app.e2e-spec.ts`.

## Report Download Expiry

- Report status and download rules are enforced in `apps/api/src/report/report.service.ts`.
- Expired ready reports are marked `EXPIRED` and have download access denied with explicit error codes.
- Background expiry cleanup runs through `apps/api/src/report/report-expiry.task.ts` and the storage lifecycle is centralized in `apps/api/src/report/services/report-storage.service.ts`.
- Coverage lives in `apps/api/test/report/report.service.e2e-spec.ts`, `apps/api/test/report/report-expiry.task.e2e-spec.ts`, and `apps/api/test/report/report-storage.service.e2e-spec.ts`.

## Queue Recovery

- Stuck scan recovery is handled by `apps/api/src/scan/stuck-scan-recovery.task.ts`.
- Coverage lives in `apps/api/test/scan/stuck-scan-recovery.task.e2e-spec.ts`.

## Provider Errors

- Provider-level rate limit, not-found, and authorization mapping are handled across `apps/api/src/client/git/` and consuming services.
- Representative coverage exists in `apps/api/test/client/git/github.client.e2e-spec.ts`, `apps/api/test/repo/repo.service.e2e-spec.ts`, and `apps/api/test/scan/scan.service.e2e-spec.ts`.

## Frontend Error States

- Session bootstrap, unauthorized API responses, dashboard degraded mode, and transient report failures have explicit UX handling in the shipped frontend.
- Coverage exists in `apps/web/src/hooks/useAuth.test.tsx`, `apps/web/src/api/client.test.ts`, `apps/web/src/pages/LoginPage.test.tsx`, and `apps/web/src/pages/DashboardPage.test.tsx`.

## Completion Note

This review assumes the repository is validated with the final quickstart command path:

```powershell
corepack pnpm lint
corepack pnpm test
corepack pnpm typecheck
corepack pnpm build
```
