# Scan Infrastructure Design

## Goal

Build the backend scan orchestration layer that can create queued scans, collect Java source
files from connected repositories, run mock analysis asynchronously, persist scan summaries and
findings, and recover scans that get stuck in non-terminal states.

## Scope

This design covers T014 only:

- `apps/api/src/scan/scan.module.ts`
- `apps/api/src/scan/scan.service.ts`
- `apps/api/src/scan/scan.processor.ts`
- `apps/api/src/scan/stuck-scan-recovery.task.ts`
- `apps/api/src/scan/services/code-collector.service.ts`

Out of scope for this issue:

- scan controller endpoints
- repository controller/service UX flows
- frontend polling and scan request UI
- report generation
- production analysis engine integration
- `AppModule`-level global wiring and middleware registration, which remains part of T026

## Current Context

The repository already has the prerequisites this layer depends on:

- Prisma models for `Scan` and `Vulnerability`
- session/OAuth foundation and persisted provider tokens
- `IGitProviderClient` implementations for GitHub and GitLab
- `ILanguageHandler` registry with a Java handler
- `IAnalysisApiClient` with a default `MockAnalysisApiClient`

`AppModule` already imports config, auth, git-client, language, analysis, and prisma modules, so
the scan layer can be added as another backend module without reshaping the current application
boundaries.

## Proposed Architecture

### ScanModule

`ScanModule` owns the BullMQ queue registration, provider wiring, and exports `ScanService` for
later controller use. It imports `PrismaModule`, `AuthModule`, `GitClientModule`,
`LanguageModule`, `AnalysisApiModule`, and BullMQ redis configuration.

### ScanService

`ScanService` handles the request path that later controllers will use:

- validate the connected repository exists
- block duplicate active scans for the same connected repo + branch
- create a `Scan` row in `PENDING`
- enqueue a BullMQ job keyed by the scan id

It does not perform collection or analysis inline. That work stays in the processor.

### CodeCollectorService

`CodeCollectorService` converts a connected repo + branch + access token into an
`AnalysisRequest`-ready payload.

Responsibilities:

- resolve the right provider client from `GitClientRegistry`
- fetch the latest commit SHA
- fetch the repository file tree
- select files supported by the configured language handler
- read file contents for supported files
- skip unsupported or oversized files
- return the normalized analysis file list plus summary metadata

The collector is intentionally focused on data gathering. It does not write Prisma state.

### ScanProcessor

`ScanProcessor` is the asynchronous execution boundary.

Responsibilities:

- transition `PENDING -> RUNNING`
- load the scan and connected repo context
- decrypt the provider access token via `AuthService` dependencies
- collect Java source files through `CodeCollectorService`
- delegate analysis to `IAnalysisApiClient`
- persist aggregate counts and vulnerability records
- transition `RUNNING -> DONE` or `RUNNING -> FAILED`

For the MVP, the processor replaces prior vulnerability rows for the scan before inserting the new
set. This keeps retry behavior deterministic and avoids duplicate findings.

### StuckScanRecoveryTask

`StuckScanRecoveryTask` scans for `PENDING` and `RUNNING` scans older than a configured threshold
and marks them `FAILED` with a recovery error message. This is intentionally minimal for MVP: it
does not requeue work automatically, but it prevents indefinite non-terminal scan states.

## Data Flow

1. Caller asks `ScanService` to create a scan.
2. `ScanService` blocks duplicate active scans and stores a `PENDING` scan row.
3. `ScanService` enqueues the scan id onto the BullMQ queue.
4. `ScanProcessor` starts the job and marks the scan `RUNNING`.
5. `CodeCollectorService` gathers Java files and the latest commit SHA.
6. `IAnalysisApiClient` returns the mock analysis result.
7. `ScanProcessor` stores vulnerability rows, updates severity counters and totals, and marks the
   scan `DONE`.
8. Any setup or processing error marks the scan `FAILED` with an error message.

## Queue Strategy

- Queue name: `scan`
- Job name: `scan.process`
- Job id: scan id
- Default behavior: one job per scan row, no controller-level retry logic yet

Using the scan id as the BullMQ job id lines up the persisted `Scan` row with the queued work and
keeps duplicate scheduling behavior explicit.

## Persistence Rules

- Duplicate active scans are defined as an existing `PENDING` or `RUNNING` scan for the same
  `connectedRepoId` and `branch`.
- `startedAt` is written when the processor starts.
- `completedAt` is written on terminal states.
- `commitSha`, `totalFiles`, `totalLines`, and severity counters come from the collector and
  analysis result.
- Vulnerabilities are replaced per scan execution to keep retries idempotent.

## Error Handling

- Missing scan row in the processor fails the job immediately.
- Missing provider token for the connected repo owner fails the scan.
- Provider client and analysis client failures become `FAILED` scan states with an error message.
- Collection with zero supported files is treated as a successful empty scan unless analysis
  reports an error.
- Recovery task failures should not throw the whole app down; the task simply logs and continues.

## Testing Strategy

The implementation will be driven by tests first:

- `scan.service` tests for duplicate blocking and queue enqueue behavior
- `code-collector.service` tests for language filtering, file-content collection, and commit SHA
  propagation
- `scan.processor` tests for success persistence and failure state transitions
- `stuck-scan-recovery.task` tests for expiring old active scans while leaving fresh scans alone

All tests should mock external dependencies and focus on real behavior at the service boundary
instead of asserting framework internals.
