# Report Infrastructure Design

## Scope

`#92` implements the Phase 2 report foundation only. This task adds the backend module,
queue worker, PDF generator, local file storage, and expiry lifecycle needed so later
controller and frontend work can request, poll, and download reports without redesigning
the internals.

Out of scope for this task:

- report controller endpoints
- dashboard endpoints or UI
- report download UI
- rich branded PDF templates beyond a minimal production-valid report document

## Goals

- Generate a PDF asynchronously for a completed scan.
- Persist report rows and local files using the existing Prisma `Report` model.
- Reuse in-flight or still-valid reports instead of duplicating work.
- Mark expired report files so later download endpoints can enforce expiry cleanly.

## Status Model

The report lifecycle is:

- `GENERATING`: report row exists and the BullMQ job is in progress or queued
- `READY`: report file exists locally and is available until `expiresAt`
- `FAILED`: generation failed and includes an `errorMessage`
- `EXPIRED`: the file lifecycle task has deleted the local artifact and the report must be regenerated

This adds `EXPIRED` to the Prisma and shared-contract report status surface.

## Module Decomposition

`apps/api/src/report/`

- `report.constants.ts`
  - queue names and job names
- `report.module.ts`
  - queue registration and runtime/test provider wiring
- `report.service.ts`
  - request/reuse logic and report detail lookup for future controller work
- `report.processor.ts`
  - BullMQ worker that loads scan data, generates the PDF, stores it, and updates status
- `services/pdf-generator.service.ts`
  - creates a minimal valid PDF from scan and vulnerability data
- `services/report-storage.service.ts`
  - local filesystem path resolution, write/delete/existence helpers
- `report-expiry.task.ts`
  - expires old ready reports and deletes local files

## Behavioral Rules

- Only scans in `DONE` status may request a report.
- Ownership is derived from `scan.connectedRepo.userId`; a user may only request reports for scans they own.
- If a `GENERATING` report already exists for the same `scanId` and `userId`, reuse it.
- If a non-expired `READY` report exists and the file is still present, reuse it.
- If a `READY` report is expired or its file is missing, mark it `EXPIRED` and create a new one.
- If queue enqueue fails after the row is created, mark the report `FAILED` with a clear error message.

## PDF Generation Strategy

Use a lightweight generator with `pdf-lib` instead of introducing browser rendering at this stage.
The generator will create a valid PDF containing:

- report title and generated timestamp
- scan repository, branch, commit, file and line counts
- severity summary
- vulnerability list with file path, line number, title, severity, and short recommendation

This keeps the infrastructure reliable while leaving rich HTML-based templates to later work if
the product still needs them.

## Storage and Expiry

- Use `REPORT_STORAGE_PATH` from config.
- Write files as `aegisai-scan-report-<scanId>-<reportId>.pdf`.
- On successful generation, set:
  - `status = READY`
  - `filePath`
  - `downloadUrl = /api/reports/<reportId>/download`
  - `expiresAt = now + REPORT_EXPIRY_HOURS`
- The expiry task will:
  - find expired `READY` reports
  - delete the local file if present
  - set `status = EXPIRED`
  - clear `downloadUrl`
  - keep `expiresAt` as the historical expiry time

## Testing Strategy

- `report.service.e2e-spec.ts`
  - creates and enqueues a new report
  - reuses generating and ready reports
  - rejects non-owned and non-`DONE` scans
  - compensates on queue failure
- `report.processor.e2e-spec.ts`
  - marks a report ready and writes storage on success
  - marks a report failed on generator/storage error
- `pdf-generator.service.e2e-spec.ts`
  - verifies a valid PDF buffer is produced
- `report-expiry.task.e2e-spec.ts`
  - expires ready reports and deletes files

