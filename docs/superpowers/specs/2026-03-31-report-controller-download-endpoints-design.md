# Report Controller And Download Endpoints Design

## Goal

Expose the existing report infrastructure as protected API endpoints for requesting report generation, checking report status, and downloading generated PDFs.

## Scope

- Add `ReportController` under `apps/api/src/report/`
- Expose:
  - `POST /api/reports/scans/:scanId/pdf`
  - `GET /api/reports/:reportId`
  - `GET /api/reports/:reportId/download`
- Keep ownership checks inside `ReportService`
- Support raw PDF download without response envelope
- Align OpenAPI and shared report contracts with the implemented behavior

## Design

### Request Endpoint

`POST /api/reports/scans/:scanId/pdf` delegates to the existing `ReportService.requestReport`.

- authenticated only
- accepted only for owned `DONE` scans
- returns wrapped `GENERATING` or `READY` response

### Status Endpoint

`GET /api/reports/:reportId` delegates to `ReportService.getReportDetail`.

- authenticated only
- owned report only
- returns wrapped report detail including `EXPIRED`

### Download Endpoint

`GET /api/reports/:reportId/download` delegates to a new `ReportService.getReportDownload`.

- authenticated only
- owned report only
- `READY` returns raw `application/pdf`
- `GENERATING` returns `409 REPORT_NOT_READY`
- `FAILED` returns `409 REPORT_FAILED`
- `EXPIRED` returns `410 REPORT_EXPIRED`
- stale `READY` rows with missing files or past expiry are converted to `EXPIRED` before returning `410`

## Storage Behavior

`ReportStorageService` gains a `read(filePath)` helper so controller/service code can stream the generated PDF using the same storage abstraction used for write/delete.

## Testing

- service tests for download-ready, generating, failed, expired, and stale-file cases
- controller e2e tests for request, detail, and raw download responses
- full workspace lint, test, typecheck, build
