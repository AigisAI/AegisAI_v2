# Feature Specification: AegisAI Platform MVP Foundation

**Feature Branch**: `001-aegisai-mvp-foundation`  
**Created**: 2026-03-13  
**Status**: Draft  
**Input**: User description: "Prepare the repository so agents can start building the AegisAI MVP directly from the docs"

## Scope Alignment *(mandatory)*

- **Primary Reference**: `spec 2.2.md` and `.specify/memory/constitution.md`
- **Delivery Class**: MVP Required
- **In Scope**: End-to-end MVP delivery planning for GitHub/GitLab auth, repository connection, queued Java scan execution with mock analysis, vulnerability review, dashboarding, scan history, and PDF reporting
- **Explicitly Out of Scope**: Direct source upload, in-backend vulnerability engine implementation, realtime scan streaming, billing, team/RBAC, production webhook automation, suggested changes automation, email notifications, compliance work, and other Phase 2/3 roadmap items
- **Affected Surfaces**: `apps/api`, `apps/web`, `packages/shared`, `apps/ai` (optional integration only), local infra, docs

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Connect and Scan a Repository (Priority: P1)

As a signed-in user, I can connect my GitHub or GitLab account, choose a repository and
branch, and request a queued Java security scan so that I can get the first actionable
result without leaving the product.

**Why this priority**: This is the core value loop of the platform. Without auth, repo
selection, and scan execution, none of the later review features matter.

**Independent Test**: Mock OAuth login, connect one repository, fetch branches, submit a
scan request, poll until completion, and verify that the system returns a completed scan
with summary data.

**Acceptance Scenarios**:

1. **Given** an authenticated user with a valid GitHub or GitLab token, **When** they
   connect a repository and start a scan on an allowed branch, **Then** the API returns a
   `scanId` immediately and the scan transitions through `PENDING` to `DONE`.
2. **Given** a repository already has a `PENDING` or `RUNNING` scan for the same target,
   **When** the user submits another identical scan request, **Then** the system rejects it
   with a duplicate-scan response instead of creating competing jobs.

---

### User Story 2 - Review Vulnerabilities and Feedback (Priority: P2)

As a user with completed scan results, I can inspect the vulnerability list, open a
detailed finding view, and submit accept or reject feedback so that I can evaluate
whether the proposed issue and remediation are useful.

**Why this priority**: The product only becomes valuable once scan results are reviewable
and understandable by humans.

**Independent Test**: Seed or generate a completed scan, fetch the paginated vulnerability
list, open one detail item, verify the code context and consensus data, and submit
feedback successfully.

**Acceptance Scenarios**:

1. **Given** a completed scan with findings, **When** the user opens the vulnerability list,
   **Then** they can filter, sort, paginate, and navigate to a detail page.
2. **Given** a vulnerability detail, **When** the user reviews the issue and submits
   feedback, **Then** the updated feedback status is persisted and reflected in later reads.

---

### User Story 3 - Monitor Progress and Export Reports (Priority: P3)

As a user managing multiple scans, I can view dashboard summaries, scan history, and a
generated PDF report for a completed scan so that I can track trends and share results.

**Why this priority**: Dashboarding and exports strengthen the operational value of the MVP
but depend on core scan execution and result storage already existing.

**Independent Test**: Use completed scan fixtures to load dashboard metrics and history,
request PDF generation for a done scan, poll report status, and download the generated PDF.

**Acceptance Scenarios**:

1. **Given** completed scan data, **When** the user opens the dashboard, **Then** they see
   severity distribution, trend data, and recent scan summaries.
2. **Given** a completed scan, **When** the user requests a report, **Then** the system
   generates a PDF asynchronously and later exposes a download endpoint.

---

### Assumptions

- `MockAnalysisApiClient` is the default implementation for MVP completion.
- Only Java repositories are in scope for analysis, but the codebase must stay extensible
  through `ILanguageHandler`.
- The backend collects repository files via provider APIs and passes normalized `files[]`
  payloads to analysis clients.
- Session auth with CSRF protection is the default web security model.
- The frontend is a React SPA backed by REST APIs from the NestJS backend.

### Edge Cases

- What happens when an OAuth token is expired or revoked after a repository is connected?
- How does the system behave when a repository branch contains no eligible Java files?
- What happens when provider API pagination or rate limits interrupt repository listing or
  file collection?
- How does the worker recover when analysis times out or returns malformed data?
- What happens when a report is requested for a scan that is not `DONE`?
- How does the system handle large repositories that exceed file-count or total-size limits?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST authenticate users through GitHub and GitLab OAuth and
  persist encrypted provider tokens for later API access.
- **FR-002**: The system MUST create and maintain server-side sessions in Redis and require
  CSRF validation for mutating authenticated API requests.
- **FR-003**: The system MUST expose authenticated endpoints for listing available provider
  repositories, connecting a repository, disconnecting a repository, and listing branches.
- **FR-004**: The system MUST allow a user to request a scan for a connected repository and
  branch and return a scan identifier immediately.
- **FR-005**: The system MUST prevent duplicate active scans for the same repository target.
- **FR-006**: The system MUST execute scan processing asynchronously through BullMQ workers.
- **FR-007**: The backend MUST collect repository files from GitHub or GitLab APIs and MUST
  NOT require direct source-file uploads.
- **FR-008**: The backend MUST send analysis work through `IAnalysisApiClient` and MUST NOT
  embed the vulnerability-detection engine directly in `apps/api`.
- **FR-009**: The system MUST preserve consensus-oriented result fields, including
  `consensusScore` and `modelResults`, even when using mock analysis data.
- **FR-010**: The system MUST filter collected files through `ILanguageHandler` and the MVP
  handler MUST support Java only.
- **FR-011**: The system MUST store scan summaries, vulnerability findings, and scan history
  in PostgreSQL.
- **FR-012**: The system MUST provide a vulnerability list and detail experience that
  includes severity, file path, line information, code context, remediation guidance, and
  model-level review data when available.
- **FR-013**: The system MUST allow users to submit feedback such as accept or reject on
  individual vulnerabilities.
- **FR-014**: The system MUST provide dashboard summaries covering severity distribution,
  trend data, and recent scans.
- **FR-015**: The system MUST support asynchronous PDF report generation for completed scans
  and later allow report download.
- **FR-016**: The system MUST expose a `GET /api/health` endpoint that reports API uptime and
  dependency health without the standard API response wrapper.
- **FR-017**: Shared API contracts used by backend and frontend MUST live in
  `packages/shared`, while NestJS runtime DTO validation remains in `apps/api`.
- **FR-018**: The frontend MUST use dedicated API modules, TanStack Query for server state,
  and Zustand for client auth state.
- **FR-019**: The system MUST apply rate limiting, structured error responses, and response
  transformation rules consistent with `spec 2.2.md`.
- **FR-020**: The MVP MUST be implementable without requiring the optional `apps/ai` service,
  while still preserving a clean integration path for it.

### Guardrails & Non-Goals *(mandatory)*

- **NG-001**: The feature MUST NOT pull roadmap-only work into MVP acceptance criteria unless the spec explicitly reclassifies it.
- **NG-002**: The feature MUST NOT bypass the repository-collection and analysis separation defined in `spec 2.2.md`.
- **NG-003**: The feature MUST NOT introduce direct source upload or an in-backend vulnerability engine unless that architectural change is explicitly approved.
- **NG-004**: The feature MUST preserve shared contract compatibility for any data exchanged between `apps/api`, `apps/web`, and `packages/shared`.

### Key Entities *(include if feature involves data)*

- **User**: Authenticated platform user with provider identities and session-backed access.
- **OAuthToken**: Encrypted provider credential record associated with a user and provider.
- **ConnectedRepo**: Repository the user has linked to AegisAI, including provider metadata.
- **Scan**: A queued or completed repository analysis request tied to a repository and branch.
- **Vulnerability**: A finding returned for a scan, including severity, evidence, confidence,
  and feedback state.
- **Report**: An asynchronously generated PDF export for a completed scan.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A new user can complete provider connection, repository selection, and first
  scan request within 1 minute using the reference flow.
- **SC-002**: For the reference Java repository workload defined in `spec 2.2.md`, the first
  mock-backed scan result is available within 30 seconds.
- **SC-003**: Users can independently complete the primary review flow for a completed scan,
  including finding inspection and feedback submission, without engineering intervention.
- **SC-004**: Users can generate and download a PDF report for a completed scan without
  blocking the rest of the application.

### Alignment Checks

- **AC-001**: This feature remains inside the MVP baseline and leaves Phase 2 and Phase 3
  roadmap items out of the acceptance scope.
- **AC-002**: This feature preserves backend repository collection, `IAnalysisApiClient`
  delegation, `MockAnalysisApiClient` default behavior, and Java-only MVP language support.
- **AC-003**: This feature requires shared contract updates, session plus CSRF security, queue
  processing, health checks, and the critical backend/frontend tests defined by the constitution.
