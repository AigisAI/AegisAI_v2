# Research: AegisAI Platform MVP Foundation

## Decision 1: Use session auth with Redis-backed storage and CSRF validation

- **Decision**: Implement OAuth login through Passport strategies, persist sessions in
  Redis, and require `X-CSRF-Token` for mutating authenticated requests.
- **Rationale**: The product is a browser-based SaaS with cross-origin frontend and backend
  coordination. Session auth fits that model well and matches the architecture in
  `spec 2.2.md`.
- **Alternatives considered**:
  - JWT-only auth: rejected because it would add token rotation and storage decisions not
    required by the baseline architecture.
  - No CSRF layer: rejected because the MVP still needs browser-safe session semantics.

## Decision 2: Keep repository access in the backend and analysis behind an interface

- **Decision**: The NestJS backend owns repository listing, branch listing, commit lookup,
  file discovery, and file retrieval. Analysis receives normalized `files[]` input through
  `IAnalysisApiClient`.
- **Rationale**: This preserves credential isolation, avoids direct Git access in the
  analysis service, and keeps the MVP compatible with both mock and future internal
  analysis clients.
- **Alternatives considered**:
  - Allow `apps/ai` to fetch repositories itself: rejected because it breaks the separation
    mandated by the specification.
  - Direct file upload: rejected because it is explicitly out of scope.

## Decision 3: Use a hybrid provider file-collection strategy

- **Decision**: Use provider tree APIs to enumerate candidate files, then choose direct
  file fetches for smaller repositories and tarball download plus filtering for larger
  ones.
- **Rationale**: This balances API efficiency and operational control while respecting
  limits such as max file count, total size, and concurrency.
- **Alternatives considered**:
  - Only contents API calls: rejected because it scales poorly for large repositories.
  - Always download tarballs: rejected because it is wasteful for small repositories.

## Decision 4: Make `MockAnalysisApiClient` the default MVP implementation

- **Decision**: Build around `MockAnalysisApiClient` first and preserve `InternalAnalysisApiClient`
  only as an optional integration target.
- **Rationale**: This keeps the MVP deliverable independent from model training, serving,
  or external analysis system readiness.
- **Alternatives considered**:
  - Implement real analysis immediately: rejected because it is roadmap-level complexity.
  - Skip the interface abstraction and call mock data directly: rejected because it would
    weaken the architecture boundary agents need to preserve.

## Decision 5: Generate reports asynchronously through BullMQ

- **Decision**: Model report generation the same way as scan execution, with a report queue,
  worker, status endpoint, and download endpoint.
- **Rationale**: PDF generation can be slow or failure-prone. The asynchronous model gives
  a consistent user experience and fits the queue-centric architecture.
- **Alternatives considered**:
  - Generate PDFs inline in request handlers: rejected because it can block the API.
  - Defer reports entirely to Phase 2: rejected because PDF export is explicitly included in MVP.

## Decision 6: Test critical flows at backend, queue, and frontend boundaries

- **Decision**: Require integration and regression coverage for OAuth/session flows, queue
  processing, repository access, vulnerability retrieval, dashboard summaries, and reports.
- **Rationale**: These are the highest-risk integration points and the ones most likely to
  regress as multiple agents work in parallel.
- **Alternatives considered**:
  - Unit tests only: rejected because the primary complexity is in integration behavior.
  - No frontend interaction tests: rejected because dashboard, scan, and report UX are core
    user-facing flows in the MVP.
