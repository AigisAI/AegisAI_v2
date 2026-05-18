# Scan Architecture Contract

## Purpose

This contract defines the first milestone interface surface for the production scan
architecture. It intentionally describes boundaries and data shapes, not full scanner,
sandbox, or AI runtime implementation.

## Public API Skeleton

- `POST /api/integrations/github/install`
- `POST /api/integrations/gitlab/install`
- `GET /api/integrations`
- `DELETE /api/integrations/:integrationId`
- `GET /api/repository-bindings`
- `POST /api/webhooks/github`
- `POST /api/webhooks/gitlab`
- `POST /api/scan-requests`
- `GET /api/scan-requests/:scanRequestId`
- `GET /api/findings`
- `GET /api/findings/:findingId`
- `GET /api/evidence/:evidencePackId`
- `POST /api/evidence/:evidencePackId/access-requests`
- `POST /api/policy-decisions/evaluate`
- `GET /api/policy-decisions/:policyDecisionId`
- `POST /api/ai-advisories`
- `GET /api/ai-advisories/:advisoryId`
- `POST /api/comment-dispatches/plan`
- `POST /api/comment-dispatches/enqueue`
- `GET /api/comment-dispatches/outbox`
- `PATCH /api/comment-dispatches/outbox/:outboxItemId/status`
- `GET /api/comment-dispatches/audit-events`
- `POST /api/waivers`
- `PATCH /api/waivers/:waiverId`
- `POST /api/suppressions`

## CanonicalScanKey

Fields:

- `tenantId`
- `repositoryBindingId`
- `lane`
- `targetRef`
- `commitSha`
- `policyVersion`
- `scannerSetVersion`

The serialized key is used for deduplication, stale-result suppression, comment
idempotency, and retry safety.

## Token Broker

Token Broker issue requests are tenant, repository, and scan scoped. The request may
include a principal, fixed commit SHA, TTL, and audit reason. The token value itself must
not be persisted or logged.

Token Broker issue responses may include a short-lived `SCM_REPOSITORY_ACCESS` credential
value for the immediate caller. Credential values are tenant/repository/scan/commit scoped,
expire according to the requested TTL, and must never appear in audit events or persisted
records.

## GitHub App Installation Runtime

GitHub Cloud repository access is modeled through a GitHub App installation principal.
The Control Plane may exchange an app JWT for a short-lived installation token to list
installation repositories and create repository bindings. Installation token values are
runtime-only and must not be returned by public APIs, stored in tenant records, or logged.

Installation state is persisted as tenant-scoped `ScmIntegration` and `RepositoryBinding`
records. The Control Plane may acknowledge GitHub `installation_repositories` webhooks and
reconcile repository additions/removals into repository bindings. Webhook acknowledgements
must not include or persist GitHub App installation token values.

## GitLab Cloud Integration Runtime

GitLab Cloud repository access is modeled through project/group integration metadata and
webhook flows. The Control Plane may use a runtime-only GitLab access token to list
accessible projects and create repository bindings for a tenant-scoped
`GITLAB_CLOUD_INTEGRATION`. GitLab runtime token values must not be returned by public APIs,
stored in integration records, repository bindings, or logs.

## Scan Plane Boundary

Scan Plane accepts scan-scoped repository access and emits scanner runs, raw artifact
references, normalized findings, evidence metadata, and audit events. It must not receive
comment-write or integration-admin authority.

Opengrep, Trivy, and Syft execution is exposed through scanner adapter invocation metadata.
Adapters must run against a scan-scoped read-only workspace reference with network egress
disabled, package installation disabled, build commands disabled, and customer code
execution disabled. Scanner execution responses may include scanner run records, raw
artifact references, adapter command metadata, and redacted short-lived evidence metadata;
they must not include SCM credentials, full repository archives, package install commands,
or build commands.

## AI Plane Boundary

AI advisory requests contain a normalized finding, reduced redacted evidence, and model
version. They must not contain SCM credentials, full repository input, or raw unbounded
scanner payloads. AI output is advisory metadata only and cannot override deterministic
scanner findings or policy decisions.

AI detector/planner output in this milestone is a standalone runtime service boundary in
`apps/ai` that returns advisory-only detector signals, planner steps, confidence, and model
version. It must not emit authoritative finding status, enforcement action, block request,
waiver state, suppression state, credential values, full repository content, or raw scanner
payloads.

When `USE_INTERNAL_AI=true`, the API server may forward the same reduced advisory request to
`AI_SERVER_URL` at `/ai/advisories`. The runtime response is accepted only when it contains
advisory-only detector signals, planner steps, confidence, and model version. Runtime
responses that include policy authority, finding override fields, credentials, full
repository content, source archives, or raw scanner payloads must be rejected.

The dev/demo AI runtime also exposes `GET /health` for Compose health checks. This health
endpoint is operational metadata only and does not accept tenant, scan, repository, evidence,
or credential material.

## EvidencePack

EvidencePack metadata includes tenant ID, scan request ID, data classification, tenant/scan
scoped object key, expiration timestamp, byte size, and redaction state.

Evidence object storage in this milestone is a local dev/demo adapter behind the
Data/Security Plane boundary. Evidence access requests return metadata-only descriptors
with `METADATA_ONLY` access mode and redacted evidence references. Access responses and
stored payloads must not include SCM credential values, workspace references, raw source
archives, full repository content, or unbounded scanner payloads. Expired evidence objects
are deleted by TTL cleanup using the tenant/scan scoped object key, while production object
storage and KMS integration remain deferred.

## PolicyDecision

PolicyDecision is structured. It includes enforcement action, comment allowance, dashboard
visibility, ticket/block requests, reason codes, required coverage set, waiver application,
stale suppression, and AI advisory visibility.

Policy evaluation in this milestone is deterministic and scanner-first. It accepts normalized
finding metadata, scan lane, scanner coverage metadata, and optional AI advisory visibility
metadata. AI advisory input may be surfaced through `aiAdvisoryVisible`, but suggested AI
actions must not select or override enforcement action, ticket request, block request, waiver
state, or stale suppression.

## Waiver and Suppression Lifecycle

Waiver lifecycle endpoints accept tenant-scoped metadata only:

- `POST /api/waivers` creates a waiver with owner, reason, scope, and expiration metadata.
- `PATCH /api/waivers/:waiverId` updates an existing waiver for the same tenant and may
  record `lastReviewedAt`.

Suppression lifecycle endpoints accept tenant and scan scoped metadata only:

- `POST /api/suppressions` creates a stale-result, duplicate, or policy suppression for a
  scan request and optional finding.

Waiver and suppression payloads must not include SCM credentials, full repository content,
source archives, raw scanner payloads, AI override fields, finding override fields, or policy
authority such as enforcement action or block requests. Lifecycle APIs record exception
metadata; they do not execute scans, make deterministic policy decisions, or grant SCM
principals.

## Comment Dispatcher Boundary

Comment dispatch planning is a Control Plane boundary. `POST /api/comment-dispatches/plan`
accepts tenant, repository binding, target ref, commit SHA, policy decision metadata, and a
normalized finding. It returns metadata for a planned comment dispatch only when the policy
decision allows comments and the repository binding's SCM integration has a comment-write
principal. The response includes a deterministic `idempotencyKey` built from tenant,
repository binding, policy decision, finding, target ref, and commit SHA.

Comment dispatch planning must not receive or return repo-read credentials, integration-admin
authority, SCM token values, full repository content, source archives, or raw scanner payloads.
This milestone does not publish GitHub/GitLab comments; it only validates the comment-write
principal boundary and produces deterministic dispatch metadata.

Repeated dispatch planning requests with the same `idempotencyKey` return the existing plan
instead of creating a duplicate plan or duplicate `comment_dispatch.planned` audit event.
Different finding, target, commit, policy decision, repository binding, or tenant inputs create
separate plans.

`POST /api/comment-dispatches/enqueue` converts an existing tenant-scoped plan into a
metadata-only `PENDING` outbox item. Repeated enqueue requests for the same plan return the
existing outbox item. `GET /api/comment-dispatches/outbox` returns tenant-scoped outbox
metadata for dispatcher runtime pickup. This milestone does not publish external GitHub or
GitLab comments, does not persist external comment IDs, and does not call SCM write APIs.

`PATCH /api/comment-dispatches/outbox/:outboxItemId/status` may update a tenant-scoped
outbox item to `FAILED` or `CANCELED` with a reason and timestamp. `PUBLISHED` transitions,
external comment IDs, and SCM write-result metadata remain deferred until a real dispatcher
runtime exists.

Every successful dispatch planning operation records a tenant-scoped
`comment_dispatch.planned` audit event. `GET /api/comment-dispatches/audit-events` returns
metadata only: repository binding ID, provider, provider repository ID, policy decision ID,
finding ID, target ref, commit SHA, and comment-write principal ID. Audit events must not
include SCM token values, repo-read principals, integration-admin principals, full
repository content, source archives, or raw scanner payloads.

Every first successful outbox enqueue records one tenant-scoped
`comment_dispatch.enqueued` audit event. Repeated enqueue requests for the same plan return
the existing outbox item and do not create duplicate enqueue audit events. Enqueue audit
metadata is limited to outbox item ID, plan ID, idempotency key, repository binding ID,
provider, policy decision ID, finding ID, target ref, commit SHA, and comment-write
principal ID. It must not include SCM token values, repo-read principals,
integration-admin principals, external comment IDs, full repository content, source
archives, or raw scanner payloads.

Every first successful outbox failure/cancel status transition records one tenant-scoped
`comment_dispatch.outbox_status_updated` audit event. Repeated requests with the same
status and reason return the existing outbox item and do not create duplicate status audit
events. Status audit metadata is limited to outbox item ID, plan ID, previous status, next
status, status reason, status update timestamp, repository binding ID, provider, finding
ID, and commit SHA. It must not include `PUBLISHED` write-result metadata, external comment
IDs, SCM token values, repo-read principals, integration-admin principals, full repository
content, source archives, or raw scanner payloads.
