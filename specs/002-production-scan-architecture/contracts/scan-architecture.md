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
- `GET /api/policy-decisions/:policyDecisionId`
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

## AI Plane Boundary

AI advisory requests contain a normalized finding, reduced redacted evidence, and model
version. They must not contain SCM credentials, full repository input, or raw unbounded
scanner payloads. AI output is advisory metadata only and cannot override deterministic
scanner findings or policy decisions.

## EvidencePack

EvidencePack metadata includes tenant ID, scan request ID, data classification, tenant/scan
scoped object key, expiration timestamp, byte size, and redaction state.

## PolicyDecision

PolicyDecision is structured. It includes enforcement action, comment allowance, dashboard
visibility, ticket/block requests, reason codes, required coverage set, waiver application,
stale suppression, and AI advisory visibility.
