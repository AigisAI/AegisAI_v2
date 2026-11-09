# Scan Architecture Contract

## Purpose

This contract defines the first milestone interface surface for the production scan
architecture. It intentionally describes boundaries and data shapes, not full scanner,
sandbox, or AI runtime implementation.

## Public API Skeleton

Implemented user-facing routes require the server-managed login session. Tenant identity is
derived from that session and is never accepted from a request body or query string.
State-changing routes require the synchronized `X-CSRF-Token` header.

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

Authentication and operations routes currently implemented by the skeleton are:

- `GET /api/auth/github`
- `GET /api/auth/github/callback`
- `GET /api/auth/me`
- `POST /api/auth/logout`
- `GET /api/health`
- `GET /api/scan-plane/scanner-runs`
- `GET /api/findings`
- `GET /api/evidence`
- `GET /api/audit-events`

`POST /api/token-broker/issue` and `POST /api/scan-plane/mock-runs` are internal-plane
routes. They require the dedicated internal bearer credential and do not use a user session.

## CanonicalScanKey

Fields:

- `tenantId`
- `repositoryBindingId`
- `lane`
- `targetRef`
- `commitSha`
- `policyVersion`
- `scannerSetVersion`

The serialized key is versioned and delimiter-safe. It is used for deduplication,
stale-result suppression, comment idempotency, and retry safety.

## Token Broker

Token Broker issue requests are tenant, repository, and scan scoped. The request may
include a principal, fixed commit SHA, TTL, and audit reason. The token value itself must
not be persisted or logged. The current contract caps scan credentials at ten minutes and
verifies repository binding and commit SHA against the immutable scan request.

## Scan Plane Boundary

Scan Plane accepts scan-scoped repository access and emits scanner runs, raw artifact
references, normalized findings, evidence metadata, and audit events. It must not receive
comment-write or integration-admin authority.

## Language Discovery and Scan Profiles

Scan Plane planning may classify repository manifest metadata before scanner execution.
This classification must use path and manifest metadata only, not full source content.

The first detailed language profile is Java:

- Java signals include `.java`, `pom.xml`, `build.gradle`, `build.gradle.kts`,
  `settings.gradle`, and `gradle.lockfile`.
- Non-Java signals such as `package.json`, `pyproject.toml`, `requirements.txt`,
  `go.mod`, `Dockerfile`, Terraform files, and Kubernetes YAML remain common-only in
  this slice.

The implemented mock scan profile set is:

- `JAVA_DETAILED`: Opengrep, Trivy, and Syft scanner metadata is scoped to Java detailed
  coverage, and normalized Java findings may be emitted by the Scan Plane.
- `COMMON`: Opengrep, Trivy, and Syft scanner metadata is emitted for common coverage,
  but no Java normalized finding or Java-only AI advisory eligibility is emitted.

Language discovery is a routing aid for Scan Plane planning. It must not move repository
source code into the AI Plane.

`POST /api/scan-plane/mock-runs` accepts optional `repositoryManifest` in this form:

```json
{"files":[{"path":"service/pom.xml"},{"path":"src/App.java"}]}
```

Only `files[].path` is accepted: source content, credential fields, and caller-selected
profiles are rejected. Each manifest is limited to 1,000 entries with paths of at most
512 characters. Paths must be repository-relative, use `/`, and contain no empty, `.`,
or `..` segments, backslashes, colons, or ASCII control characters. Larger repositories
require a future discovery contract; this endpoint rejects oversized input rather than
silently truncating it and implying full discovery.

The result and each scanner run include `planning` with `scanProfile`, deterministically ordered
`detectedLanguages`, `detectedSurfaces`, and `aiAdvisoryEligibility`. Java findings carry
`language: JAVA` and `scanProfile: JAVA_DETAILED`. Common-only runs produce the three
mock scanner records and no findings or evidence. Empty manifests are common-only.
Omitting the manifest preserves the original mock finding and evidence output, with no
planning or Java eligibility annotation. All outputs remain simulated.

Classification is case-sensitive and uses names only. Kubernetes detection is a path
hint for YAML under `k8s/` or `kubernetes/`, or named `kubernetes.yaml`/`.yml`; arbitrary
YAML is unknown. No file contents are inspected. The mock Java finding remains a fixed
fixture and does not assert that its sample file exists in the submitted manifest.

Retries accept reordered and duplicated paths as the same manifest. Changing the path
set, or adding/removing a manifest for an existing run, returns
`REPOSITORY_MANIFEST_MISMATCH` without changing stored results.

## AI Plane Boundary

AI advisory requests contain a normalized finding, reduced redacted evidence, and model
version. They must not contain SCM credentials, full repository input, or raw unbounded
scanner payloads. AI output is advisory metadata only and cannot override deterministic
scanner findings or policy decisions.

For the Java-first slice, AI advisory eligibility is limited to normalized findings from
the `JAVA_DETAILED` scan profile. AI requests may include language and scan profile
metadata, but they must not include full Java files, full repository archives, source
uploads, raw scanner output dumps, SCM credentials, or policy override fields. Java
findings remain Scan Plane outputs; AI Plane outputs are advisory metadata such as root
cause, exploitability context, remediation plan, confidence band, and uncertainty note.

## EvidencePack

EvidencePack metadata includes tenant ID, scan request ID, data classification, tenant/scan
scoped object key, expiry, byte size, and redaction status.
The current metadata contract rejects expired evidence and retention beyond seven days.

The `AiAdvisoryRequest` TypeScript boundary requires `JavaDetailedFinding` and evidence
with `redacted: true`. This is a compile-time contract, not an inference gateway or
runtime authorization check. No AI requests are dispatched in this milestone.

## PolicyDecision

PolicyDecision is structured. It includes enforcement action, comment allowance, dashboard
visibility, ticket/block requests, reason codes, required coverage set, waiver application,
stale suppression, and AI advisory visibility.
