# Production runtime scope

## Current acceptance and reading context

The constrained private Java runtime was deployed on 2026-11-08. Read
[current documentation](../../docs/production/README.md),
[acceptance evidence](../../docs/production/release-evidence.md) and
[remaining work](../../docs/production/remaining-work.md).
The initial/discovery/queue sections below retain incremental requirements and
their historical activation limits. A statement such as no consumer in that slice
does not describe the final integrated runtime. Current activation is recorded in
tasks.md and release evidence. General-service DOCX compliance remains unclaimed.

## Reclassification

This follow-on package authorizes the real runtime work deferred by 002. The DOCX
product baseline and all 002 trust boundaries still apply. First production scope
is GitHub Cloud and deterministic Java scanning; GitLab and AI inference remain
future slices and must be visibly unavailable rather than simulated.

On 2026-11-08 the user confirmed the planned final AI provider is their own local
model, with an external API permitted as a temporary substitute. AI is optional:
the first deployment runs with AI disabled and requires no model/API credential.
Unavailable or failed advisory inference must never prevent deterministic scans,
result persistence or result viewing. Do not show fixture advice as actual output.
API/local provider integration may follow behind the same reduced-evidence,
advisory-only boundary; neither provider becomes a finding or policy authority.

## Initial persistence slice

User login may use either the legacy dedicated OAuth App or the new distinct
identity-only GitHub App (Email addresses read only, no repository-content or
organization-membership authority). The identity App is never installed for
repository access; its signing key is discarded. Its OAuth client ID/secret are
independent of the organization SCM App signing key and installation credentials.
Use PKCE/state for both login modes and retain no user access/refresh tokens.
The single-instance private deployment requires an explicit numeric GitHub
account admission list at startup and rechecks admission for existing sessions.

- Provision the deterministic personal tenant and user identity after verified
  GitHub OAuth, without retaining the OAuth access token.
- Persist integrations, repository bindings and scan requests with Prisma.
- Tenant predicates and active-tenant checks apply to every access.
- Concurrent retries must return the same integration/binding/canonical scan.
- Integration removal revokes access but preserves historical scan/audit rows.
- Suspended tenants and revoked integrations cannot start new scans.
- Never fall back to process memory when the database is unavailable.
- Mock integration registration, token issuance and scanner execution must reject
  production requests until their trusted runtime replacements exist.
- In-memory doubles are allowed only in test support, never selected by production DI.

## GitHub installation discovery slice

Add a separate authenticated, CSRF-protected installation-link route accepting
only a numeric installation ID and 1–100 selected numeric repository IDs. Verify
the installation using the configured GitHub App JWT. For a personal installation,
require the account ID to equal the authenticated GitHub identity. For an
organization installation, require Organization Members-read permission, resolve
the login from the durable GitHub user ID, then verify active administrator
membership with matching user and organization IDs using the App installation
token. No user OAuth repository or organization scopes are added for this check.
Reject suspended installations and missing Contents-read permission. Repository
names, branches, visibility and principal IDs come only from provider responses.

Use an installation token with only Metadata-read permission scoped to the selected
repository IDs to retrieve repository metadata (plus Members-read only for
organization authority verification). Bound provider response sizes and
timeouts, reject redirects and never follow provider-provided pagination URLs.
Revoke the discovery token before persisting verified bindings, including on
failure. Do not expose or persist token values or provider error bodies. A failure
must not create an integration. The initial slice used an external read-only key
file; the integrated production runtime loads its key from Secrets Manager into
memory. Missing App configuration returns 503. Existing mock routes stay blocked.

This slice does not provide scan credentials. GitHub installation tokens normally
last one hour; a separate broker enforcing the contract's ten-minute maximum and
durable revocation/worker delivery is still a release gate. No token is returned
from this route. Live installation acceptance requires an actual configured App.

## Immutable GitHub branch resolution prerequisite

Resolve a requested branch to a full forty-character commit SHA using the trusted
App client, never a caller-supplied SHA. Recheck installation/administrator and
selected-repository authority first. For the resolution call, issue Contents-read
and Metadata-read permission scoped to exactly that repository. Read the Git ref
metadata endpoint only (not the commit endpoint that can include source patches).
Require the exact requested refs/heads value and a commit object with a canonical
SHA. Reject invalid Git branch names, missing branches, tags and malformed responses.
Revoke the temporary metadata-resolution token before returning, including failures.
No source or credential is returned. This helper alone does not enable scan creation
or replace the separate worker credential broker gate.

## Durable dispatch queue slice

Write exactly one tenant-attributed dispatch job in the same transaction as a new
canonical scan request. Duplicate requests reuse the existing job, including its
terminal state. Backfill only existing QUEUED/PLANNING requests when migrating.
Integration revocation cancels pending/leased jobs atomically with queued scans.

Use PostgreSQL as the durable dispatch queue, with Serializable transactions,
server database time, a 60-second lease and unguessable per-attempt fencing token.
Limit dispatch leases to two globally and one per tenant. Retry transient failures
with bounded exponential backoff, at most five attempts, then mark dead-letter and
fail the scan. Lease expiry invalidates old acknowledgements and schedules a retry.
Suspended tenants, revoked integrations and canceled scans cannot be claimed or
acknowledged. Audit terminal transitions without credential values or raw errors.

This is an at-least-once dispatch substrate, not exactly-once scanner execution.
No background consumer or HTTP lease endpoint is enabled in this slice. Future
consumers must make provisioning idempotent by scan ID, reconcile old sandboxes
before redelivery, and acknowledge only after a durable handoff. Acknowledging
dispatch must not mark a scan COMPLETED. Real isolated worker delivery remains a
release gate; do not expose scan creation based on queue tests alone.

## Baseline production gates

GitHub installation ownership verification and separate SCM credentials; immutable
commit resolution; outbox and retry-safe scheduling; per-scan ephemeral VM/sandbox;
approved scanner execution without customer builds/packages/code execution;
bounded output normalization; real durable results; encrypted TTL evidence;
deterministic policy and coverage enforcement; supported frontend contracts;
configured OAuth; backup restoration; tenant/egress/security regression; bounded
cost and capacity; observability and tested rollback.

Operator AWS API authentication is temporary and independent of the current
application instance role. Only the existing EC2 is authorized for compute. The
integrated private release has actual scan, cleanup, evidence and recovery evidence;
see its dated release record. These checks do not certify all baseline gates or
authorize general-service expansion. Never weaken isolation to finish deployment.

## Mandatory rollout/scaling expansion — 2026-11-09

User instruction makes Blue/Green, Canary, actual Kubernetes RollingUpdate and
HPA implementation plus measured verification mandatory, all currently incomplete.
Follow [existing execution plan](../../docs/reports/2026-11-07-production-deployment-plan.md)
4/G and 9 and [remaining work](../../docs/production/remaining-work.md).
The existing commit-based private release is deployed; new requirements do not
retroactively certify new strategies. Keep one existing EC2, no extra compute,
scanner boundaries and applicable 005/006 gates. Capacity and architecture review
precede changes; lab-only proof cannot substitute for actual-service completion.

## Restored mandatory platform scope — 2026-11-09

The user's follow-up instruction reclassifies the initially omitted IaC, GitOps/CD,
supply-chain security and correlated observability work as mandatory H1-H4, alongside
G1-G4. Implementation-ready acceptance is in
[the existing execution plan](../../docs/reports/2026-11-07-production-deployment-plan.md)
section 4/H and [remaining work](../../docs/production/remaining-work.md).
Require actual Terraform-managed approved resources and reproducibility, GitOps
deployment/drift/recovery with limited OIDC, deployment image scans/SBOM/signature
rejection gates, and AWS request-to-result logs/metrics/traces with data/cost limits.
All four remain incomplete. Preserve one existing EC2, no additional compute,
independent scanner isolation, no source/secret telemetry and applicable qualification
gates. No live migration or new resource is authorized by this document change.

H4 observability explicitly requires Grafana, Loki and Prometheus, all actually
used and verified. Keep OpenTelemetry tracing and choose its storage backend
separately; metric/log dashboards alone do not complete distributed tracing.
Preserve the one-existing-EC2 resource/cost constraints. This stack declaration
does not authorize installation or production changes.
