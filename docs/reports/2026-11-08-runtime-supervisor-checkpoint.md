# Private production runtime checkpoint — 2026-11-08

Current operational documentation is indexed in
[production docs](../production/README.md); exact acceptance scope and uncompleted
baseline items are in [release evidence](../production/release-evidence.md) and
[remaining work](../production/remaining-work.md). Historical notes below preserve
the state of earlier implementation slices.

2026-11-09 update: [source capture](../production/source-capture.md) records commit
feb7628, draft PR #337 and hosted CI success for the independent snapshot. Statements
below saying hosted CI had not run refer to the earlier deployment stage. The
running images were not rebuilt/redeployed and dev integration remains uncompleted.

## Current deployed state (supersedes historical notes below)

Private production ingress is enabled at `https://aegisai-aws.tailaca7d2.ts.net/`.
The owner confirmed on a phone that connected repositories and the completed scan
are visible after actual GitHub authentication. This is the explicitly authorized
one-EC2, single-owner/private-organization Java profile, not the general multi-tenant
or separate-node baseline. AI is DISABLED; scans and results need no model/API key.

API: `ec2-runtime-20261108-122119`, 266-file dirty snapshot, base
`a8e51eb26d082fefe420cb150b43815f09fbbcf7`, archive SHA-256
`66e0c49897d81797fcd77d605dd98897dfa8c5f35518d69b59d53614c1c3732e`.
Host worker bundle: `host-worker-20261108-122846.tar.gz`, SHA-256
`024d980e856dff855cc3ddf6a90720fee76454f113ffa95f79f556cbd460a3c4`.

Frontend: `ec2-runtime-20261108-124735`, 275-file source snapshot, SHA-256
`8d49489993a3b2252dab758be5d144ab05a8b1c4d006ece80a7a3075ff40a69d`.
The initial dedicated runtime screen changed the existing design without being
requested. Following the owner's feedback, the original cream/brass theme,
display typography, sidebar and Dashboard/Repositories/Scan layout classes were
reapplied to the real runtime contracts. No legacy fixture endpoints or demo
sessions were enabled. API/shared/dependency inputs were byte-compared against the
API release before this frontend-only replacement. Original unsupported AI/PDF,
GitLab, compliance and source-upload claims are not exposed as functioning features.
The phone confirmation preceded this design correction; no later visual sign-off
or automated browser screenshot is claimed. CUA could not initialize its kernel.

## Verified production behavior

- Actual selected private Java repository 1087577243 at immutable commit
  `f79652f3912f7ad8170db7e46a2c37cc0e8de2e9` completed three real scanner runs.
  Scan `scan_request_77c5b7c8-c3a8-4b01-be7e-7a348e0664ea` has dispatch SUCCEEDED,
  zero normalized findings, LIMITED coverage, AI DISABLED and no merge enforcement.
  Zero findings is not a repository safety guarantee. The request used the existing
  verified owner through the operator acceptance service, not an invented session;
  browser-initiated scan submission itself has not been claimed as verified.
- After completion, source tmpfs was empty, parser sandboxes absent, and transient
  source gateway units stopped. No customer build/package/code command ran.
- A private SSE-KMS S3 evidence object was read with tenant checks and a read audit.
  It contains reduced rule metadata, no source fragments. The real cloud probe
  exercised the same retention implementation and confirmed expired-object removal.
- Two Secrets Manager entries separate identity and SCM credentials. API/broker load
  values in memory using the restricted existing-instance role. Boot uses native AWS
  CLI, independent of Docker/operator credentials, to place only the DB password in
  root-only RAM. Current container configuration has secret references, no SCM PEM
  mount. Inactive root-only legacy recovery files still exist; do not claim all
  historical copies are managed-secret-only.
- Actual reboot automatically recovered secret loading, all app workloads, broker,
  dedicated scanner containerd, supervisor and private Tailscale ingress. Reading the
  existing completed scan and encrypted evidence passed; the completed job was not
  replayed. Counts: six migrations, one identity/integration, five repository bindings,
  one scan, three scanner runs and one evidence pack.
- An instance-role encrypted offsite backup was uploaded, downloaded, hash-verified
  and restored into a unique disposable database with the same counts. Nightly
  03:15 Asia/Seoul backup timer is enabled, with 14-day S3 lifecycle retention.
- Evidence cleanup runs every 15 minutes with 7-day expiry, deletion auditing,
  retry/orphan cleanup and readiness blocking on unhealthy/stale status. Egress and
  vulnerability DB refresh run every six hours; DB snapshots retain only two versions.
- Private ingress pause (root 503) and restoration (root 200, unauthenticated runtime
  401, legacy APIs/operator routes 404) were exercised. This proves access rollback;
  it does not prove arbitrary older application images are compatible with the schema.
  Use forward repair/verified data restoration for incompatible releases.

## Validation and provenance

All six canonical workspace checks passed once for the managed-runtime release.
Target deployment additionally passed HTTP 3, PostgreSQL 16 and native Unix-role 7
checks; affected managed data-plane persistence checks passed 5. The design correction
passed web tests (63), typecheck, changed-file lint, production image build and live
frontend route health. Unchanged SQL/scanner suites were not repeated for that edit.
Hosted GitHub CI was not run. Both releases are dirty snapshots, not clean commits.

Local evidence: `output/deploy/managed-runtime-candidate-deploy.log`,
`actual-private-java-scan.log`, `actual-scan-cleanup-proof.log`,
`managed-runtime-live-checks.log`, `first-offsite-backup-restore.log`,
`managed-boot-recovery.log`, `private-access-rollback-check.log`,
`restored-design-{tests,types,lint,deploy}.log`, and `final-*.log`.
Root-only host reports live under `/opt/aegisai/operator/acceptance/`, with separate
`web-release.json`, `offsite-backup-status.json` and `private-ingress-status.json`.

## Operating limits

One actual scan at a time, bounded source/output and sandbox resources. No public
Funnel, public inbound, onboarding, webhook intake, GitLab, AI inference, PDF export,
SCM writes or multi-tenant/HA certification. The active root and offsite backup are
encrypted. The user declined cleanup of the original unencrypted root volume and
snapshot; they remain retained. Original Oracle service was not modified.

See `deploy/aws-ec2/PRODUCTION-ACCESS.md` for operating/recovery steps. Future work:
optional local/API advisory integration, additional supported language/coverage,
clean reviewed source release/hosted CI and broader separate-plane infrastructure.

## Historical implementation notes (not current status)

Latest continuation: candidate 054147 passed 49 provider/lifecycle tests, 33 real
PostgreSQL checks and six native Unix-broker checks in the target image before
replacement. The native gate is now mandatory in the deployment script and CI
configuration (hosted CI has not run). Default local tests remain 168, and all
lint/typecheck/build/schema/runtime-layout checks passed. New snapshot: 214 files,
base `a8e51eb26d082fefe420cb150b43815f09fbbcf7`, SHA-256
`1b05cc26b0f125d0d01c25ca50e1b9d8dacb13ec2bb33c5a4fafe1d4027f7b74`.

After replacement, all four app workloads were healthy and authentication preflight
was reattached. Fresh backup `verified-live-20261108-054408.sql.gz` restored into a
disposable database: four migrations, one identity, one integration, five bindings,
zero scans; 1.149 seconds for this small database is not an RTO claim. The verification
DB was stopped afterward. The broker code is packaged but no production broker or
consumer is active. Root/ordinary API ingress remains closed.

Additional native acceptance: 20 synthetic-provider fetch cases, including strict
tenant/scan storage binding; three temporary-writer/sealing/link-rejection cases;
all three real tools and timeout/output-limit cleanup against the separate new jobs
path. The privileged daemon directory remains root-only. Raw scanner logging is
disabled; corrected sandbox-kill/attachment-drain cleanup passed ten fault repetitions
before the storage-path change and one complete acceptance afterward. No actual
repository fetched or customer code executed.

The user requested no unnecessary repeated testing. Subsequent slices use targeted
checks for changed boundaries; full completion validation remains the final gate.
AI may be disabled initially, use an API temporarily, and later use the user's
local model. Deterministic scans must operate without any AI provider or credential.

The new host supervisor library `apps/scanner/runtime.py` passed native trusted-fixture
acceptance through the separate containerd/gVisor daemon. It requires a fresh scan-owned
no-exec/nosuid/nodev tmpfs, uses the approved immutable OCI alias with pulls disabled,
and supplies no network, host credentials or daemon sockets to the parser sandbox.
CPU, memory, PID, time and output limits are explicit. Repository scanner configuration
is not accepted. Only fixed Opengrep-core/Trivy/Syft commands are exposed by its API.

Acceptance evidence: all three real tools returned valid expected fixture results;
the positive Java file produced its expected weak-cipher finding, safe file had none,
SBOM included the declared dependency and offline Trivy detected CVE-2021-44228.
Trusted timeout and output-flood fixtures triggered the expected fixed failure codes.
Both failure paths removed the actual sandbox. Final cleanup verified that the
per-scan tmpfs was unmounted and its directory removed. No customer code was executed,
package installed, repository source downloaded or application ingress promoted.

Batch Opengrep target metadata also passed the earlier three-positive/safe-negative
fixture, using the protocol pinned by the upstream v1.33.1 interface commit.
The loader now creates a canonical local image digest alias: an imported tag/config ID
alone was not resolvable with nerdctl's pull-never mode. It verifies the alias descriptor
before use; there is no tag or runc fallback.

`runtime-execution.md` defines the next integration slice: ten-minute opaque fetch
capabilities, source gateway separated from Control Plane, immutable bounded fetch,
durable fenced results, evidence and policy. The library is not a background worker.
Broker/gateway, queue handoff, source-boundary and crash regressions, normalization,
durable results, scheduled DB/evidence maintenance, UI and operational acceptance
remain open. Do not expose scan creation based on fixture acceptance alone.

The source gateway helper additionally passed 19 synthetic-provider tests against
actual tmpfs (including identity/repository/commit mismatch, Git object integrity,
unsafe entries, limits, expiry and mid-fetch authority loss). It rechecks trusted
broker authority before each source request and revokes on failure. No actual
repository has been fetched.

The additive fetch-capability migration/library passed 32 combined PostgreSQL
tests locally: ten-minute SQL TTL, hash-only secrets, composite scope constraints,
one-use concurrent claims, rotation, stale fences, current broker epoch, suspension,
unconfirmed revocation and transactional audit rollback. The upstream read resource
is private memory state, not a serializable worker credential. Full default tests
passed 168; final lint/typecheck/build/schema and two compiled runtime checks passed.
Candidate `ec2-runtime-20261108-042848` repeated 49 provider/lifecycle and 32 database
checks successfully in the target Node 22 image. Real selected-repository upstream
resource creation/revocation passed without transferring source. Four migrations
are applied; all four workloads healthy. Fresh data backup restored into a disposable
database with matching identity/integration/binding counts. Authentication preflight
remains 200; root and ordinary API ingress remain 503. No broker/gateway endpoint or
consumer has been activated. Hosted CI has not run.

The 209-file dirty source snapshot uses base commit
`a8e51eb26d082fefe420cb150b43815f09fbbcf7` and archive SHA-256
`c3dc92681a37cd986858893e547ce9a00b882df26c7013694dc7c5fcfb471b62`.

The original unencrypted EBS volume/snapshot are retained following the user's
response declining cleanup. The active root and completed rollback-copy snapshot
are encrypted. Do not claim all historical copies are encrypted.
