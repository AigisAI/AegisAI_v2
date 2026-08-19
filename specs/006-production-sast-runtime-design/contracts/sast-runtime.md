# Contract: Production SAST Runtime

The executable TypeScript contract is exported from
`packages/shared/src/types/sast-runtime.ts`. This document defines component ownership,
transport behavior, state transitions, validation order, and policy semantics.

## Component Boundary

```text
Control Plane Scan Planner
  -> signed lane queue
  -> Scan Orchestrator
  -> microVM Provisioner
  -> one ephemeral Scanner Sandbox
  -> write-only Result Ingress
  -> Artifact Validator
  -> Normalizer
  -> Correlator
  -> Evidence Builder
  -> Data/Security Plane + Policy
  -> reduced evidence reference to AI when eligible
```

The Control Plane does not receive repository content. The sandbox does not receive
Control Plane database, policy-write, comment-write, integration-admin, or AI credentials.

## Queue Contract

Fast and Deep lanes use separate queues:

- `scan.fast.v1`
- `scan.deep.v1`
- `scan.dead-letter.v1`

Each message contains only:

- message schema version
- tenant, repository binding, scan request, and canonical scan identifiers
- fixed commit SHA and contextual target ref
- lane, profile ID/digest, policy version, scanner-set version/digest
- isolation class
- result-ingress, evidence-output, and audit references
- issued and expiry timestamps
- issuer workload identity and detached signature reference

Messages must not contain repository content, credential values, arbitrary commands, CLI
flags, environment-variable maps, or executable rule/config bodies.

Consumers validate signature, expiry, tenant/repository/scan binding, canonical key,
profile/scanner-set availability, kill switches, and quota before acknowledging. Queue
leases are shorter than the sandbox hard timeout and are renewed by the orchestrator. The
DLQ preserves tenant and scan attribution but not payload secrets.

## Planner Runtime Contract

`SastScanPlannerService` composes the immutable scan request with
`TrustedSastRepositoryMetadata`, an approved profile policy, a signed scanner set, a signed
queue-policy set, and a versioned counter-only queue-usage snapshot. These are internal runtime inputs;
the public scan-request DTO cannot provide source content, language overrides, scanner
commands, executable configuration, queue limits, credential values, or artifact bodies.

The session-authenticated `POST /api/scan-requests` creates only immutable user intent. An
approved metadata/preflight workload continues that request through the
internal-service-authenticated `POST /api/sast-planning/:scanRequestId` boundary. That boundary
is the only HTTP entry point for trusted metadata, signed profile/scanner/queue policy, and
authoritative usage counters. The session-authenticated scan status returns only the reduced
planning state. This two-step flow prevents a user from supplying trusted planning inputs while
ensuring the planner is part of the production request lifecycle rather than a test-only helper.
The internal DTO validates every nested planning object against the shared runtime predicates and
an exact allowlist of keys; unknown command, environment, plugin, or executable-config fields are
rejected before the planner runs.

Trusted repository metadata is accepted only when it contains a full 40- or 64-character
commit SHA, inventory digest, attestation reference, collection timestamp, normalized
language byte/file signals, manifest names, and bounded resource counters. Its repository
binding and commit must equal the immutable scan request. Profile-policy and scanner-set
versions must also equal the versions already bound to that request. The planning timestamp
must be valid UTC, and metadata collected in the future relative to that timestamp is rejected.

Selection is deterministic for v1:

| Lane and trusted inventory | Decision | User-visible coverage |
| --- | --- | --- |
| Fast with Java only | `JAVA_FAST_V1` | language SAST complete for the approved profile |
| Deep with Java only | `JAVA_DEEP_V1` | language SAST complete for the approved profile |
| Deep without Java | `COMMON_DEEP_V1` | common static coverage only; language SAST unavailable |
| Fast without Java | reject | `UNSUPPORTED_LANGUAGE_FOR_FAST` |
| Java plus another source language | reject | `UNSUPPORTED_POLYGLOT_PROFILE` |
| Selected profile disallowed by policy | reject | `PROFILE_NOT_ALLOWED_BY_POLICY` |

The profile limit check returns explicit repository bytes, selected bytes, file count,
single-file bytes, and path-depth reason codes. Missing or invalid required scanner, rule,
vulnerability database, schema, or normalizer assets reject planning before queue admission.

The SHA-256 canonical key binds tenant, repository, lane, target context, full fixed commit,
trusted inventory digest and attestation reference, policy, isolation class, immutable profile digest, scanner-set
version/digest, every scanner image and wrapper digest, every sorted rule-bundle digest,
vulnerability database
version/digest, schema digest, normalizer digest, and SBOM schema. Result/evidence/audit
references are scoped to tenant and scan but are not mutable customer inputs.

Queue policy is itself versioned, digest-pinned, signed, and provenance-attributed. Its usage
snapshot must carry the authoritative lane/day `snapshotVersion` and match the tenant,
repository binding, lane, and current UTC daily window of the decision. Repository-active counts
cannot exceed tenant-active counts, and tenant-queued counts cannot exceed the lane total. Fast
and Deep must resolve to `scan.fast.v1` and `scan.deep.v1` respectively. Admission evaluates
tenant active/queued/daily limits, repository concurrency/frequency, and lane queue capacity.

The pure policy evaluator is not an admission authority. `SastQueueAdmissionService` must compare
the complete observed live counters and `snapshotVersion` with the authoritative lane-global
ledger, compare the daily budget in a separate normalized UTC-day row, and in one critical section
create an idempotent reservation, increment tenant/lane/daily counters, record the repository
admission time, and advance the version. A replayed or concurrently consumed
snapshot is `DEFERRED` as `QUEUE_USAGE_STALE`; it cannot consume capacity. The production adapter
for this boundary must use one shared transactional/CAS store across API replicas before queue
publication; a per-replica cache is not authoritative. `PrismaSastQueueAdmissionStore` implements
that boundary with PostgreSQL `SERIALIZABLE` transactions, bounded serialization/unique-conflict
retries, durable reservation records, one live ledger per lane, and canonical millisecond UTC
daily-budget keys. Equivalent UTC representations therefore cannot create parallel daily budgets,
active/queued work cannot disappear or become ghost usage at midnight, and process restarts retain idempotency.
The immutable `ScanRequest` exists in PostgreSQL before reservation. The admitted planning state
and complete immutable `SastScanPlan` are written with the reservation in the same transaction,
and the reservation has a restrictive foreign key to that request. A dispatcher therefore receives
the exact profile, scanner-set snapshot, repository attestation binding, and output references even
after every API process restarts; it never reconstructs execution inputs from mutable state.

Capacity outcomes are `DEFERRED` with a bounded retry condition; malformed policy or usage is
`REJECTED`. Within one lane, dispatch interleaves the oldest item from each tenant using
deterministic tenant round-robin ordering, with the last-served tenant rotated to the end. Admission
capacity and dispatch order are separate concerns: durable admitted reservations form the pending
dispatch set, while `claimNextForDispatch` advances the shared ledger cursor in the same serializable
transaction that acquires a bounded dispatch lease. Claiming searches all pending UTC windows for
the lane through the lane-global ledger and selects the oldest eligible backlog, so a day rollover
or dispatcher restart cannot hide older work. An acknowledgement is accepted only from the lease owner before lease expiry;
unacknowledged work becomes eligible for one retry after the first expiry. After two total expired
leases, the next claim atomically marks the reservation and scan request `FAILED`, decrements queued
lane/tenant counters, and advances the ledger version instead of redispatching forever. A valid
acknowledgement atomically moves lane/tenant counters from queued to active and marks the durable
scan request `RUNNING`. Completion atomically decrements tenant/repository active counters, advances
the ledger version, records the terminal state, and is idempotent for the same worker and outcome.

The public scan status exposes only `ADMITTED | DEFERRED | REJECTED`, selected profile,
coverage claim, queue name, queue-policy version/digest, canonical key, reason codes,
retry-after seconds, and timestamp.
It never exposes trusted inventory internals, source, credentials, or scanner configuration.
Once a canonical planning identity is recorded it cannot be replaced by a different identity.
An admitted decision is idempotent across delivery timestamps and immutable, and planning cannot rewrite a running,
completed, failed, or canceled scan.

Scan creation resolves the active tenant-attributed SCM integration and repository binding from
the durable Control Plane store. Process-local inventory caches are not authoritative, so a restarted
or newly scheduled API replica reuses the persisted binding identity and rejects revoked context.
Scan-request status changes read, validate, and write inside a serializable transaction. Running or
terminal requests cannot move backward, while identical status delivery remains idempotent.

SCM repository removal soft-revokes the durable repository binding instead of deleting immutable
scan history. Revoked bindings cannot create new work; historical requests and reservations retain
their tenant/repository attribution, and an authorized re-add explicitly restores `ACTIVE` state.

Risk escalation signals on the immutable request select `RESTRICTED`; ordinary SAST requests are
raised from `STANDARD` intent to the mandatory `HARDENED` execution floor by the planner.

## Profile Contract

A known profile ID is accepted only when the complete snapshot exactly matches its immutable
platform definition and its digest matches the compiled approved-profile allowlist. A caller
cannot narrow required scanners, capabilities, limits, or path controls while retaining the
same profile ID.

### `JAVA_FAST_V1`

- Scope: changed `.java` files plus bounded symbol/import context, relevant Java manifests,
  changed IaC, and secret scanning within the selected file set.
- Required: OpenGrep SAST and Trivy dependency/secret coverage.
- Optional: Syft incremental inventory; it does not satisfy Deep SBOM coverage.
- Limits: 1 GiB repository metadata, 256 MiB selected bytes, 25,000 files, 2 MiB per file,
  5,000 findings, 64 MiB/25,000-record scanner artifact, 1 MiB bounded stdout/stderr,
  1,024 file descriptors, and a 15-minute hard timeout.
- Performance target: p95 <= 10 minutes.
- External publication: only with complete required coverage and non-stale commit context.

### `JAVA_DEEP_V1`

- Scope: full bounded repository excluding approved generated/vendor behavior.
- Required: OpenGrep SAST; Trivy dependency, secret, and IaC; Syft SBOM.
- Limits: 2 GiB, 250,000 files, 5 MiB per file, 25,000 findings,
  256 MiB/250,000-record scanner artifact, 1 MiB bounded stdout/stderr,
  2,048 file descriptors, and a 60-minute hard timeout.
- Performance target: p95 <= 45 minutes.

### `COMMON_DEEP_V1`

- Scope: dependency manifests, secrets, IaC, and source-workspace package inventory.
- Required: Trivy and Syft.
- Optional OpenGrep results are non-authoritative until an approved language profile exists.
- AI advisory eligibility: false.
- The UI and policy must not label this profile as language-complete SAST coverage.
- Its resource/artifact/log/timeout ceiling equals `JAVA_DEEP_V1`.

Languages after Java must pass `language-profile-extension.md`. Merely enabling generic rules
or recognizing an extension cannot create a language-complete profile.

## Repository Fetch Contract

1. Orchestrator creates an attempt and requests a microVM.
2. Provisioner establishes a unique workload identity and empty encrypted scratch volume.
3. Sandbox exchanges its attested identity for one fixed-scan repo-read credential through
   Token Broker.
4. Sandbox fetches the fixed commit SHA. It never resolves a mutable ref itself. Before checkout,
   it inventories Git tree/object metadata and enforces the selected profile's file-count,
   expanded-byte, single-file, and path-depth materialization limits.
5. Only a tree within those bounds is checked out. Credential is held in memory or tmpfs,
   excluded from process arguments, and wiped and revoked before any scanner starts.
6. Fetch metadata records the remote host, fixed commit, object count, and byte count, but
   never records URL userinfo or credential material.
7. Network egress is phase-bound: fetch permits HTTPS only to the SCM host from the signed
   repository binding. The remote, Git metadata, credential, and SCM egress rule are removed
   before scanner execution switches to Result Ingress and telemetry only.

Submodules and LFS object content are disabled by default. A future policy must enumerate
each allowed secondary repository and issue separate scope-bound access.

## Hostile Repository Preflight

Preflight runs before any scanner and in the same microVM boundary. Validation order is:

1. Normalize path separators and Unicode to NFC.
2. Reject NUL, control characters, absolute paths, drive/UNC roots, and parent traversal.
3. Detect case-fold and Unicode-normalization collisions.
4. Resolve symlinks without following outside the workspace root.
5. Enforce path depth, repository bytes, selected bytes, file count, and single-file size.
6. Classify generated, vendor, fixture, hidden/system, LFS pointer, submodule, and archive
   entries.
7. Refuse archive expansion.
8. Produce an inventory digest and `ACCEPT`, `REJECT`, or `RESTRICTED_ESCALATION` decision.

The selection input is explicit: Deep uses `ALL_SCANNABLE`, while Fast supplies the
deterministic changed/context path allowlist. Selected bytes include only scannable entries in
that selection. The selection mode and normalized sorted paths are part of the length-prefixed
inventory digest, so a changed-file selection cannot be substituted after attestation.
Fast scanners never receive `/workspace/repository` as their input. The provider materializes
a platform-owned, read-only `/workspace/selected/<preflight-inventory-sha256>` projection from
the attested allowlist, excludes every unselected entry, and attests the projection path and
source inventory digest. Deep scanners use the read-only repository root. A missing or
mismatched projection fails closed before process start.

For an accepted decision, the platform signs an attestation over the attempt ID, fixed commit,
path-policy version, normalized inventory digest, and decision. The control plane passes that
attestation reference and digest as immutable wrapper inputs. Immediately before each scanner
starts, its wrapper re-manifests the exact read-only repository mount visible to that scanner,
using the same canonicalization algorithm and limits, and compares the new digest with the
attested digest. The wrapper records both digests and the attestation reference in the artifact
envelope. A missing attestation, stale attempt binding, re-manifest failure, or digest mismatch is
a `SECURITY_VIOLATION`: the scanner does not start, the sandbox is terminated, the attempt and
artifact metadata are quarantined, and coverage cannot become complete.

The T022-T024 runtime implementation persists only attempt-bound credential lease metadata and
a SHA-256 credential fingerprint. The credential value remains in an opaque memory buffer and a
verified tmpfs handoff file, is never accepted in command arguments, and is zeroized after fetch.
Lease reservation requires a `RUNNING` durable scan and database-enforced tenant/repository/scan
association. Workload and preflight signing keys are distinct from each other and from the token
encryption key. Replay uniqueness is tenant plus attempt scoped. Distributed HTTP consumers
complete the lease with a fresh scope-bound workload attestation and `WIPED` or `REVOKED`
disposition; a bounded background reconciliation atomically revokes expired nonterminal leases.
The durable active repository binding determines the SCM host and repository path; callers cannot
substitute a remote URL. Fetch uses the full fixed SHA with `--depth=1`, no tags, no submodule
recursion, LFS smudge disabled, pre-checkout tree/object limit enforcement, detached checkout
verification, remote removal, and `.git`
metadata destruction before scanner handoff. Preflight binds each entry's Git object ID so
same-size content replacement changes the bytewise-sorted, length-prefixed UTF-8 inventory
digest, uses the validation order above, and signs its decision. T025-T028 connect this
verified state to a plan-digest-bound sandbox attestation, fixed scanner wrappers, bounded
runtime observations, signed attempt number/deadline, and signed cleanup evidence. The default provider intentionally fails
closed until the 005 rollout installs a live microVM adapter.
The repository credential issuer uses an opaque synthetic value only outside production for
contract and handoff tests. Its default production path fails closed until the provider rollout
installs a GitHub App/GitLab scoped credential-minting adapter; it never treats the synthetic
value as a live SCM token.

## Scanner Wrapper Contract

A wrapper is an immutable image entrypoint with no shell interpolation. It accepts a typed
profile file generated by the platform and owns exact tool arguments.

Required wrapper controls:

- scanner binary/image and wrapper digest verification before start
- non-root identity, read-only root, read-only repository mount, private writable output
- phase-bound default-deny network: signed SCM host only during fetch, then Result Ingress
  and telemetry only with no runtime database or rule download during scanning
- CPU, memory, disk, process, file descriptor, output, finding, and wall-clock enforcement
- bounded stdout/stderr capture with secret redaction
- deterministic locale, timezone, and clock metadata
- machine-readable output to a private path
- explicit exit-code map to `SUCCEEDED`, `FAILED`, `TIMED_OUT`, or `QUARANTINED`
- final artifact digest and envelope production

The wrapper cannot accept tenant-provided command fragments, plugins, environment maps, or
executable rules.

The implemented wrapper derives fixed platform paths and does not accept a workspace or output
path from the caller. Deep input is `/workspace/repository`; Fast input is the
inventory-digest-bound selected projection:

- OpenGrep: `scan -f <pinned-rule-asset> --sarif-output=<private-output>
  --no-autofix --disable-nosem --no-git-ignore --x-ignore-semgrepignore-files
  --disable-version-check ... <read-only-repository>`. Repository ignore files and inline
  suppression cannot reduce authoritative coverage.
- Trivy: `filesystem --format json --output <private-output>` with vulnerability,
  misconfiguration, and secret scanners plus offline/skip-update/disable-telemetry flags.
  Its read-only cache path includes both the pinned vulnerability-database digest and the
  pinned checks-bundle digest. Explicit wrapper-owned config, empty ignore policy,
  platform-owned secret configuration, emitted suppressed results, and signed-profile timeout
  prevent repository `trivy.yaml`/`.trivyignore` files or the tool's five-minute default from
  changing coverage.
- Syft: `dir:<read-only-repository> --config <pinned-wrapper-config>
  --output cyclonedx-json@1.6=<private-output>` with update, archive expansion, repository
  config discovery, Maven/local-cache enrichment, remote-license lookup, external Go
  package-tool execution, file metadata (`SYFT_FILE_METADATA_SELECTION=none`), and raw
  license content (`SYFT_LICENSE_CONTENT=none`) disabled by platform-owned environment.

Only scanners required by the immutable profile are launched. Before every launch, the
provider-facing runtime re-manifests the exact mount and verifies the original signed
preflight decision and inventory digest. Provider observations with unknown fields, raw log
content, mismatched identities/digests, unbounded resources, zero-byte artifacts, or
schema-invalid artifact metadata are rejected and never persisted.
All scanner processes start in `/workspace/output`, not the customer repository, and receive an
exact allowlisted environment.

The sandbox attestation binds the attempt identifier and attempt number and derives one
attempt-wide deadline from its issue time and the signed profile hard timeout. Manifest reads
and all required scanner executions share that cumulative deadline; the provider receives an
abort signal and may not reset the timeout per scanner.
Cleanup has a separate 60-second destruction deadline. Signed cleanup evidence predating the
runtime attempt is rejected.
Attempt admission runs in a serializable transaction, and a database partial unique index
allows only one `VALIDATING`, `SCANNING`, or `CLEANUP_PENDING` attempt for a scan request.
Attempt 1 requires no prior attempt. Attempt 2 additionally requires durable attempt 1 to be
terminal `FAILED` with `failureClass=RETRYABLE_INFRASTRUCTURE`, `retryEligible=true`, a
completion timestamp, and an attempt-scoped final audit event. Scanner defects, input
rejections, security violations, cleanup failures, or completed scans cannot be retried with
an identical second execution.
The signed attempt deadline is durable. A bounded reconciliation loop atomically transitions
any process-orphaned attempt still nonterminal 60 seconds after that deadline to
`CLEANUP_FAILED` and records an attempt-scoped final `sandbox.cleanup_failed` audit event. The
default reconciliation poll is 10 seconds and uses a stage/deadline index plus bounded batches.

## Scanner Responsibility Matrix

| Capability | Authoritative scanner | Required profile | Durable output |
| --- | --- | --- | --- |
| Java source SAST | OpenGrep | Java Fast/Deep | Normalized finding |
| Dependency vulnerability | Trivy | All profiles | Normalized finding |
| Secret detection | Trivy | All profiles | Redacted normalized finding |
| IaC misconfiguration | Trivy | Deep; changed IaC in Fast | Normalized finding |
| Source SBOM | Syft | Deep profiles | Transient inventory only; raw SBOM object/artifact expires in <= 7 days and retained BOM references are SHA-256 digests only |

Rules that duplicate another scanner's authoritative capability are disabled by default.
If retained as supporting evidence, they cannot independently create or block a finding.

## Result Ingress Contract

The sandbox writes only `ScannerArtifactEnvelope` plus artifact bytes to a per-scan,
write-only endpoint. Result ingress checks in this order:

1. mTLS/workload identity and exact expected sandbox attempt, scanner run, and workload
   identity binding
2. tenant, repository, scan, scanner, fixed commit, and profile binding
3. scanner-set, profile, scanner image, wrapper, rule, database, schema, and normalizer digests,
   signatures, provenance, and compatibility allowlists
4. content digest and byte/record count
5. maximum size, nesting, string length, and finding count
6. UTF-8 and schema validation with unknown-field policy
7. path canonicalization and coordinate bounds
8. secret-field and unsafe markup checks
9. produced timestamp and replay/idempotency key

The T029 transport is `PUT
/api/scan-plane/result-ingress/{scanRequestId}/scanner-runs/{scannerRunId}` with
`application/octet-stream`. `x-aegis-sast-artifact-envelope` carries at most 8 KiB of
canonical JSON encoded as unpadded base64url, `Idempotency-Key` is exactly
`sast-ingress-v1:{scannerRunId}:{contentDigest}`, and a positive canonical `Content-Length`
must equal the envelope byte count before streaming begins. The path, envelope, immutable
plan, active attempt, and pre-registered `RUNNING` scanner run must all agree.

The ingress identity comes only from a directly authorized TLS peer certificate containing
exactly one bounded SPIFFE URI SAN. Caller headers, including forwarded client-certificate
headers, are never an identity source. The identity must match both the active durable attempt
and envelope before the artifact stream is passed to object storage. The attempt must remain
`SCANNING`, the scanner run must remain `RUNNING`, and the signed attempt deadline must not
have elapsed. SPIFFE syntax validation requires a lowercase trust domain, path segments limited
to `[A-Za-z0-9._-]+`, and rejects percent encoding plus `.` or `..` path segments.

The Scan Plane object-store interface intentionally exposes only immutable `put` and cleanup
`delete`; it has no read method. A first upload creates one scanner-run-unique
`RECEIVING` record, atomically binds the opaque object key, observed byte count, and observed
digest, then returns only a `PENDING_VALIDATION` receipt. An exact retry returns the same
receipt without overwriting the object; changed-envelope replay fails closed. No GET route
exists and the object key is absent from all ingress responses. The default production
adapter remains unavailable until a Data/Security Plane object-store implementation is
installed, so local filesystem storage cannot become a production fallback.

T030 validates the first upload inline as a bounded tee before the object write completes.
The parser uses fatal UTF-8 decoding, rejects a BOM and duplicate JSON keys, and caps nesting
at 64, each key at 256 UTF-8 bytes, each object at 4,096 keys, strings at 4,096 UTF-8 bytes, number tokens at 128 bytes, and
the document at 5,000,000 tokens. Parsing occurs on globally aligned, at most 4,096-byte slices
independent of transport chunking and never builds the artifact object graph. A parser or schema
failure stops further parsing but continues
draining the already transport-bounded stream to the immutable object so T031 can apply the
same quarantine policy without a second sandbox upload.

The envelope carries a semantic artifact version separately from immutable supply-chain
digests:

- OpenGrep emits `OPENGREP_SARIF` version `2.1.0`.
- Trivy emits `TRIVY_JSON` version `2` and must bind the pinned vulnerability database.
- Syft emits `CYCLONEDX_JSON` version `1.6`.
- Every scanner binds the scanner-set, schema-bundle, and normalizer-bundle digests; OpenGrep
  and Trivy also bind their rule bundle.

Schema-specific streaming inspection enforces root, run/result, finding, and component
container types; required tool/message structures; pinned enum/version sets; and explicit
unknown-field sets at security-relevant boundaries. The immutable binding includes the exact
scanner-run scanner and canonical result-ingress artifact reference in addition to attempt,
identity, inventory, profile, source, and supply-chain digests. It counts SARIF results,
Trivy vulnerabilities/misconfigurations/secrets, and root/nested CycloneDX inventory
components independently of the envelope; `metadata.tools.components` is producer metadata
and never contributes to inventory record count.
The transport observer and validator independently recompute content SHA-256 and bytes and
must agree with one another and the envelope; records are independently counted and checked
against the envelope and immutable profile limits. OpenGrep and Trivy records are additionally capped by the smaller
`maxFindings` limit, while CycloneDX inventory components use `maxArtifactRecords`.

Artifact paths must be NFC repository-relative canonical paths with bounded length/depth and
no absolute, drive, UNC, control, empty, dot, or parent segments. Case-fold ambiguity is
rejected, and unique retained paths cannot exceed the smaller profile file/artifact-record
limit. SARIF URI references may use only canonical uppercase percent-encoding; encoded
separators, encoded unreserved characters, and indirect `uriBaseId`/artifact-index resolution
are rejected, then the decoded direct path must match
the provisioner-attested inventory exactly. Positive safe-integer lines and columns are
checked against `2,147,483,647` and, when present, the exact attested file line/column bounds.
The attestation provider is scoped to tenant, repository, scan, attempt, attestation reference,
and inventory digest; unavailable, malformed, duplicate, or case-colliding metadata fails
closed for every reported location. Coordinate metadata is also capped at 5,000,000 attested
lines in addition to the profile file-count limit; provider implementations must apply the
same cap before materializing their return value.

The durable validation value is `sast-artifact-validation-v1`: ordered boolean checks, ordered
reason codes, aggregate byte/record/depth/string/path/coordinate statistics, and a SHA-256
result digest over its canonical core. Audit metadata receives only the outcome, result digest,
and bounded reason-code list. Raw artifact bytes, source, secret values, and object keys are
excluded. Completing T030 does not accept an artifact: all completed transports remain
`PENDING_VALIDATION`, and T031 alone performs the atomic accept/reject/encrypted-quarantine
disposition before any normalization adapter can run.

Accepted artifacts become short-lived Data/Security objects. Rejected artifacts record
metadata only. Security-significant mismatches are encrypted into an access-restricted
quarantine prefix with the same maximum seven-day retention and no user access.

T031 uses the versioned `sast-artifact-disposition-v1` contract. A serializable worker claims
only terminal scanner runs through a lease token and expiry fence, independently revalidates
the stored canonical envelope, validation-result digest, observed transport values, immutable
plan binding, every scanner image/wrapper/rule/database/schema/normalizer/profile/preflight/
workspace digest, and scanner exit/timeout/output outcome, then writes an immutable disposition
intent before any external storage mutation. The Data/Security port has no read operation and
accepts only an intent-bound idempotency operation for accepted retention, rejected deletion, or
server-side quarantine re-encryption. A quarantine receipt must return the exact
`sast-artifact-quarantine-context-v1` digest and an object under the restricted quarantine
prefix. Every receipt uses a bounded `storage-receipt://` opaque reference, and the canonical
decision binds the exact storage operation ID; neither the context nor the durable decision
carries an object key or key material.

An ingress request rejected while still `RECEIVING` never created an immutable object and does
not enter this worker. It remains a metadata-only `REJECTED` transport outcome with zero
disposition attempts and no T031 intent. This path cannot be normalized and is distinct from a
post-object T031 rejection, which always has an immutable decision and storage receipt.

Finalization rechecks the live database fence and atomically writes the ingestion state,
scanner terminal state, immutable decision, and bounded audit event. `ACCEPTED` requires a
successful validation, successful scanner terminal state, and explicit acceptance-gate
`ALLOW`; an unavailable gate leaves the row pending for retry. A gate `DENY`, durable metadata
tamper, binding mismatch, unsuccessful scanner, or failed validation is security-significant
and quarantined. A seven-day expiry or storage-confirmed missing source object is deleted or
recorded as metadata-only `REJECTED`. Retention is always calculated from the original receipt
time. Only an accepted decision sets `normalizationEligible=true`.

The sandbox never has direct Prisma, findings, policy, comment, or AI access.

## Normalization Contract

Each supported artifact schema has one explicit adapter version. T032 and T033 adapters emit
transient `SastNormalizedFindingCandidate` values and cannot change policy state. A candidate
is not a `NormalizedSastFinding`: it has no platform stable fingerprint, evidence reference,
or finding lifecycle status and carries `durablePersistenceAllowed=false`. T035 redacts
the transient candidate before any durable storage, log, audit, dashboard, or evidence path;
T036 then computes the platform fingerprint and constructs the first persistence-eligible
normalized-finding handoff. T037 and later gates still own occurrences, lifecycle, correlation,
coverage, evidence, policy, publication, and AI eligibility.
T034 emits a separate transient `SyftCycloneDxInventoryBatch`, not a finding candidate. It
has SBOM inventory authority only and is not eligible for finding, policy, AI, or durable
persistence paths.

### OpenGrep SARIF adapter v1

`opengrep-sarif-normalizer-v1` accepts only an unexpired T031 `ACCEPTED` decision whose
ingestion ID, validation-result digest, canonical envelope digest, content digest/byte/record
counts, tenant/repository/scan/attempt/scanner binding, fixed commit, profile, scanner image,
wrapper, rule bundle, schema bundle, and normalizer bundle still match the immutable plan.
Retention is evaluated before and after streaming against the adapter's own default wall clock;
an alternate clock exists only as an explicit trusted test/task seam and is never read from
artifact or envelope payload.
The adapter does not expose a route and does not gain a general object-store read capability.
Its bounded stream is supplied only by the later Data/Security-owned
normalization/redaction/fingerprinting worker. The T035 and T036 components exist, but the
default runtime remains unwired and fail closed until that Data/Security worker installs the
artifact reader and durable persistence boundary.

The v1 schema mapping is deliberately narrower than generic SARIF:

- schema URI is the OASIS SARIF 2.1.0 release schema and `version` is exactly `2.1.0`;
- exactly one run is allowed, with driver name `Opengrep OSS` and `semanticVersion` equal to
  the envelope's pinned OpenGrep version;
- exactly one invocation must report `executionSuccessful=true` with zero execution
  notifications; a partial/error notification rejects the entire batch;
- result `ruleId`, and `ruleIndex` when present, must resolve to one unique driver rule and
  one immutable rule-bundle manifest entry. The scanner-local `ruleId` remains provenance;
  `ruleSemanticId` and `ruleRevision` are copied only from that signed manifest entry and
  never inferred from SARIF;
- the result `message.text` is the plain-text description; rule `shortDescription.text` is
  the title, with a bounded deterministic rule-ID fallback;
- only zero or one primary location is accepted. OpenGrep's literal `%SRCROOT%` URI base is
  the sole permitted base. Its canonical uppercase percent-encoded relative URI is decoded,
  NFC checked, and rebound to exact provisioner-attested coordinates. SARIF `endColumn`
  remains the standard exclusive end coordinate;
- an omitted location becomes `UNKNOWN/SCANNER_LOCATION_OMITTED`; a safe but unattestable
  location becomes `UNKNOWN/LOCATION_NOT_MAPPABLE` with no retained path or coordinates;
  multiple primary locations, unsafe bases, or invalid attested bounds reject the batch.
  A genuinely unavailable coordinate-attestation provider may produce the explicit unknown
  location, but a supplied unverified, malformed, or plan-drifted attestation rejects the
  batch before artifact bytes are read;
- `fingerprints["matchBasedId/v1"]` is retained only as bounded T036 identity material. A
  namespaced SHA-256 projection supplies the candidate's non-authoritative `structuralHash`;
  neither value is copied into `stableFingerprint` or treated as platform authority.

Severity resolution uses valid result `level` over the matching rule default level. A valid
OpenGrep rule `security-severity` score refines that mapping: `9.0..10.0 -> CRITICAL`,
`7.0..<9.0 -> HIGH`, `4.0..<7.0 -> MEDIUM`, `>0..<4.0 -> LOW`, and `0 -> INFO`. Without a
score, SARIF `error/warning/note/none` maps to `HIGH/MEDIUM/LOW/INFO`. A missing severity maps
to `INFO` plus `UNKNOWN_SEVERITY`; an explicit unknown enum rejects. The unique
`HIGH|MEDIUM|LOW CONFIDENCE` rule tag maps confidence; absence becomes `UNKNOWN` plus
`UNKNOWN_CONFIDENCE`, while conflicting tags reject.

Only canonical leading `CWE-<id>` and `CVE-<year>-<id>` rule tags become identifiers. Values
are uppercased, de-duplicated, naturally sorted, and capped by the limits below. Scanner
snippets, fixes, code flows, help Markdown, result properties, and any other raw substructure
are parsed only for bounded structural validity and discarded. HTML and Markdown-looking
characters in `message.text` remain literal text; no adapter renders trusted markup.

Parsing reuses the T030 fatal UTF-8, duplicate-key, nesting, token, string, and number bounds
with globally aligned fixed parser slices. It collects only required scalar fields rather
than materializing the raw SARIF or a complete result object. Raw JSON Unicode escapes are
validated before token decoding so an unpaired surrogate cannot collapse to a replacement
character and alter canonical identity. The adapter independently
rehashes bytes, checks byte/record counts, deterministically sorts candidates, and binds the
canonical batch to a SHA-256 digest. The batch and each candidate retain the immutable
`planDigest`, `canonicalScanKey`, `preflightAttestationRef`, and
`preflightInventoryDigest`; those values participate in canonical batch hashing and must
match the accepted artifact binding. Any semantic ambiguity rejects the complete batch with
ordered bounded reason codes; rejection metadata contains no raw message, snippet, path,
object key, or source bytes. The batch repeats the scanner kind/version/image digest and rule
bundle digest, and every candidate repeats `scannerRunId`, so an accepted zero-finding batch
still carries complete scanner provenance without dereferencing the source artifact.

OpenGrep normalized limits:

- title <= 512 UTF-8 bytes
- description <= 4,096 UTF-8 bytes
- normalized path <= 1,024 UTF-8 bytes
- symbol <= 512 UTF-8 bytes
- rule ID/revision <= 256 UTF-8 bytes each
- scanner identity hint <= 512 UTF-8 bytes; its namespaced structural projection is SHA-256
- maximum 128 bounded OpenGrep rule tags per rule; 129 or more rejects the complete batch,
  with no truncation or ignored tail tags
- maximum 25 CWE and 25 CVE identifiers per finding; each canonical identifier <= 64 UTF-8
  bytes. A `CWE-` or `CVE-`-prefixed tag with malformed identifier syntax rejects as
  `NORMALIZATION_IDENTIFIER_INVALID`, while byte/count overflow rejects as
  `NORMALIZATION_IDENTIFIER_LIMIT_EXCEEDED`
- a file-relative location requires the matching attested file metadata; line and column values
  are positive safe integers no greater than `2,147,483,647`, lines cannot exceed the attested
  line count, and columns cannot exceed the attested per-line maximum. `columnStart` is
  inclusive and SARIF `columnEnd` is exclusive. Each `maxColumnByLine` value is the legal
  one-past-last UTF-16 boundary, so equality is valid and any larger value is rejected
- absent file metadata never relaxes validation: adapters must emit the explicit `UNKNOWN`
  location with `SCANNER_LOCATION_OMITTED` or `LOCATION_NOT_MAPPABLE` and no path or coordinate
  fields; arbitrary fallback coordinates are rejected
- HTML is encoded as text; Markdown is sanitized only at presentation
- unknown severity maps to `INFO` plus `UNKNOWN_SEVERITY`, never silently to `HIGH`

### Trivy JSON adapter v1

`trivy-json-normalizer-v1` has the same T031 acceptance, retention, immutable-plan,
coordinate-attestation, supply-chain, validation-result, and pre/post-stream rebinding
requirements as the OpenGrep adapter. It additionally binds the exact immutable Trivy
vulnerability-database digest and database version. It accepts only the JSON v2 shape emitted
by the pinned Trivy 0.66.0 filesystem wrapper and only the three authoritative Trivy
capabilities:

OpenGrep, Trivy, and later normalizers consume one shared implementation for retention-clock
validation, coordinate-attestation loading, safe text/identifier bounds, canonical SHA-256
helpers, and digest-field omission. Adapter-specific reason codes remain explicit parameters;
security-critical validation behavior must not be copied into an adapter-local variant.

- dependency records from `Vulnerabilities` become `DEPENDENCY_VULNERABILITY`;
- secret records from `Secrets` become `SECRET_DETECTION`;
- failed IaC records from `Misconfigurations` become `IAC_MISCONFIGURATION`.

The adapter also parses the pinned producer's `ExperimentalModifiedFindings`. Only nested
vulnerability, secret, and misconfiguration findings are supported; license or unknown
finding types reject the complete batch. The scanner status is retained as
`scannerDisposition={source:"MODIFIED",status,platformPolicyAuthority:false}`. A direct finding
uses `source:"DIRECT"` and `status:"active"`. Neither representation is a platform waiver,
suppression, finding lifecycle state, severity override, policy decision, nor reason to omit
the finding. Unknown modified-finding types or status enums reject as semantic ambiguity.

Rule authority is capability-specific:

- dependency `ruleSemanticId` is a namespaced projection of the validated vulnerability ID,
  and `ruleRevision` is the pinned vulnerability-database version. Package type/name,
  installed version, optional fixed version, advisory status, and database digest remain
  structured provenance. Its non-authoritative scanner identity also includes the canonical
  package/result target, so the same package advisory in separate monorepo manifests remains
  distinct without inventing a source coordinate. The scan rule-bundle digest is still bound
  at batch and candidate level, but it is not falsely presented as the dependency advisory source;
- secret and IaC scanner rule IDs must resolve exactly to one entry in the signed immutable
  checks-bundle manifest. Only its `ruleSemanticId` and `ruleRevision` are authoritative;
  scanner-local titles, descriptions, and rule metadata cannot replace them.

Trivy titles and descriptions are deterministic platform projections from those validated
identifiers and bounded package/check metadata. Scanner `Title`, `Description`, `Message`,
secret `Match`, `Code`, modified-finding `Statement`/`Source`, misconfiguration traces,
rendered causes, and all other raw context are structurally bounded but discarded. In
particular, Trivy secret `Code` can contain nearby unredacted values even when `Match` is
masked, so neither value may enter a candidate, digest preimage, rejection, log, audit,
dashboard, evidence, or AI payload. A secret candidate states
`secretValueStored=false` and `secretPayloadDiscarded=true`; T035 remains a mandatory
defense-in-depth redaction gate before any durable persistence.

Dependency findings use `UNKNOWN/SCANNER_LOCATION_OMITTED` because the fixed wrapper does not
enable Trivy package-file line coordinates; the adapter never invents line 1. Secret and IaC
line ranges require a canonical result target and exact provisioner-attested file bounds.
Omitted scanner coordinates become `UNKNOWN/SCANNER_LOCATION_OMITTED`; safe coordinates with
genuinely unavailable metadata become `UNKNOWN/LOCATION_NOT_MAPPABLE` without retaining the
path; malformed or drifted supplied attestations reject before artifact bytes are read.
Secret and IaC `scannerMatchBasedId` and `structuralHash` preimages exclude line and column
coordinates: coordinates are occurrence metadata only and a pure line shift must preserve
T036 identity material. Multiple records for the same semantic rule and canonical target use
their deterministic producer-order occurrence ordinal to remain distinct. Two otherwise
indistinguishable records at the same exact coordinate are rejected as ambiguous instead of
being assigned an unstable identity.

Severity `CRITICAL|HIGH|MEDIUM|LOW` maps directly. Missing or explicit `UNKNOWN` maps to
`INFO` plus `UNKNOWN_SEVERITY`; every other enum rejects. Trivy does not supply an
authoritative confidence value, so confidence is `UNKNOWN` plus `UNKNOWN_CONFIDENCE`.
Vulnerability IDs, package fields, check types, categories, statuses, CWE/CVE lists, and
locations are syntax-checked and byte/count bounded without truncation. Duplicate semantic
identity within one artifact rejects the complete batch.

The adapter processes globally aligned 4,096-byte parser slices independent of transport
chunking, collects only required scalar fields, and never materializes the artifact or a
complete raw finding object. It independently rehashes bytes and recounts direct plus modified
findings. A zero-finding artifact still emits the full scanner, rule bundle, vulnerability
database, schema, normalizer, plan, attestation, validation, disposition, envelope, and
artifact provenance. Canonical candidate ordering and the batch digest are byte-identical
across transport chunk boundaries.

### Syft CycloneDX inventory adapter v1

`syft-cyclonedx-inventory-ingestor-v1` accepts only an unexpired T031 `ACCEPTED` decision
whose ingestion, validation, disposition, envelope, content, immutable plan, canonical scan,
preflight, profile, Syft image/wrapper, schema-bundle, and normalizer-bundle bindings all
match. It performs those checks before reading bytes and re-evaluates retention after
streaming. The adapter has no route, general object-store read capability, finding
persistence path, policy hook, or AI handoff.

The accepted producer subset is pinned to Syft v1.44.0 directory output and CycloneDX JSON
1.6:

- root `$schema`, `bomFormat`, `specVersion`, serial UUID, BOM version, metadata, components,
  and optional dependencies must match the exact bounded structure;
- metadata contains exactly one `application/anchore/syft/<pinned-version>` tool component
  and one `file` source component whose name is the wrapper-owned Deep repository path or
  inventory-digest-bound Fast projection. The 16-hex source BOM reference is validated and
  not retained;
- package components may be `library`, `application`, or `machine-learning-model`;
  operating-system components use the Syft `os:<name>@<version>` and SWID relationship.
  File components are rejected because the wrapper forces
  `SYFT_FILE_METADATA_SELECTION=none`;
- every package requires unique `syft:package:foundBy` and `syft:package:type` properties.
  A canonical PURL requires a BOM reference equal to that PURL plus exactly one 16-hex
  `package-id` qualifier and its component name follows Syft's ecosystem-specific namespace
  inclusion rule; a package without a PURL uses the 16-hex Syft package ID directly;
- license choices are bounded SPDX IDs, expressions, or declared names. SPDX ID fields resolve
  case-insensitively to the canonical 727 identifiers in Syft's pinned SPDX License List
  3.28.0. Expressions follow SPDX 2.3 grammar, canonicalize listed license and exception IDs,
  permit `LicenseRef`/`DocumentRef` only where the expression grammar allows them, and accept
  `WITH` only with one of the pinned 84 SPDX exception identifiers. Raw attached text is
  rejected because the wrapper forces `SYFT_LICENSE_CONTENT=none`; URLs are validated and
  discarded. Syft's URL-only fallback, which duplicates the URL into `license.name`, is
  discarded as one choice rather than allowing the URL through the name field. Repeated
  normalized identities from multiple producer URLs become one deterministic license value;
- retained CPEs must satisfy the complete NISTIR 7695 CPE 2.3 formatted-string ABNF: exact
  field count, `a|h|o|*|-` part, non-empty attribute values, valid quoting and boundary
  wildcards, and the defined language-tag form;
- dependency nodes and each non-empty `dependsOn` list must be producer-sorted, unique,
  non-self-referential, and reference accepted components. Every retained edge is translated
  to canonical component IDs and sorted independently of document chunking;
- Syft properties, source-location properties, component prose, license URLs, and external
  references are structurally bounded and counted but never copied. Legitimate Java
  URL-empty `build-meta` references require a supported MD5/SHA-1/SHA-256 digest.
  Vulnerability/VEX fields, nested components, file components, foreign tools/schemas,
  malformed PURL/CPE/license/hash data, and dangling or duplicate edges reject the complete
  batch.

Inventory limits are fail-closed and never truncate: at most the profile
`maxArtifactRecords`, plus separate global maxima of 250,000 components, 250,000 dependency
nodes, and 250,000 dependency edges; 64 licenses, 256 properties, and 64 external references
per component; and 16 hashes per external reference. Names/groups/versions/license values are
at most 512 UTF-8 bytes, PURLs and BOM references 2,048 bytes, and CPEs 1,024 bytes. Raw
property values, URLs, comments, and other discarded fields remain subject to the shared
4,096-byte token ceiling.

Parsing uses the same fatal UTF-8, raw-token, duplicate-key, depth, globally aligned
4,096-byte slice, independent SHA-256, byte, and record-count implementation as the finding
adapters. CycloneDX record count is the inventory component count and excludes
`metadata.tools.components`. A zero-component SBOM still returns complete producer and
supply-chain provenance.

The output is deterministically ordered and digest-bound. Component IDs use a versioned,
length-prefixed SHA-256 identity; raw producer BOM references and the document serial number
are represented only by SHA-256 digests. The batch contains package/OS identity, bounded
license identities, dependency edges, discard statistics, exact plan/artifact/disposition
provenance, `durablePersistenceAllowed=false`, and these fixed authority values:

```text
capability=SBOM
mayCreateFindings=false
mayEvaluateVulnerabilities=false
policyAuthority=false
aiPayloadEligible=false
```

Raw artifact bytes, raw properties, source paths, raw license text, prose, external-reference
payloads, findings, severity, stable fingerprints, evidence references, and object keys are
not batch fields. The accepted raw SBOM remains only in the Data/Security Plane under the
T031 retention deadline, which is derived from receipt time and capped at seven days.

### Secret redaction gate v1

`sast-secret-redaction-v1` accepts only an exact shape-valid OpenGrep or Trivy candidate
batch. Before reading candidate text it recomputes the adapter-specific canonical batch
digest and independently verifies the exact T031 decision shape/digest, `ACCEPTED`
disposition, `normalizationEligible=true`, ingestion and validation-result binding, and
candidate-carried disposition digest. Its private default wall clock must be at or after
`decidedAt` and before `retentionExpiresAt`; the same monotonic check runs after the complete
pass. A caller-provided clock is a trusted test/task seam only; production uses the private
wall clock and the service's internal `setImmediate`-backed yield.

The detector policy is versioned with this gate:

- at most 64 unique NFC platform values, each 8-4,096 UTF-8 bytes and at most 65,536 bytes
  total, may be supplied as caller-owned transient values;
- private-key blocks, authorization credentials, URL user information, documented AWS,
  GitHub, GitLab, Slack, Google, Stripe, and SendGrid formats, JWTs, prefixed/quoted
  low-entropy and contextual secret assignments, and bounded high-entropy tokens are
  detected;
- pattern evaluation is linear over already-bounded candidate scalars. Detector order is
  canonical, and overlapping or directly adjacent spans merge before replacement;
- the sole replacement is the fixed ASCII `[REDACTED]` marker. It reveals no original
  length, digest, provider account, or validity signal;
- a source candidate containing the reserved marker is rejected so scanner content cannot
  forge `secretRedactionApplied=true`.

Only `title`, `description`, and optional `location.symbol` are display-redactable.
Ingestion/scope/preflight bindings are inspected even for a zero-finding batch. A match in
one of those bindings or in normalized path, semantic rule identity, symbol anchor, sink
kind, scanner version/match identity, rule provenance identifier/revision, dependency
vulnerability/package/type/installed/fixed-version identity, secret category, or IaC check
type/AVD identity rejects the complete batch with
`SECRET_REDACTION_IDENTITY_FIELD_BLOCKED`. The gate does not replace an identity field,
silently drop the candidate, hash the match, or use line coordinates to invent a
replacement identity.

The async gate rejects a batch above 8,000,000 inspected UTF-16 code units. It yields before
the next candidate when either 64 candidates or 32,768 code units have been processed in the
current chunk. Candidate, batch, rejection, and audit validation requires the trusted
canonical SHA-256 digester and recomputes the sanitized preimage; digest syntax alone is not
integrity.

Success returns only a fresh, ordered `SastSecretRedactionBatch`. Each finding carries an
ordered `SastFindingSecretRedaction` decision and a
`redaction://sast-secret-redaction-v1/<safe-decision-digest>` reference. The decision digest
preimage contains the sanitized candidate plus version, fixed token, safe counts, ordered
redacted-field names, and ordered detector categories. Batch counts include the eight
binding fields plus all finding fields, so a zero-finding batch still proves binding
inspection. Its canonical batch digest contains only fresh sanitized output. These
invariants are literal:

```text
secretRedactionApplied=true
secretValueStored=false
matchedValueDigestStored=false
rawCandidateStored=false
sourceCandidateDigestStored=false
durablePersistenceAllowed=false
```

The output and bounded audit projection never carry a matched value, match length,
matched-value digest, input object, input candidate-batch digest, or rejected binding.
Rejections contain only the exact version, globally ordered coarse reason codes, the three
negative storage assertions, and a digest over those safe fields. The source artifact digest
may remain normal accepted-artifact provenance only on success; it is absent from rejection.

`ScanPlaneModule` does not export the raw OpenGrep or Trivy normalizer providers after T035.
The redaction gate remains internal and is consumed by T036. At the T035 checkpoint only the
identity service crossed the next-stage boundary; after T037/T038 installation those earlier
providers remain internal and only the correlation service is exported. No checkpoint
authorizes a user route, log sink, audit of candidate text, evidence construction, policy
evaluation, publication, or AI call.

## Stable Fingerprint Contract

The canonical field order is:

```text
repositoryBindingId, capability, ruleSemanticId, normalizedPath,
symbolAnchor, sinkKind, structuralHash
```

The preimage algorithm is byte-exact and versioned:

1. Start with UTF-8 bytes for `sast-fingerprint-v1`, followed by one `0x00` byte.
2. For each field in the order above, normalize the string to Unicode NFC and encode it as
   UTF-8 bytes.
3. Append the ASCII decimal UTF-8 byte length with no leading zero, one ASCII colon (`0x3A`),
   and then the field bytes. Append no delimiter or terminator between fields.
4. Hash the complete byte sequence with SHA-256 and store `sha256:` followed by lowercase hex.

The length prefix makes colons, newlines, NULs, pipes, and multibyte characters unambiguous.
Adapters must use this algorithm rather than language-native string lengths or URL encoding.
Branch, target ref, commit SHA, line, column, scanner patch version, message text, and severity
are excluded.

Interoperability test vector:

| Field | Canonical value |
| --- | --- |
| `repositoryBindingId` | `repo-é` |
| `capability` | `SAST` |
| `ruleSemanticId` | `java.sql-injection` |
| `normalizedPath` | `src/Café.java` |
| `symbolAnchor` | `com.example.Café#run` |
| `sinkKind` | `SQL_EXECUTE` |
| `structuralHash` | `ast:v1\|call(é)` |

The escaped display form of the preimage is
`sast-fingerprint-v1\0` +
`7:repo-é4:SAST18:java.sql-injection14:src/Café.java` +
`21:com.example.Café#run11:SQL_EXECUTE15:ast:v1|call(é)`. Its digest is
`sha256:7bc64e19d97c160a7d58334c79149af47c9148d7238732d6092f51c7df269661`.
An adapter that emits decomposed `e` + U+0301 for every `é` must produce the same preimage and
digest after NFC normalization.

If a rule changes semantic meaning, it receives a new `ruleSemanticId` even when its
scanner-local rule ID stays unchanged.

### Finding identity construction gate v1

`sast-finding-identity-v1` accepts exactly one complete `SastSecretRedactionBatch`; it has no
raw adapter, artifact-reader, object-store, route, log, evidence, policy, or AI input. Before
constructing identity it recomputes the complete T035 source batch and every sanitized
redaction decision with the trusted canonical SHA-256 implementation. It rejects more than
25,000 findings, a malformed or forged handoff, a non-monotonic clock, and a retention window
that is invalid or reaches expiry before or during construction. The async pass yields before
finding 65 and every subsequent 64-finding boundary.

Each finding projects the seven canonical fields above from the verified sanitized candidate.
A `FILE` location contributes its canonical normalized path. An `UNKNOWN` location contributes
the explicit empty string; its reason, coordinates, scanner match identifier, and any invented
fallback path are excluded. The UTF-8 length prefix makes that empty component unambiguous.
The resulting `SastFindingFingerprintDecision` binds:

- exact `sast-fingerprint-v1`, all seven projected fields, and the lowercase SHA-256 stable
  fingerprint
- the exact T035 sanitized redaction-decision digest
- `unstableCoordinatesIncluded=false`,
  `scannerMatchIdentityAuthoritative=false`, and `fingerprintPreimageStored=false`
- a canonical decision digest and
  `fingerprint://sast-fingerprint-v1/<safe-decision-digest>` reference

Repeated observations with the same fingerprint and byte-identical preimage remain separate
ordered findings for T037 occurrence construction. If one fingerprint is observed with two
different preimages, the whole batch fails closed with
`FINDING_IDENTITY_FINGERPRINT_COLLISION`; no first-writer or scanner-local identity wins.
The collision map is transient and neither a fingerprint preimage nor a source candidate is
stored or returned.

Success is a fresh canonical `SastFingerprintedFindingBatch` that preserves the complete
sanitized T035 candidate and scanner/rule/artifact provenance, binds the T035 batch digest,
adds safe distinct/repeated counts, and sets `durablePersistenceAllowed=true`. This is the
first normalized-finding persistence-eligible handoff, not a lifecycle or publication
decision. Until T037 and later gates consume it, the following authority flags remain false:

```text
occurrenceAuthority
lifecycleAuthority
correlationAuthority
coverageAuthority
evidenceAuthority
policyAuthority
publicationAuthority
aiPayloadEligible
```

Rejections expose only the version, globally ordered coarse reason codes, four negative
storage assertions, and their canonical digest. They omit the T035 batch digest, artifact
digest, candidate, fingerprint, fingerprint preimage, and secret value. T036 remains an
internal provider once T037 is present; T035 redaction and both raw normalizers also remain
internal.

### Finding lineage and lifecycle gate v1

`sast-finding-lineage-v1` accepts exactly one complete
`SastFingerprintedFindingBatch`. It recomputes the T036 batch and every fingerprint decision,
checks the active retention window before and after asynchronous authority work, and reloads
the accepted artifact, completed scanner run, immutable plan, fixed commit, target ref,
profile, scanner/schema/normalizer/rule/database provenance, and all T030/T031 digests from
durable state. Any mismatch rejects before persistence.

The gate derives:

- `sast-finding-lifecycle-context-v1` from NFC/UTF-8-length-framed tenant, repository binding,
  and target ref
- a `finding-lineage://<sha256>` identity from tenant, repository, capability,
  `sast-fingerprint-v1`, and stable fingerprint
- a deterministic observation batch, one normalized row, and one occurrence per producer
  ordinal; repeated fingerprints never collapse occurrences

Exact alias lookup creates no new lineage. Observation batches are fenced by source identity
digest and scanner run; replay rechecks every immutable batch field and every ordered
occurrence, while any changed, missing, extra, or malformed row is a conflict. All lineage,
alias, occurrence, lifecycle, reconciliation, event, and audit writes use one serializable
transaction with a 5-second acquisition wait, 120-second transaction deadline, and at most
three serialization/unique-race attempts.

Path continuity is optional and fail-closed. `sast-finding-rename-attestation-v1` requires a
sorted non-empty one-to-one set of safe canonical `from`/`to` paths, distinct fixed commits
and scan requests, exact target/profile/context binding, issued time, signature, provenance,
and canonical digest. Paths cannot duplicate, chain, or cycle. An injected verifier must
return `VERIFIED`; the default returns `UNAVAILABLE`. T037 changes only the path component of
the verified current fingerprint input to look up the predecessor. It retains both aliases
only when the predecessor resolves unambiguously and the durable predecessor scan exists.
No fuzzy title, coordinate, rule, severity, scanner-local match, or AI similarity can rename
a lineage. A verified rename-back reuses the retained exact alias but is still classified as
`RENAMED` and appends a new event; it never inserts a duplicate alias or rewrites history.

Lifecycle state is unique per lineage and lifecycle context and is separate from the legacy
normalized-finding policy/triage status. Observation creates `OPEN` and appends `CREATED`;
trusted alias continuity appends `RENAMED`. Observing a previously fixed lineage records the
occurrence but does not reopen it.

`sast-finding-lifecycle-coverage-v1` is an input owned by T039. T037 has
`coverageCalculationAuthority=false` and accepts the decision only when its injected gate
verifies exact `state=COMPLETE`, `stale=false`, and `comparable=true`. Before applying it,
T037 verifies:

- the current durable in-flight/terminal scan context plus the previous completed scan, same
  target context, fixed commits, plan, profile, and strict monotonic reconciliation sequence
- sorted unique eligible lineage IDs scoped to complete capability families
- exact equality between expected batch digests and every durable T037 observation batch for
  the current scan, including zero-finding batches
- every relevant observed lineage is eligible and every eligible lineage already has state
  in that target context

An `OPEN` eligible lineage absent from the verified observation set becomes `FIXED`; a
`FIXED` eligible lineage present becomes `OPEN` with `REOPENED`. Unchanged states only advance
the reconciliation fence. Transitions append immutable events with the next state revision.
Partial, stale, incomparable, missing, extra, out-of-order, unavailable, or malformed
coverage cannot change lifecycle.
The lifecycle-context sequence is globally contiguous. A newly created or newly eligible
state may catch up from an earlier non-future state fence during the current verified
reconciliation, while any state fence ahead of the previous global sequence rejects.

Successful observation authority is limited to normalized-finding persistence, occurrences,
exact/verified-rename lineage, and lifecycle recording. Correlation, coverage calculation,
evidence, policy, publication, and AI eligibility remain false. Rejections expose only the
operation, ordered coarse codes, five negative storage assertions, and rejection digest; they
never echo source batch/finding data, rename paths, eligible lineage IDs, or secrets.
T037 remains an internal provider after T038 is installed.

### Finding correlation gate v1

`sast-finding-correlation-v1` accepts a non-empty, bounded set of canonical T037 observation
results for one target context and attempt. It verifies each result digest, sorts unique
observation IDs, reloads every durable observation batch and ordered occurrence, and requires
the requested set to equal the complete durable set, including zero-finding batches. The
source-set digest binds canonical durable batch IDs, T036 batch digests, scanner/run and
capability attribution, lifecycle context, counts, and observed times. It deliberately omits
the T037 result digest because a valid replay changes only that result's `replayed` field and
digest.

Correlation is deterministic and versioned:

- `EXACT_FINGERPRINT`: repeated occurrences in one exact lineage; a sorted star preserves
  every occurrence without an all-pairs expansion.
- `SAME_DEPENDENCY_CVE`: exact NFC ecosystem, package, installed version, and canonical CVE;
  distinct lineages and all source provenance remain intact.
- `SUPPORTING_EVIDENCE`: cross-capability CVE or same-file CWE overlap where exactly one side
  is optional-profile `SUPPORTING_ONLY`; it can support but never replace a required,
  scanner-owned authoritative finding.
- `POSSIBLE_OVERLAP`: compatible cross-capability identifier overlap between equal authority
  levels; display grouping only, with no automatic merge or inheritance.

Only the configured scanner owner may contribute a capability. A profile-required capability
is `AUTHORITATIVE`; a scanner-owned but optional capability is `SUPPORTING_ONLY`. Matching by
path alone, title, coordinates, severity, scanner match ID, substring, fuzzy text, or AI is
forbidden. CVE comparison is canonical, while CWE overlap additionally requires the same NFC
file path.

Each edge has canonical source/target occurrence ordering, sorted unique hashed bases, fixed
confidence, a decision digest, and two separately persisted provenance rows. Provenance binds
the observation, lineage, normalized finding, scanner run, capability/authority, severity,
fingerprint decision, sanitized source-finding digest, scanner/image, rule/revision/bundle,
artifact, and Trivy database when present. Safety flags are invariant:
`findingMergeAllowed=false`, severity/lifecycle/policy/coverage inheritance false, and
`occurrenceProvenancePreserved=true`.

Source SAST, secret, dependency, and IaC findings remain distinct capability families even
when they refer to the same file. A serializable transaction persists the correlation batch,
complete source set, bounded edges, both provenance rows, and audit event. Exact replay checks
the whole ledger; changed or late sources conflict. Rejections expose only ordered coarse
codes and negative storage assertions. Correlation grants no severity, lifecycle,
coverage-calculation, evidence, policy, publication, or AI authority. After T039 installation
the correlation service is internal and only `SastScanCoverageService` crosses the Scan Plane
module boundary to T040.

## Coverage Contract

### Scan coverage gate v1

`sast-scan-coverage-v1` accepts only a canonical T038 result. It reloads and re-hashes the
immutable plan, attempt, correlation sources (including zero-finding sources), scanner runs,
artifact envelopes, and final dispositions. Profile scanner/capability requirements are
platform-owned. Finding-producing scanners require a matching T038 source; Syft proves SBOM
coverage through its accepted CycloneDX artifact without inventing a finding source.

Coverage can be evaluated while required runs are pending, but a capability is achieved only
when its owning required scanner is terminally successful, its pinned provenance matches, and
its artifact is accepted and normalization-eligible. A `PENDING` result is canonical but
explicitly non-persisted and must be reevaluated after durable scanner state advances; this
prevents a unique attempt ledger from freezing before a terminal decision exists.

| Condition | Coverage | Comment/block | AI |
| --- | --- | --- | --- |
| Every required scanner accepted | `COMPLETE` | Deny until T040 | Deny until T040 |
| Required scanner absent/failed/timed out | `PARTIAL` | Deny | Deny |
| Required scanner still pending/running | `PENDING` | Deny | Deny |
| Quarantine, identity/digest mismatch, sandbox kill | `FAILED` | Deny | Deny |
| Complete; latest-target authority unavailable | `COMPLETE` | Deny | Deny |

Optional scanner failure does not reduce required coverage but is visible and cannot replace
an authoritative required capability. Quarantine, kill, provenance/artifact digest mismatch,
or an invalid T038 source set security-blocks the decision even when it affects optional
output. For a terminal evaluation, one serializable write persists all canonical scanner records, coverage, and
`sast-external-publication-v1`; exact replay is idempotent and all changed/cross-scope replay
conflicts. The artifact-ingestion foreign key is restrictive: an ingress abort must fail if an
immutable coverage record references that ingestion, so cleanup cannot cascade-delete part of
the coverage ledger while leaving its decision digest behind.

T039 does not accept a caller-supplied `stale=false` or `comparable=true`. Its publication
row is a database-enforced zero-authority decision with latest-target authority
`UNAVAILABLE`, stale/comparability `UNKNOWN`, and comment/block/AI/lifecycle booleans false.
T040 must replace that missing authority before any external or lifecycle action can proceed.

### Freshness and bounded retry gate v1

`sast-scan-freshness-v1` accepts only the durable terminal T039 decision reference and reloads
its canonical coverage object. It independently binds tenant, repository, provider, target,
fixed commit, scan/attempt number, profile/digest/family, canonical scan key, plan digest,
required capability set, `sast-fingerprint-v1`, and lifecycle-eligibility scope. The caller
cannot supply `stale=false`, `comparable=true`, target head, or publication authority.

A `sast-latest-target-observation-v1` row is valid only when a provider-authoritative read-only
adapter returns a canonical commit, strictly increasing target-scoped sequence, nondecreasing
observation time, and bounded observer reference. Freshness is `FRESH` only when that head is
byte-exactly the scan's fixed commit. Missing authority is `UNAVAILABLE`/`UNKNOWN`; malformed,
future, rolled-back, or cross-scope observation is invalid; a different head is `STALE`.
The default adapter is unavailable and therefore cannot authorize publication or lifecycle.

Comparability selects the newest completed `COMPLETE` T039 source from a different scan
request in the same tenant, repository, and target whose supported profile family and required
capability set are compatible; an attempt-one row from the current scan and an incompatible
profile cannot hide an older valid predecessor. Fingerprint version and lifecycle-eligibility
scope must also match exactly. Only complete coverage with
`VERIFIED`, `FRESH`, and `COMPARABLE` state creates comment/block eligibility and permits the
T037 lifecycle gate to reverify its exact source. The decision keeps `aiAdvisoryAllowed=false`
and `publicationAttempted=false`; T040 installs neither an SCM writer nor a publisher route.
The lifecycle consumer performs another authoritative head read and rejects when the target
has advanced since the stored decision.
The original T039 external-publication object remains immutable for exact replay. The migration
adds the named T039-source constraint `NOT VALID`; the mandatory online-schema step validates
it and only then removes `SastExternalPublicationDecision_contract_check`. Existing-table
comparison and retry indexes are built concurrently, and their dependent foreign keys are
installed or validated afterward.

`sast-scan-retry-decision-v1` is durable before attempt-two admission. Allow requires the
immediately preceding attempt one to be terminal `FAILED`, classified
`RETRYABLE_INFRASTRUCTURE`, explicitly retry eligible, completed, and bound to its exact
`sandbox.terminated` audit event. It revalidates current scanner-set availability and
kill-switch state while preserving the original canonical scan key, immutable plan digest,
and scanner-set digest. Attempt, sandbox, and workload identities must all be new. Attempt
two also carries signed, attempt-bound preflight evidence issued within 60 seconds and a fresh
sandbox attestation over the unchanged fixed commit and inventory digest; the original
canonical plan remains immutable. An allowed decision replay reuses its original `decidedAt`
as the attempt start timestamp so an interruption between decision persistence and attempt
creation cannot strand attempt two. Denied rows are permanent audit evidence for that
scan/attempt slot; reevaluation requires a new scan request. Attempt
three, cleanup failure, capacity/input/scanner/security failure, missing audit, changed or
unavailable scanner set, active/unavailable kill-switch authority, and identity reuse deny.
All target, freshness, and retry ledgers use bounded serializable writes and exact replay.

## Failure Contract

| Failure class | Examples | Automatic retry | Isolation/action |
| --- | --- | --- | --- |
| `RETRYABLE_INFRASTRUCTURE` | node loss, queue lease loss, transient storage failure | One retry; two attempts total | New sandbox |
| `NON_RETRYABLE_INPUT` | size/path policy reject, unsupported encoding | No | Explain in dashboard |
| `SCANNER_DEFECT` | crash on valid bounded input, schema-invalid output | No identical retry | Quarantine; scanner kill switch candidate |
| `SECURITY_VIOLATION` | scope/digest mismatch, root escape, tamper signal | No | Kill sandbox, quarantine, `RESTRICTED` escalation |
| `CAPACITY_REJECTED` | tenant budget or concurrency exceeded | No immediate retry | Defer/reject with retry condition |

Every retry revalidates current kill switches and scanner-set availability but preserves the
original immutable scan intent. The second attempt cannot be admitted unless the immediately
preceding durable attempt carries the retry-eligible infrastructure decision and final audit
binding.

## Evidence Contract

Default maximums:

- total bytes: 32 KiB
- fragments: 5
- bytes per fragment: 8 KiB
- context: five lines before and after
- retention: seven days

Evidence construction applies scanner-provided redaction, platform secret detection, entropy
and known-format redaction, path/identifier classification, and reconstruction-risk checks.
Each fragment records the source-file line count, redaction decision reference, and digest;
the pack records policy version, classification and reconstruction-risk decision references,
and its deletion schedule. It records truncation and suppressed fragment counts. A full file,
archive, broad debug log, raw SARIF/JSON, or sequential fragments that reconstruct substantial
source is rejected.

### Accepted-finding evidence gate v1

`sast-accepted-finding-evidence-v1` accepts a fragment request only after the persistence
store reloads the exact T040 decision and proves T039 `COMPLETE`, provider authority
`VERIFIED`, `FRESH`, `COMPARABLE`, and an empty reason set. The requested occurrence must
belong to the canonical T038 source set and its T037 observation, normalized-finding metadata,
lineage, capability, fingerprint, target, fixed commit, profile, canonical key, and plan must
all match. An UNKNOWN-location or non-occurrence input has no evidence authority.

The source authority is internal and defaults to `UNAVAILABLE`. A verified response binds the
candidate ID, role, path/range, attested anchor, source-file line count, scanner-redaction
decision, and source-content digest. Source text is bounded to 8 KiB and exists only in memory.
T041 reapplies known-format and platform-secret redaction, preserves line count, recomputes
exact UTF-8 byte size/content digest, and stores neither raw source nor secret values.

Candidate order is canonical. The builder selects at most five fragments and 32 KiB, records
truncation and every suppressed fragment, and rejects a full-file span or context beyond five
lines on either side of an attested anchor. Reconstruction uses canonical per-file intervals:
more than two fragments from a file, overlap, adjacency, or at least 25% combined line coverage
is `RISK` and rejects the complete pack. A rejected or accepted result is immutable; the
tenant/occurrence/policy/candidate-set key permits exact replay only inside a bounded
serializable transaction.

An accepted T041 pack grants only evidence-construction authority.
`dashboardSafe=false`, `aiSafe=false`, classification and deletion references are null,
and policy, publication, lifecycle mutation, user access, and AI payload authority remain
false until T042. `SastAcceptedEvidenceService` exposes no controller or SCM writer.

### Evidence access and deletion gate v1

`sast-evidence-access-decision-v1` accepts only an authenticated scope plus a purpose of
`DASHBOARD` or `AI_ADVISORY`. The persistence boundary reloads the exact T041 build decision,
pack, every fragment, scope, T040 freshness, T039 coverage, and T038/T037 source chain. It also
requires the canonical `sast-evidence-deletion-schedule-v1` row created with the pack. Caller
content, flags, paths, identifiers, timestamps, and digests grant no authority.

Each purpose independently reruns known-format, registered platform-value, and entropy
redaction, validates canonical paths and identifiers, and recomputes every content, pack,
projection, and decision digest. The registry authority defaults `UNAVAILABLE`. Time is checked
before storage confirmation and again after the final awaited confirmation, immediately before
return; expiry, an active deletion claim, clock rollback, registry-version drift, unsafe
identifier, or any durable mismatch denies. Neither
raw/pre-redaction content, secret values, matched-value digests, nor access-time redacted
content enters the access ledger, logs, audit, or error response.

An allowed dashboard decision returns only a second-pass-redacted projection after session
tenant and repository binding authorization. A denied or cross-scope request uses a generic
not-found response. An allowed AI decision returns only a
`sast-reduced-evidence://<sha256>` reference whose eligibility expires in at most 24 hours and
never later than pack expiry. T042 performs no AI provider request, stores no request payload,
and grants no retrieval, tools, policy, publication, lifecycle, or SCM action. T041 safe flags
and null classification/deletion fields remain unchanged.

Every accepted pack creates a deterministic `sast-evidence-delete://<sha256>` operation with
a positive retention window no longer than seven days. Due work uses one leased claim with an
owner and unique fencing token. The task runs immediately on startup, wakes at the earliest
durable due time, and gives a saturated bounded batch a zero-delay continuation so a fixed poll
interval or per-tick cap cannot create a retention backlog. The deletion provider defaults
`UNAVAILABLE`; retry releases the claim without weakening access denial. Only a bounded receipt
bound to the exact operation, pack, provider, reference, digest, and monotonic completion time
may authorize pack/fragment content deletion and finalization of
`sast-evidence-deletion-proof-v1`. An exact deterministic provider replay may return the original
receipt from an earlier claim; its completion must remain at or after `deleteAfter` and no later
than the current observation and fencing lease. The T041 build decision,
schedule, access decisions, canonical proof, and bounded audit state remain retained. Exact
replay is idempotent; a stale token, changed receipt, late reader, deletion race, or clock
rollback fails closed.

A claim whose durable context fails validation is fenced in a separate write, moved behind
other due work, and quarantined after three failed validations. The service contains that
expected `CONTEXT_DRIFT` result so one corrupt row cannot abort the bounded batch or starve the
deletion queue. Request-path serializable transactions use a short interactive timeout;
backfill uses one bounded background transaction with locked rows, and retry collisions use
bounded jitter.

Tenant/repository offboarding normally soft-revokes the durable scope. The proof-to-schedule
foreign key deliberately restricts hard parent cascades so deletion evidence is not silently
lost. An exceptional authorized hard purge must revoke access, finish provider deletion for
live content, retain/export the required external audit record, delete the proof ledger first,
and only then remove the tenant or another cascading parent.

### Advisory AI handoff gate v1

`sast-ai-advisory-handoff-v1` accepts only an exact intent containing `tenantId`,
`repositoryBindingId`, `evidencePackId`, and `modelVersion`. It obtains a T042 `AI_ADVISORY`
decision, reloads that ledger and the exact T037 occurrence, secret-redacted source finding,
and normalized-finding row, then obtains the same access decision again. Any missing, changed,
cross-scope, expired, or non-monotonic state produces one generic unavailable result.

The canonical request contains the normalized finding projection and the opaque
`sast-reduced-evidence://<sha256>` reference only. Its creation time is the immutable T042
decision time, so exact retries derive identical `sast-ai-request`, `sast-ai-handoff`, and
`sast-ai-advisory` IDs. Serializable persistence permits only exact replay. The immutable ledger
stores relationship IDs, digests, model version, expiry, and explicit booleans; it stores no
handoff/request JSON, title/path, prompt, source, secret, evidence fragment, redacted content,
or provider payload.

The internal AI request contains the handoff-bound model version, normalized metadata, one
opaque reference, and `snippets=[]`. The model version is part of the canonical runtime key,
selects the gateway configuration, and must equal the returned model metadata. The request
carries the canonical T035/T037 `cweIds` and `cveIds` in strict ascending, duplicate-free
order without runtime normalization; malformed or reordered identifier sets are rejected at
the shared handoff boundary rather than silently repaired. The request
carries no result-ingress artifact reference and grants no retrieval, tools, policy,
publication, lifecycle mutation, or SCM write authority. The runtime rejects unknown keys,
legacy caller-supplied finding/evidence shapes, content-bearing snippets, model or correlation
drift, expired references, and authority widening before provider execution. T043 records
advisory output only; T044 separately proves that output cannot acquire authoritative finding
or policy effects.

The API consumer treats provider output as hostile input. It accepts at most 32 detector and
32 planner advisories, at most 32 bounded signals per detector advisory, 2,048 UTF-8 bytes per
rationale/action/signal/fallback reason, 128 UTF-8 bytes per provider/model identifier, 30,000
milliseconds of reported latency, and a forbidden-key scan bounded to depth 12 and 64 entries
per collection. Oversized, excessively nested, cross-request, model-drifted, authority-bearing,
or sensitive output is rejected before persistence. Client-visible runtime rejection bodies
use stable error and reason codes and never echo provider or parser exception messages.

Normal tenant or repository offboarding soft-revokes access while retaining the immutable,
digest-only handoff and advisory audit chain under the tenant tombstone. An exceptional hard
purge requires an authorized, externally audited database-maintenance procedure: revoke access,
export the required audit record, remove `AiAdvisoryMetadata` children, bypass the immutable
delete fence only for the identified handoff rows, and then remove parent scope. The restrictive
foreign keys intentionally prevent an ordinary cascade from erasing this ledger.

### Advisory output authority proof gate v1

`sast-ai-advisory-authority-proof-v1` accepts exactly `tenantId` and `advisoryId` over a
tenant-bound internal credential; the authenticated tenant must equal the body tenant. Caller
finding, severity, status, lifecycle, waiver, suppression, policy action, block request, state
digest, or proof fields are unknown keys and reject before storage. The store reloads the
tenant-bound `AiAdvisoryMetadata`, T043 handoff, T037 occurrence, normalized finding, lineage,
and lifecycle context. Any advisory/handoff/scope/authority drift returns one generic
unavailable result.

The caller sends `x-aegis-internal-tenant-id` and a `Bearer v1.<hex>` credential derived with
HMAC-SHA-256 from the internal root secret, a fixed versioned domain separator, and that exact
tenant ID. A credential derived for one tenant fails under every other tenant header. The root
secret is never sent, stored in a proof, or accepted in the request body.

Within one bounded serializable transaction, the store first locks the advisory context fence
and then the canonical scan, lifecycle-context, and finding authority fences. Every application
write to normalized findings, lifecycle state, policy decisions, finding-scoped waivers, or
suppressions advances and locks the same database fence before mutation. The store then reads
at most 25,000 normalized findings for the scan and at most 1,024 finding policy decisions,
waivers, and suppressions, plus exactly one T037 lifecycle state. These policy and lifecycle
API paths persist to the same authoritative Prisma tables read by the proof store; they have no
in-memory shadow authority. Canonical row digests include status, severity, lifecycle revision,
policy flags, and row update instants.

The store inserts only the proof row and projects the single locked state snapshot into both
`before` and `after`; equality is therefore evidence of zero authority, while race exclusion is
provided by the database fence and serializable conflict retry. A concurrent relevant writer
blocks or causes retry instead of being hidden by a transaction snapshot. Over-limit, missing
target/lifecycle, missing fence, reordered, cross-scope, or changed replay state fails closed;
exact advisory replay returns the one existing immutable proof.

The database row contains scope IDs, counts, component/state/proof digests, verification time,
and fixed booleans only. Checks require every finding-create/status/severity, lifecycle,
waiver, suppression, policy-override, block, publication, and SCM authority bit false; every
authoritative-write audit bit is false and only `proofLedgerWritten` is true. Immutable update
and delete triggers plus delete/update-restrictive foreign keys preserve the audit chain. There is no JSON,
advisory text, rationale, prompt, source, evidence, secret, or policy payload column.

`sast-ai-advisory-policy-reference-v1` exposes only version, advisory ID, proof ID/digest, and
`advisoryOnly=true`. Policy verifies that reference against the same tenant and normalized
finding before setting display visibility. Enforcement action, reason codes, comment/ticket/
block requests, finding status/severity, waiver, suppression, and lifecycle remain derived
without AI input. Waiver create/update and suppression create requests use exact key allowlists,
so advisory/proof fields and the legacy `suggestedAction` shape reject rather than being ignored.

Normal offboarding retains this content-free proof under the tenant tombstone. Exceptional
tenant/legal hard purge follows the two-operator, externally audited procedure in
[`docs/runbooks/sast-ai-authority-proof-hard-purge.md`](../../docs/runbooks/sast-ai-authority-proof-hard-purge.md);
ordinary application roles cannot bypass the immutable fence.

### Rule-bundle manifest and compatibility gate v1

`sast-rule-bundle-manifest-v1` accepts only canonical platform metadata. It requires a
scanner-specific bundle ID and semantic version, lifecycle state, build/source identity,
bundle digest, one or more code-unit-sorted unique member ID/digest pairs, one or more sorted
unique rule identity projections, exact sorted compatibility sets, four digest-bound quality
references, trusted signer identity, non-HTTP digest-bound signature/provenance/rollout/
kill-switch references, and a distinct rollback target. Unknown fields, mutable references,
duplicate/noncanonical sets, customer executable configuration, and content fields reject.

The supply-chain authority returns
`sast-rule-bundle-supply-chain-attestation-v1` only after signature, provenance, trusted signer,
and every subject digest are verified. Its deterministic identity is derived from the manifest
digest. It contains verification facts and references, never signature bytes, provenance
payloads, rule bodies, source, or secrets. The application default returns
`AUTHORITY_UNAVAILABLE` and cannot mint a local attestation.

Before queue reservation, the compatibility gate reloads that immutable verified manifest,
compares every plan-visible bundle field and ordered rule projection, validates the selected
profile digest, and checks exact scanner version/image, wrapper, schema, normalizer, and profile
membership. Only `CANARY` and `ACTIVE` manifests are selectable. A successful evaluation
creates one `sast-rule-bundle-compatibility-receipt-v1`; a later equivalent evaluation returns
that first immutable receipt, while denials write no receipt. Its digest is copied into the
verified scanner-set descriptor and canonical scan key.
Missing, drifted, unsupported, malformed, or unavailable verification produces one bounded
planning reason and invokes neither queue reservation nor scanner execution.

Manifest, child-set, attestation, and receipt rows are normalized, serializable, insert-only,
and protected by update/delete rejection triggers plus restrictive foreign keys. The store
reconstructs and revalidates every canonical set on read and permits replay only when the
complete immutable contract matches. There is no user route for manifest registration.

### Semantic metadata and tenant rule-policy gate v1

T046 resolves only platform-managed `sast-rule-definition-metadata-v1` content through an
exact `sast-rule-definition-metadata-binding-v1` for every rule in the verified T045 scanner
set. The metadata digest is independent of bundle/manifest identity; the binding digest
commits to the full manifest, bundle, scanner rule/revision, semantic identity, and metadata
projection. This prevents the manifest/metadata circular hash while allowing unchanged
metadata to be reused across later signed bundles.

The semantic identity digest covers capability, category, languages/formats, vulnerability
predicate, source/sink taxonomy, default severity/confidence, finding identity, and mandatory
tenant control. A reused semantic ID with any changed core, unsupported scanner version,
pre-introduction bundle, retired rule without replacement, mutable reference, or mismatched
manifest projection rejects before policy evaluation.

`sast-tenant-rule-policy-v1` is exact canonical metadata: approved category/rule states,
literal safe path prefixes, platform-minimum severity floors, monotonic repository narrowing,
tenant-scoped existing waiver/suppression references, bounded effective/expiry time, actor,
and digest-bound audit reference. It has no rule body, flags, regex/glob program, plugin,
arbitrary configuration, source, secret, scanner command, policy script, or customer-supplied
authority field. Once any applicable policy scope disables a selection, a more specific scope
cannot re-enable it. Mandatory rules cannot be disabled by this contract.
Policy-window and evaluation timestamps use exact UTC millisecond form so their digest-bound
string representation survives the `TIMESTAMP(3)` persistence round trip without normalization
or calendar-date drift.
The evaluation timestamp comes only from the planner's injected service-owned UTC clock;
caller `requestedAt` is not a policy-time authority. A throwing or invalid clock produces a
bounded fail-closed planning result, no receipt, and no queue reservation.

A successful evaluation emits one immutable `sast-tenant-rule-policy-resolution-v1` receipt
and normalized rule/path children. Its independently validated identity digest binds policy,
repository, scanner set, profile, manifest set, and semantic metadata set; its receipt digest
also binds the exact evaluation time, resolved binding states, paths, severity floors, and all
fixed safety facts. The verified descriptor enters both the canonical scan key and immutable
`SastScanPlan` before queue reservation. All failure paths expose only bounded planning reasons,
write no successful receipt, and invoke neither queue reservation nor scanner execution.

The tenant-policy receipt remains part of the current canonical preimage. T047 advanced that
preimage to v3 as described below; T048 advances the current preimage to v4 with stable canary
membership as described in the next section. Terminal earlier-version records remain immutable
audit history and are never rewritten under a newer identity.

### Promotion evidence and lifecycle selection gate v1

`sast-rule-bundle-promotion-evidence-v1` accepts only an exact candidate/baseline pair whose
candidate manifest and supply-chain verification already exist in T045. The baseline must be
distinct, its bundle digest must equal the rollback target, the profile must match, every
environment/corpus reference must be immutable and digest-bound, and `measuredAt` must not be
future relative to the trusted lifecycle clock. Evidence construction applies the quantitative
thresholds in `quality-gates.md`. The positive and negative sample counts must sum exactly to the
golden-corpus denominator, subset denominators cannot exceed that bound population, and the
candidate p95 must satisfy both the relative regression threshold and the profile's absolute
Fast/Deep SLO. Failed or incomplete metrics create no evidence row. Evidence
is explicitly automated-only and has zero approval authority.

`sast-rule-bundle-promotion-approval-v1` is an exact human decision bound to that evidence and
candidate. Candidate authors cannot approve their own work. Approval roles and approvers are
unique within a transition and ordered canonically. Security Engineering is mandatory on every
edge; `ACTIVE` and `RETIRED` also require an independent Scan Platform or Security Operations
approval. Approval time must lie between evidence measurement and transition time.

`sast-rule-bundle-lifecycle-transition-v1` permits only:

```text
DRAFT -> VALIDATED -> CANARY -> ACTIVE -> RETIRED
CANARY|ACTIVE -> SUSPENDED
SUSPENDED -> ROLLED_BACK
```

Every row increments one bundle's sequence, binds the immediately previous transition and
digest, revalidates the exact evidence and approvals, and is immutable after insertion. A
`CANARY -> ACTIVE` transition requires `CANARY_OBSERVATION`; suspension requires
`EMERGENCY_SUSPENSION`; rollback requires `ROLLBACK`. Each authority must return a matching
digest-bound receipt. T048 installs `CANARY_OBSERVATION`; T049 installs
`EMERGENCY_SUSPENSION`; `ROLLBACK` remains unavailable until T050 installs its corresponding
implementation. All other edges require `NONE` and must contain no external receipt.

Before tenant-policy resolution, the lifecycle gate serializably reloads the latest transition,
evidence, and approvals and accepts only `CANARY` or `ACTIVE`. It persists one content-free
`sast-rule-bundle-lifecycle-selection-v1` receipt and enriches the immutable scanner-set
descriptor with the lifecycle state, sequence, transition, evidence, approval-set, and selection
receipt digests. Denial, stale selection, chain drift, unavailable persistence, or invalid clock
creates no successful receipt and no queue reservation. Receipt replay rechecks latest state;
ordered manifest-row locks and one serializable scanner-set transaction make all bundle receipts
atomic, while database advisory locks and triggers independently reject transition/selection
forks. Compatibility verification therefore precedes lifecycle selection, lifecycle selection
precedes tenant policy, and both verified receipts precede canonical-key construction and queue
admission.

The immutable plan retains the exact selection receipt for audit and admission validation. The
lifecycle portion introduced by `sast-canonical-scan-key-v3` commits only the stable state, sequence,
transition ID/digest, evidence ID/digest, and approval-set digest; it deliberately excludes the
evaluation-time-derived selection receipt ID/digest so an equivalent retry keeps one canonical
identity. `compatibilityReceiptDigest` remains committed. Immediately before writing a queue
reservation, the serializable store locks a trigger-maintained latest-transition head for every
manifest in deterministic order and revalidates both that stable projection and the persisted
selection receipt. The database reservation trigger applies the same fail-closed fence to direct
writes, so a concurrent suspension or retirement either precedes and rejects admission or follows
an already-serialized reservation.

T047's lifecycle-bearing preimage was exactly `sast-canonical-scan-key-v3`. Before that cutover, all
non-terminal v2 SAST plans and reservations must finish or be explicitly canceled; the schema
migration rejects a dirty cutover. Terminal v2 records remain immutable audit history and are
never rewritten or dispatched under the v3 identity.

### Deterministic canary cohort and observation gate v1

T048 registers one immutable `sast-rule-bundle-canary-rollout-v1` for one candidate manifest and
profile. The candidate must still be the exact latest T047 `CANARY` transition, the distinct
baseline must still be the exact latest `ACTIVE` transition, and both must rebind to the rollout's
T045 manifests, bundles, profile, T047 evidence, and candidate transition. The rollout also fixes
one digest-bound HMAC key reference/version, platform eligibility policy, exact observation
source, creation time, and the non-skippable progression below. A candidate manifest/profile is
single-use: `PAUSED` and completed rollouts cannot be resumed or replaced under the same pair.

```text
INTERNAL_CORPUS -> INTERNAL_REPOSITORIES -> 1% -> 5% -> 25% -> 100%
```

Eligibility is an immutable platform-owned decision. Only internal corpus, internal repository,
or eligible production classification is accepted, and contractual/residency exclusion is
explicit. The HMAC preimage is
`sast-rule-bundle-canary-membership-hmac-v1` plus UTF-8 byte-length-framed tenant ID,
repository-binding ID, profile ID, and rollout ID. HMAC-SHA-256 key material must decode from
canonical base64 to at least 32 bytes, is used in memory and zeroed, and is never persisted. Its
SHA-256 fingerprint must equal the digest suffix of the fixed key reference, preventing silent
material drift under one reference/version while persisting no secret. The first eight digest
bytes modulo 10,000 are the membership bucket; application and PostgreSQL
derive the same value. Repository content, findings, severity, and customer attributes are
forbidden inputs.

The planner order is T045 compatibility -> T047 lifecycle -> T048 canary -> T049 kill switch ->
T046 tenant policy.
An exact candidate receipt enriches the rule-bundle descriptor with rollout, membership, bucket,
step, step-head, and assignment identities. If a supplied `CANARY` bundle resolves to baseline or
exclusion, this gate rejects it rather than rewriting a descriptor that already passed
compatibility and lifecycle verification. Trusted orchestration must submit the separately
verified exact `ACTIVE` baseline scanner set for a non-cohort production scan; an explicitly
excluded scope receives no candidate. Active bundles always carry `canaryAssignment=null`. A
canary bundle is valid only with an exact candidate assignment. Denial, missing eligibility,
HMAC failure, lifecycle drift,
paused/completed rollout, stale step, store failure, or clock failure creates no plan or queue
reservation.

`sast-canonical-scan-key-v4` retains every v3 field and additionally commits the stable rollout
ID/digest, membership ID/digest, bucket, and `candidateAssigned=true`. It deliberately excludes
the evaluation-time assignment receipt ID/digest, rollout step, and step-head decision so exact
retries keep one identity. Those excluded values remain in the immutable plan. Queue admission
first locks/revalidates T047 lifecycle heads, then locks the T048 rollout head and verifies the
persisted candidate receipt, exact current step/head, manifest, membership, and selection before
reading the scan. The database trigger applies the same fence to direct inserts. Before v4
cutover, every non-terminal v3 plan and reservation must finish or be explicitly canceled;
terminal v3 history remains immutable.

An observation is accepted only from the rollout's fixed source after independently rebinding an
immutable queued plan, exact candidate assignment or exact `ACTIVE` baseline selection, one
terminal attempt with matching start/end, complete or explicitly incomplete T039 coverage,
T040 publication authority, and a digest-bound telemetry source. The source supplies only
bounded scalar measurements. The collection caller supplies no cohort role or repository-size
bucket; the trusted source derives both from durable plan and telemetry authority. The store
derives coverage completeness and publication denial
from durable rows, verifies attempt and plan scope, and stores no repository/finding content,
secret, HMAC key, or JSON payload. Baseline and candidate observations are partitioned by exact
profile and `SMALL|MEDIUM|LARGE` repository-size bucket.

Each append-only `sast-rule-bundle-canary-step-decision-v1` reloads the current rollout/lifecycle
heads, locks the step head, selects every committed observation in the exact closed window,
whose cutoff is the evaluator's trusted service time, sorts and binds the complete set without
accepting a caller-provided cutoff or IDs, and recomputes all
candidate/baseline aggregates. The first four steps require at
least 200 completed scans per arm and 24 hours; 25% and 100% require at least 1,000 per arm and
48 hours. Every applicable size bucket must be represented in both arms. Candidate gates are:

- false-positive rate no more than two percentage points above baseline;
- scanner failure rate no more than 2% of eligible attempts;
- p95 latency no more than 20% above baseline and no more than 10 minutes Fast or 45 minutes Deep;
- completed-scan-normalized Critical/High finding rate no more than 20% above baseline;
- complete telemetry and coverage, exact publication data, and all profile-size comparisons; and
- zero cross-tenant, secret-leak, sandbox-escape, stale-publication, unauthorized-egress,
  missing-destruction-evidence, evidence-policy-violation, or unsigned-artifact-execution events.

Time or per-arm sample insufficiency is `PENDING` and does not advance the head. Incomplete
coverage and any other hard-gate failure are terminal `PAUSED`; no later eligibility, assignment,
observation, or decision is
accepted. A `PASSED` decision advances exactly one step. Only six contiguous ordered passes,
ending at 100%, can issue one immutable
`sast-rule-bundle-canary-observation-receipt-v1`. The lifecycle router accepts that exact receipt
only for the matching candidate's `CANARY -> ACTIVE` transition and no other edge. The production
observation-source adapter intentionally defaults unavailable until production qualification can
provide durable metrics; T048 never fabricates an observation to unlock promotion.

### Signed SAST kill-switch authority v1

T049 defines these exact selector families:

```text
GLOBAL(SAST)
SCANNER_VERSION(scanner, version)
RULE_BUNDLE(bundle digest)
SEMANTIC_RULE(semantic rule ID)
PROFILE(profile ID, signed profile digest)
TENANT(tenant ID)
REPOSITORY_BINDING(tenant ID, repository-binding ID)
CAPABILITY(capability)
EXTERNAL_PUBLICATION(GLOBAL | TENANT | REPOSITORY_BINDING)
```

Each selector has a canonical `sast-kill-switch-selector://<sha256>` identity and one immutable
`sast-kill-switch-decision-v1` predecessor chain. A decision is exactly `ACTIVATE` or
`DEACTIVATE` and binds sequence, previous ID/digest, reason, incident, Security On-Call or
Platform On-Call actor, effective/review/expiry times, rollback-target reference, signature/
provenance references, audit reference, and decision digest. Customer input and all content,
secret, signature-byte, provenance-payload, and arbitrary-JSON fields are forbidden. A matching
`sast-kill-switch-verification-v1` from the trusted signature authority must commit in the same
transaction. The production authority defaults unavailable; no unsigned decision can commit.

A trigger-owned head is the only mutable projection. The store materializes a durable inactive
sequence-zero placeholder before locking every applicable selector in lexical key order, so a
first activation cannot race an absent row. PostgreSQL verifies predecessor continuity, selector
stability, no forks, no future activation, exact verification, and ledger immutability. An active
head whose expiry is at or before trusted evaluation time is corrupt/unavailable authority and
fails closed; expiry never acts as implicit deactivation.

Every application boundary compares its supplied boundary time with a service-owned trusted
clock under a bounded skew before evaluation. A stale or future caller-selected time is invalid
authority rather than a way to reuse an earlier clear head set.

`sast-kill-switch-evaluation-v1` binds one content-free trusted runtime context, purpose gate,
trusted time, complete selector-head set, exact active-match set, outcome, and effective coverage.
Normalized head children must cover all applicable selectors exactly once, while match children
must equal the active subset. The only gates are `PLANNING`, `QUEUE_ADMISSION`, `SCANNER_START`,
`ARTIFACT_ACCEPTANCE`, `RETRY_ADMISSION`, `COVERAGE`, `EXTERNAL_PUBLICATION`, and `AI_ADVISORY`.
Global/tenant/repository publication selectors participate in publication and AI gates; unrelated
internal processing does not include them.
The context permits at most two runtime rule bundles and the normalized snapshot is hard-capped at
50,020 selector bindings. Evaluation and queue fences lock that bounded set in one canonical
set-based query and compare drift with one anti-join; no selector-sized SQL loop is permitted.

Only a `CLEAR` planning evaluation becomes `sast-kill-switch-planning-v1` in the immutable plan.
Its evaluation time/head digest stays out of `sast-canonical-scan-key-v4`; no key cutover occurs.
Immediately before reservation, application code and the database insertion trigger lock and
revalidate the exact persisted planning receipt plus current head set after lifecycle/canary
fences. Application code reconstructs the canonical context digest and selector keys from the
immutable plan; PostgreSQL independently compares the exact normalized selector identities and
closed-set count. Omitting an applicable head, even when the remaining receipt is internally
consistent, rejects. Historical terminal plans may omit the descriptor, but every new queue
insertion must have it and pass the current fence.
An accepted artifact intent recovered after a crash must run `ARTIFACT_ACCEPTANCE` again before
storage application; denial replaces it with a new digest-bound quarantine intent and operation.
AI performs `AI_ADVISORY` both before inference and again after completion immediately before
advisory persistence.

Every later boundary obtains a fresh evaluation from durable plan state. `SCANNER_START` runs
after durable run creation and before the first provider repository-manifest read or scanner
execution. Active scope produces `KILLED`, zero provider/scanner calls, and mandatory cleanup.
Artifact acceptance maps active to quarantine; retry admission denies a new attempt; publication
and AI make zero downstream calls. Authority unavailable never becomes clear. Effective coverage
is a separate current projection: semantic-rule/capability-only activation is `PARTIAL`, any
other runtime selector is `FAILED`, and publication-only activation is `UNCHANGED`. T039 factual
coverage, old plans, findings, and lifecycle history remain immutable.

Retry admission is also a two-authority composition. The fresh `RETRY_ADMISSION` evaluation and
an independent current scanner-set availability authority must both succeed, and their exact
scanner-set digest must agree. The availability port defaults unavailable; kill-switch `CLEAR`
never implies that withdrawn scanner images, wrappers, rules, or databases are deployable.

The T037 lifecycle coverage port is a two-authority composition. A fresh persisted-plan
`COVERAGE` evaluation runs first; only `CLEAR` with `UNCHANGED` delegates to the independent T040
freshness/comparability gate. Active scope returns rejected coverage and unavailable T049
authority remains unavailable without invoking T040. External comment planning and each
comment-dispatch worker claim likewise obtain separate fresh `EXTERNAL_PUBLICATION` evaluations;
activation between planning and claim leaves the outbox unclaimed and makes zero publisher calls.

The T049 artifact gate composes rather than replaces T031 acceptance authority. It evaluates the
kill switch first, returns a kill-switch-bound denial without invoking downstream authority when
active, and delegates a clear result to the independent Data/Security Plane acceptance port. That
port retains its unavailable production default until a qualified storage/acceptance adapter is
installed; a clear switch alone can never produce `ACCEPTED`.

For `CANARY | ACTIVE -> SUSPENDED`, the lifecycle router asks T049 for one
`sast-kill-switch-emergency-suspension-v1` receipt. Under lifecycle and selector locks it must
rebind the exact latest manifest/bundle/transition/promotion evidence and at least one currently
active applicable global, bundle, scanner-version, semantic-rule, or signed-profile selector.
The complete active decision set and trigger decision are digest-bound. Cross-bundle, stale,
deactivated, expired, changed-set, or replay-conflicting authority is rejected. The lifecycle
transition locks and recomputes every applicable active selector, count, and canonical digest;
changing any captured non-trigger selector invalidates the receipt. Its reference is
exactly `sast-kill-switch-suspension://authority/<receiptDigest>` so the pre-existing lifecycle
authority contract can verify the reference without a circular digest. The receipt has no rollback
authority; `SUSPENDED -> ROLLED_BACK` remains T050.

The optional automation input is exactly
`sast-kill-switch-canary-suspension-request-v1 { canaryDecisionId,
canaryDecisionDigest }`. The resolver first derives manifest/rollout identity from that immutable
row, then locks the matching lifecycle head before the canary head and reloads the exact current
`PAUSED` decision, rollout, and complete normalized hard-failure reason set. Only then can it emit
`sast-kill-switch-canary-suspension-signal-v1` with a derived `CANARY_PAUSED | ZERO_TOLERANCE`
trigger. Manifest, bundle, profile, lifecycle transition, reasons, and time are output-only;
unknown request fields fail exact validation and `customerTargetAccepted=false`. The signal alone
cannot activate a switch or mutate lifecycle state; signing and the exact emergency receipt remain
independent mandatory authorities.

## Cleanup Contract

A scan attempt is not operationally complete until:

- repository credential is revoked/expired and wiped
- scanner processes and child processes are dead
- writable output and scratch volumes are destroyed
- microVM is terminated
- result ingress is closed to new writes
- cleanup evidence and final audit signal are recorded

After policy evaluation, the attempt enters `CLEANUP_PENDING`. It may transition to
`COMPLETED` only when every condition above is true and its signed cleanup evidence is bound to
the current attempt. A failed, missing, or overdue condition transitions to `CLEANUP_FAILED`;
that state cannot transition to `COMPLETED`, denies external publication and AI advisory, and
requires an incident/audit record even if finding normalization already succeeded.

Missing destruction evidence beyond the cleanup SLO is a security alert and blocks the
sandbox provider from accepting new work when the failure rate exceeds its threshold.
