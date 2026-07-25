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
  --output cyclonedx-json=<private-output>` with update, archive expansion, repository config
  discovery, Maven/local-cache enrichment, remote-license lookup, and external Go
  package-tool execution disabled by platform-owned environment.

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
| Source SBOM | Syft | Deep profiles | CycloneDX JSON reference |

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
identity, inventory, profile, source, and supply-chain digests. It counts SARIF results, Trivy vulnerabilities/
misconfigurations/secrets, and nested CycloneDX components independently of the envelope.
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
or finding lifecycle status and carries `durablePersistenceAllowed=false`. T035 must redact
the transient candidate before any durable storage, log, audit, dashboard, or evidence path;
T036 then computes the platform fingerprint and constructs the final normalized finding.

### OpenGrep SARIF adapter v1

`opengrep-sarif-normalizer-v1` accepts only an unexpired T031 `ACCEPTED` decision whose
ingestion ID, validation-result digest, canonical envelope digest, content digest/byte/record
counts, tenant/repository/scan/attempt/scanner binding, fixed commit, profile, scanner image,
wrapper, rule bundle, schema bundle, and normalizer bundle still match the immutable plan.
Retention is evaluated before and after streaming against the adapter's own default wall clock;
an alternate clock exists only as an explicit trusted test/task seam and is never read from
artifact or envelope payload.
The adapter does not expose a route and does not gain a general object-store read capability.
Its bounded stream is supplied only by the later Data/Security-owned redaction/persistence
worker; the default runtime remains unwired and fail closed until that worker exists.

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
  structured provenance. The scan rule-bundle digest is still bound at batch and candidate
  level, but it is not falsely presented as the dependency advisory source;
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

## Correlation Contract

Correlation is deterministic and versioned:

- `EXACT_FINGERPRINT`: one durable finding, new occurrence.
- `SAME_DEPENDENCY_CVE`: dependency findings may group by ecosystem, normalized package,
  resolved version, and CVE while preserving every manifest location.
- `SUPPORTING_EVIDENCE`: a non-authoritative overlap can support but not replace a finding.
- `POSSIBLE_OVERLAP`: display grouping only; no automatic merge or policy inheritance.

Source SAST, secret, dependency, and IaC findings remain distinct capability families even
when they refer to the same file.

## Coverage Contract

Coverage is evaluated after all required scanner runs reach terminal states.

| Condition | Coverage | Comment/block | AI |
| --- | --- | --- | --- |
| Every required scanner accepted | `COMPLETE` | Policy may allow | Profile/policy may allow |
| Required scanner absent/failed/timed out | `PARTIAL` | Deny | Deny |
| Required scanner still pending/running | `PENDING` | Deny | Deny |
| Quarantine, identity/digest mismatch, sandbox kill | `FAILED` | Deny | Deny |
| Complete but stale commit | `COMPLETE + stale` | Deny | Deny |

Optional scanner failure does not reduce required coverage but is visible. A scanner marked
required by tenant policy becomes required before execution and affects the canonical key.

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

AI receives finding metadata and reduced evidence references only after a second redaction
pass. AI never receives the result-ingress artifact reference.

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
