# Research: Production SAST Runtime Design

## Source Baseline

- Product and security requirements: `Security Scan SaaS Final Specification.docx`
- Completed plane boundaries: `002-production-scan-architecture`
- Completed microVM/runtime boundaries: `004-production-runtime-infrastructure`
- Completed deployment-operation boundaries: `005-production-deployment-operations`
- OpenGrep upstream: <https://github.com/opengrep/opengrep>
- OpenGrep SARIF producer pinned for the T032 golden mapping:
  <https://github.com/opengrep/opengrep/blob/1bef4ea4ff3264754132eec823b5b1d8cde3e4ee/src/osemgrep/reporting/Sarif_output.ml>
- OASIS SARIF 2.1.0:
  <https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html>
- Trivy filesystem scanning: <https://trivy.dev/docs/latest/target/filesystem/>
- Trivy vulnerability scanning: <https://trivy.dev/docs/latest/scanner/vulnerability/>
- Trivy misconfiguration scanning: <https://trivy.dev/docs/latest/scanner/misconfiguration/>
- Trivy secret scanning: <https://trivy.dev/docs/latest/guide/scanner/secret/>
- Trivy JSON producer pinned for the T033 golden mapping at v0.66.0 commit
  `7bcb181268893fdd69ef4582588c040bb1036c33`:
  [report model](https://github.com/aquasecurity/trivy/blob/7bcb181268893fdd69ef4582588c040bb1036c33/pkg/types/report.go),
  [modified-finding model](https://github.com/aquasecurity/trivy/blob/7bcb181268893fdd69ef4582588c040bb1036c33/pkg/types/finding.go),
  [vulnerability model](https://github.com/aquasecurity/trivy/blob/7bcb181268893fdd69ef4582588c040bb1036c33/pkg/types/vulnerability.go),
  [misconfiguration model](https://github.com/aquasecurity/trivy/blob/7bcb181268893fdd69ef4582588c040bb1036c33/pkg/types/misconfiguration.go),
  [secret model](https://github.com/aquasecurity/trivy/blob/7bcb181268893fdd69ef4582588c040bb1036c33/pkg/types/secret.go),
  and [JSON writer](https://github.com/aquasecurity/trivy/blob/7bcb181268893fdd69ef4582588c040bb1036c33/pkg/report/json.go)
- Trivy DB status/type dependency pinned by that release at commit
  [`c7c831e2254d`](https://github.com/aquasecurity/trivy-db/tree/c7c831e2254d)
- Syft v1.44.0 producer pinned at signed commit
  [`8cb78ce40ced`](https://github.com/anchore/syft/tree/8cb78ce40ced6a731fb83f2a491a67444f541bf1):
  [CycloneDX model encoder](https://github.com/anchore/syft/blob/8cb78ce40ced6a731fb83f2a491a67444f541bf1/syft/format/common/cyclonedxhelpers/to_format_model.go),
  [component/BOM-reference encoder](https://github.com/anchore/syft/blob/8cb78ce40ced6a731fb83f2a491a67444f541bf1/syft/format/internal/cyclonedxutil/helpers/component.go),
  and [license encoder](https://github.com/anchore/syft/blob/8cb78ce40ced6a731fb83f2a491a67444f541bf1/syft/format/internal/cyclonedxutil/helpers/licenses.go)
- CycloneDX 1.6 JSON schema pinned at commit
  [`8a27bfd1be5b`](https://github.com/CycloneDX/specification/blob/8a27bfd1be5be0dcb2c208a34d2f4fa0b6d75bd7/schema/bom-1.6.schema.json)
- SPDX License List JSON pinned at official release
  [`v3.28.0`](https://github.com/spdx/license-list-data/tree/v3.28.0/json), matching
  [Syft v1.44.0's generated list version](https://github.com/anchore/syft/blob/8cb78ce40ced6a731fb83f2a491a67444f541bf1/internal/spdxlicense/license_list.go)
- CPE validation follows the complete formatted-string ABNF in
  [NISTIR 7695 section 6.2.1](https://doi.org/10.6028/NIST.IR.7695)

Upstream commands and schemas change independently of AegisAI. Scanner wrappers therefore
own exact CLI flags while AegisAI contracts pin scanner image digest, wrapper version,
output schema, rule/database digest, limits, and exit behavior.

## Decision 1: Split Scanner Responsibilities

**Decision**: OpenGrep is authoritative for source-code SAST; Trivy is authoritative for
dependency vulnerability, secret, and IaC findings; Syft is authoritative for SBOM.

**Rationale**: The tools have different primary outputs. Explicit ownership prevents one
issue from appearing as multiple findings solely because two tools can inspect similar
files. Syft produces inventory and does not decide vulnerability status.

**Rejected**: Treating all three tools as interchangeable SAST engines.

## Decision 2: Use Wrapper Contracts, Not Caller-Supplied Commands

**Decision**: A platform-owned scanner wrapper maps an approved profile to a pinned tool
invocation. Queue messages and API inputs cannot carry executable strings, arbitrary flags,
plugin paths, or tenant-supplied rules.

**Rationale**: Exact CLI behavior changes across versions and arbitrary commands would
create customer-code execution and privilege-escalation surfaces.

**Rejected**: Persisting raw command lines in scan requests and allowing the orchestrator
to assemble shell commands dynamically.

## Decision 3: Java Is the First Detailed SAST Profile

**Decision**: `JAVA_FAST_V1` and `JAVA_DEEP_V1` are the first language-specific profiles.
Repositories without an approved profile use `COMMON_DEEP_V1` for dependency, secret, IaC,
and SBOM coverage only.

**Rationale**: The repository constitution and existing language handler are Java-first.
The common profile provides useful deterministic coverage without falsely claiming
language-specific SAST support.

**Rejected**: Marking every language recognized by OpenGrep as production-supported before
language-specific corpora, rules, normalizers, and quality evidence exist.

## Decision 4: No Build-Assisted Analysis in v1

**Decision**: Profiles use source and manifest analysis without package installation,
compilation, generated dependency resolution, or runtime tests.

**Rationale**: The product baseline prohibits executing or building customer code. Rule
coverage must state when unavailable symbol/build context reduces confidence.

**Rejected**: Running Maven or Gradle to improve interprocedural resolution.

## Decision 5: Use One microVM per Scan Attempt

**Decision**: Each attempt receives a new microVM, workload identity, scratch volume, and
short-lived repository credential. Retries never reuse the prior sandbox.

**Rationale**: Parser and scanner compromise must not persist across scans or tenants.

**Rejected**: Reusing warm customer workspaces or long-lived worker containers. Immutable
base images and public tool/rule/database caches remain reusable because they contain no
customer-derived data.

## Decision 6: Disable Archive Expansion and Submodules by Default

**Decision**: v1 does not expand repository archives, fetch submodules, or fetch LFS object
contents by default. It may inspect archive and LFS pointer metadata.

**Rationale**: This removes archive-ratio, nested archive, external submodule credential,
and unexpectedly large LFS download classes from the first production runtime.

**Rejected**: Automatically expanding and recursively scanning every repository artifact.

## Decision 7: Validate Outside the Sandbox Again

**Decision**: The sandbox produces a bounded artifact envelope. A separate result ingestor
verifies workload identity, tenant/scan scope, digests, schema, size, count, encoding, and
timestamps before normalization.

**Rationale**: Scanner output remains hostile even when generated by a signed scanner. A
compromised scanner cannot directly write findings or policy data.

**Rejected**: Giving the sandbox direct database or findings-service credentials.

## Decision 8: Stable Identity Excludes Volatile Coordinates

**Decision**: Finding identity uses repository binding, capability, semantic rule ID,
normalized path, symbol anchor, sink kind, and structural hash. Branch, commit, and line
numbers remain occurrence metadata.

**Rationale**: Lines and commits change during ordinary edits. Including them would reopen
duplicates and destroy trend accuracy.

**Rejected**: Fingerprints based only on rule ID + path + line number.

## Decision 9: Fail Closed on Coverage

**Decision**: Required scanner absence, failure, timeout, malformed output, quarantine,
security block, or stale state prevents external publication. Partial results remain visible
internally with explicit coverage.

**Rationale**: A clean result from one scanner is not a clean scan when the required set did
not complete.

**Rejected**: Publishing comments from whatever scanner happens to finish first.

## Decision 10: Separate Rule Bundle from Tenant Policy

**Decision**: Signed bundles are immutable. Tenant configuration selects approved
categories/rules and adds waiver or suppression metadata without editing the bundle.

**Rationale**: Mutable bundles are not reproducible and cannot be safely rolled back.

**Rejected**: Per-tenant copies of modified scanner rules.

## Decision 11: Pre-Mirror Trivy Data and Pin SBOM Format

**Decision**: Trivy vulnerability/check databases are mirrored and promoted outside the
scan path. Scans use a pinned digest and offline behavior. Syft v1.44.0 emits explicitly
versioned `cyclonedx-json@1.6`; the wrapper disables file metadata and license content, and
the accepted raw SBOM remains a short-lived Data/Security object capped at seven days.

**Rationale**: Trivy normally maintains external databases and checks bundles; uncontrolled
runtime updates would break reproducibility and egress isolation. Syft supports multiple
formats and optional raw file/license payloads, so the exact schema and privacy-affecting
producer settings must be explicit.

**Rejected**: Allowing each sandbox to download the latest database or choose its own SBOM
format.

## Decision 12: Quantitative Gates Are Release Blocking

**Decision**: Rule and scanner promotion requires complete golden/malicious corpus results,
>= 95% must-detect recall, >= 90% Critical/High precision, 100% regression recall for prior
must-detect cases, zero isolation/tenant/secret leaks, and lane SLO compliance.

**Rationale**: “Tests pass” is not a production SAST quality definition. Measurable gates
make false-positive, false-negative, security, and latency regressions reviewable.

**Rejected**: Operator judgment without recorded metrics or automatic rollback thresholds.

## Decision 13: Retire the Legacy Mock Path Before Production Traffic

**Decision**: The current user-facing `/api/scans` path must eventually become a compatibility
facade over canonical `ScanRequest` planning or be removed. It cannot decrypt stored user
OAuth tokens, collect source in the Control Plane, or call `MockAnalysisApiClient` in a
production configuration.

**Rationale**: The legacy path violates the target SCM credential and Scan Plane boundaries.

**Rejected**: Running legacy and production paths indefinitely behind undocumented feature
flags.

## Decision 14: Normalize the Pinned OpenGrep SARIF Producer, Not Generic SARIF

**Decision**: `opengrep-sarif-normalizer-v1` supports the exact safe subset emitted by the
pinned OpenGrep producer: one OASIS 2.1.0 run, `Opengrep OSS` plus exact semantic version,
successful notification-free invocation, rule-descriptor severity/tags, result text,
`matchBasedId/v1`, and zero or one `%SRCROOT%` primary location. It streams required scalar
fields, discards snippets/fixes/code flows/help markup, and emits a transient non-durable
candidate for T035/T036. The candidate is bound to the immutable plan and coordinated
attestation digests, while semantic rule identity/revision comes only from the signed bundle
manifest projection.

**Rationale**: A generic SARIF consumer would silently accept ambiguous extension components,
rule indirection, multiple runs, partial execution, or scanner-specific semantics that the
platform has not versioned. OpenGrep's producer also places result records before its rule
descriptors, so scalar streaming plus bounded rule/result maps preserves low memory use
without trusting document order.

**Rejected**: Materializing and deserializing the whole artifact, accepting any SARIF
producer that claims OpenGrep provenance, treating the scanner fingerprint as the platform
stable fingerprint, or persisting pre-redaction candidates.

## Decision 15: Normalize the Pinned Trivy JSON Producer Without Trusting Scanner Suppression

**Decision**: `trivy-json-normalizer-v1` supports only the JSON v2 result subset emitted by
the pinned Trivy 0.66.0 filesystem wrapper for vulnerability, secret, and failed
misconfiguration records. It streams bounded scalar fields, independently rehashes and
recounts direct plus `ExperimentalModifiedFindings` records, and emits only transient
non-durable candidates. Modified-finding status is preserved with
`platformPolicyAuthority=false`; modified records remain findings and cannot become AegisAI
waivers, suppressions, lifecycle states, severity overrides, or policy decisions.

Dependency semantic identity and revision come from the validated advisory ID and pinned
vulnerability database. Secret and IaC semantic identity/revision come only from the signed
checks-bundle manifest. The adapter generates safe deterministic title/description text and
discards Trivy `Title`, `Description`, `Message`, secret `Match`/`Code`, modified-finding
`Statement`/`Source`, traces, rendered causes, and other raw scanner context. Package findings
remain explicitly location-unknown because the fixed wrapper does not enable package-file line
coordinates.

**Rationale**: Trivy's modified-finding envelope represents scanner/external disposition, not
platform policy authority, and `--show-suppressed` deliberately includes it in the producer
output. Trivy secret `Code` can contain neighboring unredacted secrets even when the primary
match is masked. Capability-specific authority and scalar discard therefore prevent both
suppression smuggling and secret-context leakage while preserving deterministic provenance.

**Rejected**: Deserializing the full report, accepting license or unknown modified-finding
types, dropping modified findings, treating scanner status as policy, copying scanner prose
into candidates, hashing detected secret content, inventing dependency line coordinates, or
using the checks bundle as the dependency advisory authority.

## Decision 16: Ingest the Pinned Syft Directory Producer, Not Generic CycloneDX

**Decision**: `syft-cyclonedx-inventory-ingestor-v1` accepts only the CycloneDX JSON 1.6
directory subset emitted by pinned Syft v1.44.0. It verifies the exact schema URI, one
`anchore/syft` tool component and version, the wrapper-owned source component/path, package
and operating-system component identities, Syft provenance properties, canonical package
URL/BOM-reference/name relationships (including Syft's ecosystem-specific namespace rule),
NIST CPE 2.3 formatted strings, SPDX 2.3 expressions bound to the pinned 3.28.0 license and
exception lists, bounded declared licenses, and a canonical dependency graph. It
reuses the shared scalar-streaming parser, independently rehashes and recounts the artifact,
and rechecks T031 retention after streaming.

The output is a deterministic transient inventory with
`durablePersistenceAllowed=false`. Raw BOM references and the document serial number become
SHA-256 digests. Raw Syft properties and source paths, file components, raw license text,
license URLs, prose, external references, nested components, vulnerability/VEX extensions,
and artifact bytes are excluded. Repeated license identities caused by multiple producer
URLs are de-duplicated after every URL has been structurally validated and discarded; the
Syft URL-only fallback is dropped when the same URL is copied into `license.name`.
The inventory explicitly has SBOM capability only and cannot create findings, evaluate
vulnerabilities, influence policy, or enter an AI payload.

**Rationale**: CycloneDX 1.6 also represents VEX, vulnerability, cryptographic, nested, file,
and other structures that AegisAI has not admitted. Syft embeds repository locations and
package metadata in properties and may encode Java archive digests as URL-empty
`build-meta` external references. Producer-specific validation preserves legitimate pinned
output while preventing generic extension smuggling and long-lived path/prose leakage.

**Rejected**: Generic CycloneDX deserialization, counting the metadata tool as inventory,
retaining raw BOM references or Syft properties, treating an SBOM as vulnerability evidence,
accepting separator-count-only CPEs or regex-shaped invented SPDX IDs/exceptions, granting it
policy/AI authority, or persisting the pre-gate inventory.

## Decision 17: Redact Display Text and Reject Secret-Bearing Identity

**Decision**: `sast-secret-redaction-v1` is the only exported Scan Plane handoff for
T032/T033 candidate batches. It first verifies the exact canonical source-batch digest and
the still-active T031 accepted disposition. It performs deterministic, bounded span
detection over registered platform values, private-key blocks, authorization and URL
credentials, provider token formats, JWTs, secret assignments, and high-entropy tokens.
Overlapping and adjacent matches become one fixed `[REDACTED]` marker, so output reveals
neither matched value nor its length.

Only title, description, and optional location symbol are redactable display fields. A
detected value in scope/preflight bindings or in normalized path, semantic rule identity,
symbol anchor, sink kind, scanner version/match identity, rule provenance
identifier/revision, dependency vulnerability/package/type/installed/fixed-version identity,
secret category, or IaC check type/AVD identity rejects the whole batch. This avoids
resolving collisions by hashing or otherwise retaining a secret-derived identity preimage.
The output is a fresh
`SastSecretRedactionBatch` with per-finding decisions, ordered safe detector categories,
sanitized-only digests, no source-candidate digest, and
`durablePersistenceAllowed=false`. T036 is the sole consumer allowed to construct a stable
fingerprint from this handoff.

The implementation is asynchronous and cooperatively yields between bounded chunks rather
than scanning 25,000 candidates in one event-loop turn. An 8,000,000 inspected UTF-16
code-unit ceiling bounds total text work; 64-candidate and 32,768-code-unit chunk thresholds
bound each uninterrupted pass. Shared validators accept a trusted canonical SHA-256
digester and recompute decision, batch, and rejection preimages so T036 cannot trust a
format-only digest.

The detector families follow the provider/generic distinction documented by
[GitHub supported secret-scanning patterns](https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns),
the current [GitLab token-prefix registry](https://docs.gitlab.com/security/tokens/), and
the documented AWS `AKIA`/`ASIA` access-key identifiers in
[AWS IAM identifiers](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html).
The decision to exclude the values themselves, rather than log a correlation hash, follows
the [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
guidance for access tokens, passwords, connection strings, encryption keys, and primary
secrets. These sources were reviewed on 2026-07-26. Runtime patterns are the code-reviewed
v1 snapshot and never update themselves from the network; source changes require corpus
review and a new redaction contract version.

Typed provenance digest fields remain outside display text and are shape-bound separately.
Untrusted scanner title/description/symbol text receives no `sha1:`/`sha256:` or bare-hex
exemption: otherwise a scanner message could relabel a 32- or 64-hex credential as a digest
and bypass T035. Digest-shaped high-entropy display values are therefore redacted by design.

**Rationale**: Scanner rule messages may interpolate repository values even after snippets
and Trivy secret context are structurally discarded. Redacting only evidence is therefore
too late. Conversely, replacing identity-bearing values with one marker can collapse
distinct findings, while hashing the value would retain a secret-derived correlation
oracle. Display redaction plus identity rejection preserves both confidentiality and future
fingerprint integrity.

**Rejected**: Logging or persisting the pre-redaction batch digest, hashing matched values,
revealing provider/match detail in a rejection, masking only Trivy secret findings, silently
dropping a secret-bearing candidate, replacing identity fields and guessing a new identity,
trusting a forged `[REDACTED]` marker, or checking retention only before the pass.

## Decision 18: Construct Stable Identity Only from the Verified Sanitized Handoff

**Decision**: `sast-finding-identity-v1` accepts only a complete canonical T035
`SastSecretRedactionBatch`. It independently recomputes the source batch and sanitized
decision digests, projects the seven ordered stable fields, applies Unicode NFC and UTF-8
byte-length framing, and computes `sast-fingerprint-v1`. An `UNKNOWN` location contributes
the explicit zero-byte path component rather than a reason code or invented path. The pass
is capped at 25,000 findings, yields every 64 findings, and checks a monotonic active
retention window before and after processing.

The service keeps a transient digest-to-preimage map. Repeated observations are valid only
when the preimage is byte-identical. A digest reused for a different preimage rejects the
whole batch, including under the forced-collision test seam. Success returns a fresh
`SastFingerprintedFindingBatch` and is the first normalized-finding persistence-eligible
handoff. It deliberately grants no occurrence, lifecycle, correlation, coverage, evidence,
policy, publication, or AI authority; T037 and later gates own those decisions.

**Rationale**: A fingerprint that is deterministic but not rebound to T035 can preserve a
forged sanitized candidate. Including line, commit, scanner match IDs, or availability
reasons creates ordinary-edit churn or provider-dependent identities. Silently accepting a
hash collision would merge distinct security findings. Exact source recomputation, a
versioned byte contract, and a whole-batch collision response make the first durable boundary
reproducible without promoting it into lifecycle or policy authority.

**Rejected**: Fingerprinting pre-redaction candidates, trusting digest syntax, using locale or
runtime-native string length, inventing a path for `UNKNOWN`, persisting fingerprint
preimages, de-duplicating repeated observations inside T036, first-writer collision handling,
using scanner `matchBasedId` as platform identity, or allowing T036 output directly into
evidence, policy, publication, or AI flows.

## Decision 19: Separate Exact Lineage, Ordered Occurrences, and Target Lifecycle

**Decision**: `sast-finding-lineage-v1` independently revalidates the complete T036 handoff
against immutable scan state, then persists one global repository/capability/fingerprint
lineage and one immutable occurrence for every producer ordinal. Repeated identical
fingerprints deliberately remain separate occurrences. Source-batch replay is idempotent
only when the canonical batch and its complete ordered occurrence ledger match exactly.
All lineage, alias, occurrence, lifecycle, reconciliation, event, and audit changes run in
one serializable transaction with bounded acquisition, execution, and retry limits.

Exact fingerprints are the default continuity mechanism. A path change can retain continuity
only when a canonical, signed, fixed-commit, fixed-target, one-to-one
`sast-finding-rename-attestation-v1` is verified and its predecessor alias already resolves
unambiguously. Both aliases remain durable, which supports a later rename-back without
rewriting history. Missing predecessor aliases, ambiguous mappings, chains, cycles, and
fuzzy or AI similarity provide no rename authority.

Lifecycle state is separate per canonical tenant/repository/target context and separate from
policy or triage status. T037 consumes but never calculates a T039-owned
`sast-finding-lifecycle-coverage-v1` decision. `FIXED` and `REOPENED` are permitted only for a
strictly newer, complete, non-stale, comparable decision whose expected batch digests equal
the entire durable T037 observation-batch set for the current scan, including explicit
zero-finding batches. The default rename verifier and coverage gate are unavailable and
therefore fail closed. T037 grants no correlation, coverage-calculation, evidence, policy,
publication, or AI authority.

**Rationale**: Stable identity, observation multiplicity, and target lifecycle answer three
different questions. Collapsing them loses provenance, allows one branch to resolve another,
or turns missing scanner output into a false fix. Exact ledger replay and external coverage
authority make retries deterministic while keeping lifecycle transitions auditable and
forward-compatible with T038 correlation and T039 coverage.

**Rejected**: De-duplicating repeated fingerprints, deriving lineage from line or scanner
match IDs, repository-global lifecycle status, mutating legacy policy/triage state, accepting
partial or stale coverage, inferring completeness from the batches that happened to arrive,
omitting zero-finding batches, calculating coverage inside T037, last-writer-wins lifecycle
updates, deleting old aliases, or letting fuzzy/AI matching merge or resolve findings.

## Decision 20: Correlate by Authority Without Collapsing Capability Families

**Decision**: `sast-finding-correlation-v1` verifies every canonical T037 observation result,
then reloads the complete durable observation and ordered-occurrence set for the attempt. Its
source identity is a digest of immutable durable bindings, not the T037 result digest whose
valid replay flag changes. A serializable transaction rechecks that no zero/nonzero batch was
omitted or added before storing one batch, every source, bounded deterministic edges, two
provenance rows per edge, and one audit event. The resulting batch fences late T037 writes.

Scanner responsibility and the active profile jointly define authority. A scanner-owned,
required capability is authoritative; optional capability output is supporting only.
Repeated exact lineages use `EXACT_FINGERPRINT`. Dependency equality requires the canonical
ecosystem, package, installed version, and CVE tuple. Cross-capability canonical CVE and
same-file CWE can produce `SUPPORTING_EVIDENCE` or display-only `POSSIBLE_OVERLAP`. Groups use
deterministic star connections instead of quadratic all-pairs expansion.

**Rationale**: Correlation answers whether independently retained occurrences are related; it
does not answer which capability, severity, lifecycle, coverage, or policy result wins. Two
provenance rows and invariant no-inheritance flags keep a lower-severity or optional result
from hiding a Critical authoritative finding, while complete-set binding makes retries and
concurrent scanner completion deterministic.

**Rejected**: Reusing a T037 result digest as replay identity, accepting only the batches a
caller supplies, all-pairs comparison, merging capability lineages, severity winner-takes-all,
path/title/coordinate/scanner-ID/fuzzy/AI matching, dependency correlation without installed
version or ecosystem, storing raw match material, and allowing correlation to imply fixed,
coverage, evidence, policy, publication, or AI authority.

## Decision 21: Persist Coverage from Durable Authority and Deny Publication Until Freshness Exists

**Decision**: `sast-scan-coverage-v1` accepts only the canonical T038 correlation handoff and
independently reloads the immutable plan, current attempt, complete source set, scanner runs,
artifact envelopes, and final dispositions. The approved profile and scanner responsibility
matrix derive every required/optional scanner and capability. One serializable transaction
stores three canonical scanner records, one attempt-scoped coverage decision, and one
fail-closed external-publication decision only after evaluation is terminal. A canonical
`PENDING` result remains non-durable and is reevaluated as scanner state advances. Exact replay
is the only idempotent replay.

**Rationale**: A successful process exit, caller-provided capability list, or correlation
edge cannot prove that every required scanner ran against the same fixed commit and produced
an accepted artifact. Durable rebinding prevents optional output, zero-finding omission, or
artifact drift from laundering incomplete coverage. T039 intentionally records latest-target
authority as unavailable and stale/comparability as unknown; therefore even complete coverage
cannot publish, invoke AI, or mutate finding lifecycle before T040.

**Rejected**: Caller-supplied scanner/capability/stale flags, treating process success as
artifact acceptance, allowing optional scanners to replace required owners, synthesizing a
Syft finding source, last-writer-wins replay, per-replica coverage cache, publishing directly
from T039, or inferring latest-target freshness from the scanned commit alone.

## Decision 22: Separate Latest-Target Authority from Coverage and Fence Retry Admission

**Decision**: `sast-scan-freshness-v1` keeps T039 immutable and persists an independent,
provider-scoped latest-target observation plus a one-to-one freshness/comparability decision.
The fixed commit must equal a monotonic authoritative target head, and the prior complete scan
must match tenant, repository, target, supported profile family, required capabilities,
fingerprint version, and lifecycle scope. Only that exact conjunction creates external-action
eligibility or lets the T037 gate verify lifecycle input. It still creates no SCM write and no
AI payload.

`sast-scan-retry-decision-v1` is written before attempt two. It rechecks the immediately
preceding durable attempt-one failure/audit tuple plus mutable scanner-set and kill-switch
authority, while preserving immutable scan intent and requiring new attempt, sandbox, and
workload identities. The default target and mutable-runtime authorities are unavailable, so
the repository remains fail closed until live read-only provider and T049 governance adapters
are installed.

**Rationale**: Scanner completeness cannot prove that a provider target has not advanced,
and an old retry-eligible bit cannot prove that current runtime assets remain safe. Separate
canonical ledgers retain exact T039 replay, make every authority boundary auditable, and let
future publisher/evidence stages consume a narrow verified handoff.

**Rejected**: Caller-supplied head/fresh/comparable flags, comparing branch names instead of
fixed heads, assuming profile names imply compatible capabilities, mutating the T039 decision,
retrying attempt three, retrying cleanup/input/capacity/scanner/security failure, reusing a
sandbox identity, trusting a missing final audit event, or treating unavailable kill-switch
authority as clear.

## Decision 23: Build Evidence from a Rebound Accepted Occurrence and Reject Reconstruction

**Decision**: `sast-accepted-finding-evidence-v1` reloads the exact T040
verified/fresh/comparable decision, T039 complete coverage, T038 correlation source, and T037
occurrence, observation, normalized finding, lineage, and fingerprint before reading source.
The internal source authority defaults unavailable and returns only a bounded
scanner-redacted, attested fragment in memory. T041 reapplies known-format and platform-secret
redaction, verifies UTF-8 bytes and line count, then stores a canonical build decision and,
only when safe, a short-lived pack plus fragments.

Reconstruction is a deterministic interval decision rather than a caller flag. A file may
contribute at most two fragments; full-file, overlap, adjacency, or at least 25% combined line
coverage rejects the entire build. Candidate order, truncation, suppressed count, IDs, and
digests are canonical. Serializable re-read and the tenant/occurrence/policy/candidate-set key
permit exact replay only.

**Rationale**: Accepted scanner output alone does not prove that requested source text belongs
to the same fresh finding, and individually small snippets can reconstruct sensitive code when
combined. Durable rebinding closes the authority gap; interval union rules make
reconstruction risk auditable and independent of request order. Keeping all downstream
authority false lets T042 add classification, expiry enforcement, and deletion proof without
retroactively trusting T041 construction.

**Rejected**: Building from scanner titles/messages or rejected artifacts, accepting caller
paths/coordinates/redaction flags, storing raw source or platform secrets, per-fragment
best-effort acceptance after reconstruction risk, allowing adjacent snippets, using character
counts instead of UTF-8 bytes, mutable last-writer-wins packs, direct dashboard/AI access, or
adding an SCM writer in T041.

## Decision 24: Separate Purpose-Bound Access from Receipt-Proven Content Deletion

**Decision**: `sast-evidence-access-decision-v1` classifies dashboard and AI access as two
independent immutable decisions after a durable rebind of the complete T041/T040/T039/T038/T037
chain. The service reruns known-format, registered platform-value, and entropy redaction on
every access, validates paths and identifiers, and checks time before and after the read. The
dashboard receives only an authenticated tenant/repository-scoped redacted projection. AI
classification returns only a reduced reference with an at-most-24-hour eligibility window;
T042 never contacts a provider or constructs an AI payload. T041 pack flags and null
classification/deletion references remain immutable.

Every accepted pack receives a canonical `sast-evidence-deletion-schedule-v1` row in its
creation transaction. When seven-day retention expires, a deterministic operation is claimed
under a leased owner/token fence. The deletion authority defaults unavailable. A bounded,
operation-bound provider receipt must validate before pack and fragment content is removed and
an immutable `sast-evidence-deletion-proof-v1` is finalized. The original T041 build decision
and bounded audit/proof state remain retained; exact replay is allowed, while changed receipts,
stale claims, late reads, races, and clock rollback deny.

**Rationale**: Construction safety does not grant user or model access, and a database delete
attempt does not prove that every backing provider removed content. Purpose-specific ledgers
prevent dashboard consent from becoming AI consent, access-time redaction catches registry and
entropy changes, and a fenced provider receipt makes expiry an auditable outcome instead of a
best-effort timer. Retaining the build decision and proof preserves accountability without
retaining repository content.

**Rejected**: Mutating T041 safe flags, sharing one decision between dashboard and AI,
returning fragments before the second clock check, deriving AI eligibility from dashboard
access, retaining an AI payload for T043, treating a deletion request as deletion proof,
deleting before receipt validation, allowing an unfenced worker to finalize, or erasing the
T041 decision with the content.

## Decision 25: Derive an Expiring Reference-Only Advisory Handoff from Durable State

**Decision**: T043 accepts only tenant, repository-binding, evidence-pack, and model-version
intent. It calls the T042 AI classifier, reloads and validates the access ledger plus the exact
T037 occurrence/source and normalized-finding row, then calls the classifier again before
deriving `sast-ai-advisory-handoff-v1`. The access decision timestamp, rather than invocation
time, is canonical so every still-valid exact retry derives the same request, handoff, and
advisory identities.

The persistence ledger stores relationship references, digests, model version, expiry, and
fixed booleans only. The handoff/request JSON, title, path, source, secret values, fragments,
prompt, and provider request are not persisted there. The internal AI runtime receives the
normalized metadata and opaque reduced reference with `snippets=[]`; retrieval, tools, policy,
publication, lifecycle mutation, and SCM write authority are fixed false. Legacy direct
finding/evidence requests and unknown fields are rejected.

**Rationale**: A caller-safe reduced reference still does not prove which durable finding is
being described, and a valid decision can expire or drift while the occurrence is loaded.
Double classification plus exact durable rebinding closes that race. Reference-only persistence
keeps replay auditable without retaining a second copy of sensitive or expiring model input.

**Rejected**: Trusting caller-normalized findings, forwarding snippets or redacted fragment
content, persisting a full handoff JSON, deriving retry identity from wall-clock invocation
time, accepting dashboard-purpose authority, enabling model retrieval/tools, or treating an AI
response as finding, policy, publication, lifecycle, or SCM authority.
