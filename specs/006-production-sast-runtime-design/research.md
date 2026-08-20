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
workload identities. T049 installs the mutable-runtime gate, while the target provider and
production signature authority default unavailable; the repository remains fail closed until
qualified live adapters are installed.

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

## Decision 26: Prove Advisory Consumption with an Immutable Zero-Authority Ledger

**Decision**: T044 accepts only tenant and T043 advisory identity under a tenant-bound internal
credential. In one bounded serializable transaction it locks the advisory context, reloads the
advisory, immutable handoff, occurrence, normalized finding, and lifecycle context, and then
locks the scan, lifecycle-context, and finding authority fences. All application writers to the
covered authoritative tables advance those same fences; normalized-finding and lifecycle bulk
writes aggregate distinct affected keys once per statement. The transaction hashes one stable scan
finding set, target finding status/severity, T037 lifecycle state/revision, finding policy
decision, finding-scoped waiver, and suppression snapshot, then inserts one
`sast-ai-advisory-authority-proof-v1` row. The proof projects that one locked snapshot into
byte-identical before/after fields; replay must still match current locked state.

The proof table contains only durable scope references, counts, component/state digests,
verification time, and fixed booleans proving zero finding creation/status/severity,
lifecycle, waiver, suppression, policy override, blocking, publication, and SCM authority.
It stores no advisory output, rationale, prompt, source, evidence, secret, or policy payload.
Policy accepts only a validated `sast-ai-advisory-policy-reference-v1` for display visibility;
deterministic finding severity and coverage remain the only enforcement inputs. Waiver and
suppression payloads use exact key allowlists and reject advisory/proof fields.

**Rationale**: A TypeScript interface, ignored `suggestedAction`, or two reads from one MVCC
snapshot does not prove that AI could not reach another write path. A database fence shared by
proof creation and every covered writer closes the race; persisting fixed false bits under
database checks and immutable triggers, using the same durable policy/lifecycle tables, and
verifying the proof reference at policy entry make the separation executable and auditable.
Bounded digest sets avoid retaining sensitive content or creating an unbounded proof operation.

**Rejected**: Trusting a caller-supplied before/after snapshot, relying on two same-transaction
reads without a writer fence, storing advisory or policy JSON
in the proof, allowing AI-suggested actions and merely ignoring them, regex-only lifecycle key
blocking, mutating the authoritative row to mark it checked, creating more than one proof per
advisory, or cascading normal tenant deletion through the immutable audit ledger.

## Decision 27: Keep Kill-Switch Authority Mutable, Signed, and Outside Canonical Scan Identity

**Decision**: T049 models every SAST kill switch as a platform-managed, signed, append-only
`ACTIVATE | DEACTIVATE` decision chain over one canonical selector. Selectors cover global SAST,
scanner version, rule-bundle digest, semantic rule ID, signed profile identity, tenant,
repository binding, capability, and global/tenant/repository external-publication scope. Every
decision binds its sequence and predecessor, actor role, reason, incident, effective/review/
expiry times, rollback target, signature/provenance references, and audit reference. A separate
immutable verification row attests the exact decision digest; a trigger-owned selector head is
the only mutable projection. Missing verification, an invalid chain, a future activation, or an
active decision at or after expiry is unavailable authority and fails closed.
Every runtime boundary also validates its supplied time against a service-owned trusted clock
with bounded skew, so a stale or future caller timestamp cannot preserve an earlier clear view.

Planning evaluates the complete content-free selector set after compatibility, lifecycle, and
canary selection but before tenant policy, persists an immutable `CLEAR` receipt in the plan,
and leaves the `sast-canonical-scan-key-v4` preimage unchanged. Queue admission locks all
applicable selector heads in canonical order, reconstructs the context digest and canonical keys
from the immutable plan, and verifies that exact receipt/head snapshot again. PostgreSQL also
derives every normalized planning selector identity and the closed-set count from the plan before
a direct reservation insert, so an internally consistent receipt cannot omit an active head. The
runtime context is limited to two rule bundles and 50,020 selector bindings; evaluation and queue
admission use one canonically ordered set-based lock plus an anti-join rather than per-head SQL.
Scanner start, artifact acceptance, retry admission, coverage, external publication, and AI
advisory each obtain a fresh purpose-bound evaluation. An active switch cancels a scanner only
after the durable run exists and before the first provider repository read or scanner execution;
accepted output from an affected run is quarantined, retries are denied, and affected AI or
publication side effects receive no authority. Historical T039 facts remain immutable; the
current evaluation separately projects `UNCHANGED | PARTIAL | FAILED` effective coverage.
Crash recovery rechecks an accepted artifact intent before storage application and replaces a
newly denied intent with quarantine. AI rechecks after inference and before persistence, closing
activation windows around both long-running boundaries.
Retry admission separately requires a current scanner-set availability authority whose exact
digest agrees with the switch context; the port defaults unavailable, so clear switch state never
asserts that withdrawn runtime assets remain deployable.
T037 lifecycle coverage composes that fresh `COVERAGE` evaluation outside the independent T040
freshness/comparability authority and delegates only a clear, unchanged result. External comment
planning and each dispatch-worker claim separately evaluate `EXTERNAL_PUBLICATION`, preventing an
activation between plan and claim from producing a claim or publisher call.
Artifact acceptance remains a two-authority chain: T049 can short-circuit to quarantine, but a
clear switch must still pass the independently unavailable-by-default Data/Security acceptance
port and therefore cannot widen T031 authority.

For a matching active global, bundle, scanner-version, semantic-rule, or signed-profile selector,
the same authority may issue one digest-bound `EMERGENCY_SUSPENSION` receipt for the exact latest
`CANARY | ACTIVE -> SUSPENDED` lifecycle edge. The receipt cannot authorize rollback, mutate an
old plan/finding, or select a replacement bundle; last-known-good rollback uses the separate T050
authority in Decision 28. The transition commit locks and recomputes the complete applicable active
decision set, rejecting
deactivation or replacement of any captured non-trigger selector. A separate exact two-reference
request can resolve a content-free automatic-suspension signal from
the locked current T048 `PAUSED` decision, rollout, lifecycle head, and normalized reason set.
The caller cannot supply a manifest, bundle, profile, lifecycle target, pause reason, or
zero-tolerance claim.

**Rationale**: Including live switch state in the canonical key would split identical fixed-
commit work whenever operations toggled a control, while checking it only once would admit a
plan-to-execution race. An immutable planning receipt plus locked admission and fresh side-effect
gates preserves stable scan identity and historical truth while making current operational
authority fail closed and auditable.

**Rejected**: Mutable database booleans, unsigned operator input, decision overwrite, expiry
treated as deactivation, absent selector rows interpreted without a locked placeholder, changing
canonical scan key v4, trusting only the planning-time receipt, killing a scanner after provider
access begins, accepting artifacts from a killed run, deriving current coverage by rewriting
T039, using external-publication scope to disable unrelated internal processing, or allowing a
kill switch to perform T050 rollback, trusting a receipt's own head count without comparing it to
the immutable plan, or trusting a caller-provided canary target/signal.

## Decision 28: Derive Rollback Only from Original Promotion Evidence and Preserve History

**Decision**: T050 accepts only an exact suspended candidate transition plus bounded operational
and signing metadata. It deliberately has no caller-supplied baseline, rollback target, or scanner
set. The service derives the one permitted last-known-good target from that candidate's original
T047 promotion evidence, requires its rollback digest to equal the distinct baseline bundle,
revalidates both T045 manifests and attestations, common bundle/scanner identity and signed
profile, the exact T049 emergency-suspension receipt, and current candidate `SUSPENDED` plus
baseline `ACTIVE` lifecycle heads.

One content-free command is valid for 15 minutes and must have a matching verification from an
independently qualified signature/provenance authority whose production default is unavailable.
Receipt issuance requires exactly one fresh Security Engineering approval and exactly one fresh
independent Scan Platform or Security Operations approval, excluding the command actor. Command,
verification, approvals, receipt, and receipt-approval bindings are normalized append-only
ledgers with exact replay only.

The store locks candidate and baseline heads in canonical manifest-ID order under bounded
serializable transactions. PostgreSQL repeats the evidence, attestation, suspension, signature,
approval, and both-head checks at receipt and lifecycle insert boundaries. The resulting
digest-bound receipt authorizes only the next candidate `SUSPENDED -> ROLLED_BACK` append. Every
baseline/history/scanner-set/finding/policy/publication/SCM authority bit is false. Its baseline
identity is merely a handoff: trusted scanner-set ownership must separately choose the exact
still-`ACTIVE` baseline and pass the existing planning and queue chain. Concurrent exact retries
converge on one receipt and one transition; head drift fails closed.

**Rationale**: Choosing a target during an incident would turn operator, customer, AI, or scanner
input into supply-chain authority. Binding rollback to the already qualified promotion baseline
preserves deterministic recovery, while fresh dual control and commit-time two-head fencing close
stale receipt and race windows. Separating the narrow lifecycle receipt from scanner-set routing
prevents rollback authority from silently bypassing compatibility, canary, kill-switch, policy,
or queue gates.

**Rejected**: Caller-selected targets, using the current mutable manifest tag, allowing the T049
receipt or canary signal to choose a replacement, reactivating or rewriting the baseline, editing
the candidate's prior state, one-person or automated approval, approvals outside the 15-minute
window, unsigned commands, one-head locking, receipt-only application checks, scanner-set mutation
inside rollback, or rewriting historical plans, findings, coverage, evidence, or audit records.

## Decision 29: Pin Golden Qualification Inputs Before Scanner Execution

**Decision**: T051 establishes a code-reviewed, deterministic, versioned golden input authority
before any production-equivalent scanner run. The checked-in v1 snapshot contains 800 exact cases:
400 positives and 400 one-to-one negatives. A separate immutable prior-release manifest
authenticates the exact 400 historical Critical/High positives by case ID/digest/key, case/rule
revision, semantic rule, and severity. Its reviewed digest is pinned in generator code and its
initializer refuses overwrite, so the snapshot cannot silently derive a smaller historical set
from current positives. Twenty semantic rule families each contribute 20 positive and 20 negative
cases. `JAVA_FAST_V1`, `JAVA_DEEP_V1`, and `COMMON_DEEP_V1` each meet the 200/200 profile floor,
with negative behavior counts of 95 patched, 35 sanitizer, 95 safe-API, 80 comment/string, and 95
generated/vendor. Each family receives only applicable classes, and generated/vendor fixtures
keep the actual unsafe construct under an excluded path.

Every case binds the corpus owner, Apache-2.0 license, digest-bound provenance, semantic revision,
scanner/capability/profile tuple, expected result, exact source bundle bytes and digest, bounded
line range and anchor, and one unique future workspace path. The 40 UTF-8/LF/NFC source bundles are
platform-authored static inputs only. Their contract fixes customer-content acceptance, execution,
package installation, build, dynamic execution, and network use to false.

The loader first verifies the canonical manifest and pinned digest, then regenerates the expected
snapshot in memory and requires byte-exact snapshot and source equality, exact source-set
membership, real-path containment, no symbolic links or
junctions, an exact four-entry corpus root, stable before/open/after filesystem identity, bounded
bytes/lines, and matching range anchors. No-follow file opens are used where the host exposes
them. This makes reviewable source the
authority instead of trusting a mutable JSON count or directory. CI runs both shared hostile-shape
tests and filesystem tampering tests plus the explicit corpus validator.

**Rationale**: Qualification metrics are meaningless if their denominator, expected outcome, or
source material can drift between review and execution. Separating immutable input construction
from T052's other attack/performance corpora and T053's isolated scanner execution makes each
claim auditable and prevents a generated sample from being mistaken for production evidence.

**Rejected**: Downloading benchmarks at CI/runtime, mutable branches or tags, customer repository
fixtures, hand-edited snapshots, unpaired negatives, a denominator below the per-profile/per-rule
floor, deriving prior must-detect cases from current positives, changing or overwriting the
reviewed prior manifest, declaring inapplicable negative kinds, shared scan paths, following links, permissive text
decoding, installing fixture dependencies, building or executing fixtures, or treating successful
input validation as scanner accuracy, isolation, performance, or deployment proof.

## Decision 30: Pin Multi-Class Qualification Inputs as Non-Executable Recipes

**Decision**: T052 completes the pre-execution input authority with one exact 84-case snapshot:
16 schema/parser, 25 malicious-repository, 17 fingerprint/correlation, 17 evidence/privacy, and 9
performance cases. The required scenario arrays are shared contract constants and snapshot
construction requires each member exactly once. Every case binds its fixture ID/digest/byte count,
profiles, expected control outcome, owner/license/digest-bound provenance and revision, minimum
run count, and the T053/T054 stage that must later supply evidence. Performance supplies three
size buckets for each v1 profile, including exact profile limits, one digest-bound hardware class,
three warm-up runs, and a 30-measurement floor.

Hostile content is represented only by `sast-multi-class-qualification-fixture-v1`. It has typed
bounded scalar parameters, canonical base64 byte segments with bounded repeat expansion, and a
closed declaration-action set. It has no command interpreter and rejects command, argv,
environment, executable, script, shell, or URL parameter/argument names. Path traversal, invalid
UTF-8, special files, archive behavior, resource/output/time pressure, secret sentinels, identity
sequences, evidence reconstruction, prompt injection, retention, and large synthetic repositories
therefore remain inert reviewed data. No live symlink, FIFO, device, bomb, executable, customer
repository, package installation, build, dynamic test, scanner, or network operation is stored or
run by T052.

Revision `1.0.2` closes the interpretation gaps before isolated execution: every profile-relative
boundary—including artifact bytes and record count—carries the exact plus-one value for each
immutable profile and selects through the case profile with a generic segment formula; shared JSON
depth and string boundaries come directly from the validator's 64 and 4,096 limits; a cycle contains
both directed symlink declarations; binary and malformed UTF-8 cases bind the intended raw bytes;
and fingerprint invariance cases contain complete vectors that differ only in the excluded line,
branch, commit, or unknown-location reason. The remaining identity cases also bind concrete rename,
migration, replay, collision, lifecycle, and related-only inputs so a future runner cannot pass by
branching on the scenario label.

The generator produces the snapshot and 84 canonical fixture files. Bootstrap is exclusive and
refuses overwrite; normal generation requires the exact existing tree and performs no-follow
writes where supported with file and directory identity checks. The loader regenerates all assets
in memory, accepts only the exact three root entries, five class directories, and reviewed file
set, and rejects invalid UTF-8, BOM, CRLF, NUL, non-NFC, oversize, path escape, links, filesystem
substitution, unknown fields/actions, missing/duplicate scenarios, count/digest/outcome/stage/
profile/hardware drift, or authority widening. CI validates T051 and T052 together.

**Rationale**: Parser bombs and hostile repository shapes are necessary production qualification
inputs, but checking dangerous live objects or hundreds of gigabytes into the repository would
itself widen the attack surface. A small exact recipe language makes the denominator reviewable
and deterministic while preserving a hard trust boundary: T053/T054 must explicitly map each
allowlisted declaration inside fresh isolation and must produce independent execution evidence.
Successful input validation cannot be mistaken for a scanner, privacy, performance, or readiness
pass.

**Rejected**: Executable fixture scripts, arbitrary command/argv/environment maps, downloading
benchmarks, customer repositories, live special files or symlinks in Git, compressed bombs,
pre-expanded 2 GiB/250,000-file trees, mutable hardware labels, fewer than 30 performance runs,
empty or duplicate scenario denominators, opaque hand-authored snapshots, permissive extra files,
following links, platform-default BOM stripping, and treating T052 as T053/T054 evidence.

## Decision 31: Separate the T053 Provider Handoff from Live Qualification Evidence

**Decision**: T053 has two explicit boundaries. The repository boundary deterministically expands
the 41 applicable T052 cases across three profiles into a 123-cell immutable manifest, fixes a
closed guest-only materialization policy, validates a complete digest-bound provider dependency
set, and emits an immutable execution plan. The evidence boundary is external: Security
Engineering and Scan Platform sign the plan; a production-equivalent provider creates one new
microVM per cell; both approvals strictly predate the earliest execution start; and the provider
plus qualification runtime sign each exact receipt.

Receipts record unique attempt/sandbox/workload/attestation identity, materialization and outcome,
five phase egress observations, eight prohibited-effect counters, and six cleanup proofs completed
within 60 seconds. An offline verifier checks the dependency-set-bound trust bundle, canonical
Ed25519 SPKI identity, signatures, freshness, uniqueness, bindings, zero-effect requirements, and
destruction. Its service-owned UTC clock is the sole evaluation-time source; caller-selected
historical instants are rejected. Zero or a valid subset of receipts stays `PENDING_PROVIDER_EXECUTION`, any violation
is `FAILED`, and only all 123 may be `PASSED`. A pass grants only entry to T054; readiness remains
false.

**Rationale**: Committing provider credentials, signing keys, fabricated attestations, live hostile
objects, or local scanner output would collapse the boundary the qualification is meant to prove.
A deterministic package makes provider work reproducible and reviewable while a cryptographically
separate receipt bundle ensures CI cannot self-certify isolation or destruction.

**Rejected**: Running hostile materialization on the host or ordinary PR runner; using a pod as the
sole isolation boundary; one sandbox for multiple cells; scenario-name branching; mutable image or
policy references; unsigned plans or receipts; a repository-shipped trust root; accepting partial
evidence as success; retroactive approval; caller-controlled evaluation time; inferring cleanup
from provider termination alone; using the local clock or
filesystem presence as an attestation; and marking T053 complete before real provider evidence.

## Decision 32: Make T054 Receipt-Recomputed and Cryptographically Dependent on T053

**Decision**: T054 has a repository contract boundary and a later external evidence boundary. The
repository derives exactly 3,462 cells from the complete T051 and T052 authorities, including a
same-negative-corpus candidate/baseline comparison and 30 candidate plus 30 baseline runs for each
of nine fixed hardware-bound performance buckets. It cannot create a plan until a Qualification
Authority signature attests an exact T053 `PASSED` result that grants only T054 entry.

The plan additionally consumes the exact T053 dependency set named by the result and refuses any
T054 provider or adapter mismatch. For every T054 artifact, the verifier loads the complete
artifact signature and provenance statement, recomputes both envelope digests, binds provenance
subject/source/builder/materials to the artifact, and verifies both Ed25519 signatures before it
accepts the closed `SUPPLY_CHAIN_AUTHORITY`-signed verification set. The trust bundle is accepted
only when its byte digest equals `SAST_T054_TRUST_POLICY_DIGEST` from independent process
configuration; a submitted dependency set cannot introduce its own trust root.

Every execution receipt binds candidate and baseline assets, provider, hardware, cell, profile,
queue-to-cleanup phase evidence, resource observations, and one or two fully destroyed fresh
microVM attempts. An infrastructure retry is retained rather than replacing the first attempt.
Provider, qualification-runtime, and telemetry authorities independently sign each receipt. The
offline verifier accepts no summary measurements: it reconstructs every denominator and
percentile from the complete signed set and applies the exact quality-gate thresholds and all
eight zero-tolerance counters. Missing T053 evidence is `BLOCKED_T053_QUALIFICATION`; a valid
strict receipt subset is `PENDING_PROVIDER_EXECUTION`; any invalid evidence or gate breach is
`FAILED`; only the complete passing set authorizes T055 entry.

**Rationale**: Allowing T054 to trust a database row, CI aggregate, retried final status, mutable
hardware label, or caller-selected receipt subset would permit false readiness without proving the
actual end-to-end Scan Plane. A closed manifest plus independently signed raw measurements makes
omission, substitution, retry erasure, cross-provider reuse, and percentile manipulation
detectable while keeping customer content and production authority out of the package.

**Rejected**: Starting T054 from a partial or repository-only T053 result; using Kubernetes rollout
as qualification evidence; uploading customer repositories; accepting caller p95/precision/
recall summaries; dropping failed attempts after retry; fewer than 30 runs; sharing sandboxes;
mutable candidate/baseline tags; one signer for provider/runtime/telemetry roles; retroactive plan
approval; caller-selected trust roots; unsigned artifact/provenance references; transferring T053
qualification to a different provider or adapter; aggregate-only artifact verification without
loading each signed envelope; local evaluation-time override; partial receipt success; and allowing
a T054 result to publish, deploy, or mark the system production ready.

## Decision 33: Make T055 Supply-Chain and Rollback Qualification Closed and Receipt-Recomputed

**Decision**: T055 is split into a deterministic repository contract and a later external drill
run. The repository fixes exactly 169 cells: four mount/digest/signature/provenance variants for
each of all 36 T054 artifacts, one unlisted-component rejection, six internal vulnerability-
database cases, three result-schema cases, and five ordered rollback phases for each of three
profiles. The manifest itself fixes 115 pre-execution rejections and 39 allowed single artifact
invocations.

Plan construction is cryptographically downstream of the exact T054 `PASSED` result and consumes
the same T054 manifest, dependency set, full artifact-verification set, and execution plan named by
that result. A Qualification Authority signature binds entry, T054 and T055 provider/adapter values
must match, and trust-bundle bytes must match independently configured
`SAST_T055_TRUST_POLICY_DIGEST`. Before any receipt is considered, every T054 artifact signature
and provenance envelope is loaded again, its digest and provenance relations are recomputed, and
its `SUPPLY_CHAIN_AUTHORITY` signature is reverified.

For each profile, Qualification Authority and Supply Chain Authority signatures authenticate the
durable rollback-ledger head digest, sequence, reference, provider, and exact candidate/baseline
release sets before the plan is approved. Security Engineering and Scan Platform approvals bind
those attestations and strictly predate the earliest submitted receipt or attempt. Supply Chain
Authority, MicroVM Provider, and Qualification Runtime independently sign each receipt, whose
identities and attestation/audit references are globally single-use. Positive artifacts mount
read-only and are rehashed; negative variants reject before invocation or egress. Rollback is an
ordered five-phase proof over exact candidate/baseline release-set digests: suspend, fence, abort and
clean in-flight work, derive and reverify last-known-good, then append an activation ledger entry
that references the authenticated head and uses exactly `head.sequence + 1`, moving only the
baseline from `STANDBY` to `ACTIVE`. No customer code, package install, build, dynamic test, public
egress, Kubernetes action, or production mutation is permitted.

**Rationale**: A signed T054 aggregate does not prove that deployment-time artifacts still match
their reviewed envelopes, an unlisted binary cannot run, vulnerability data remains internal and
fresh, result schemas reject drift, or rollback preserves fencing and audit history. A closed cell
set and receipt-recomputed result make omissions, substitutions, trust transfer, retroactive
approval, post-fence work, and ledger forgery independently detectable. A complete result advances
only to T056; it is not deployment or readiness authority.

**Rejected**: Starting from repository-only, partial, or cross-provider T054 evidence; letting the
submitted dependency set choose the trust root; trusting signature/provenance booleans without
loading envelopes; aggregate-only results; mutable tags; writable mounts; network enrichment;
unlisted executables; reused identities or attestations; approvals after execution; rollback to a
caller-selected target; activating before abort evidence or without an append-only chain; erasing
failed evidence; caller-selected verification time; synthetic CI receipts as external evidence;
and allowing T055 to publish, deploy Kubernetes, mutate production, or mark the system ready.

## Decision 34: Make T056 an Immutable Evidence-Recomputed Deployment Handoff

**Decision**: T056 is a deterministic repository contract plus later external evidence, not a
deployment command. Its reviewed package fixes 54 mandatory gates and six evidence categories:
34 exact upstream T054/T055 observations, six repository-assurance observations, five canary
telemetry observations, four kill-switch observations, three rollback-readiness observations, and
two deployment-boundary observations. No v1 gate accepts `NOT_APPLICABLE`, and no caller may submit
an overall verdict, aggregate metric object, or evaluation time.

Plan creation is cryptographically downstream of the exact same-provider T054/T055 chain and a
Qualification Authority entry attestation. Trust-bundle bytes are independently pinned by
`SAST_T056_TRUST_POLICY_DIGEST`. Each category attestation binds the candidate/baseline scanner
sets, profiles, T051/T052 corpus authority, T054/T055 measurement digests, repository commit,
evidence reference and validity window, and its required signer set. The verifier recomputes all
upstream values from signed results and evaluates the reviewed thresholds itself. Security
Engineering and Scan Platform then sign the exact plan within the bounded approval window.

**Rationale**: A passing upstream aggregate, green CI run, canary label, rollback assertion, or
operator-selected timestamp does not prove that the same immutable candidate has complete, fresh,
independently signed evidence at the deployment boundary. A closed gate catalog and digest-bound
record make omissions, stale evidence, favorable metric substitution, trust-root replacement,
`NOT_APPLICABLE` laundering, and authority widening independently detectable. A complete `GO`
authorizes only entry to the separate 005 deployment-operations workflow; it does not execute or
approve Kubernetes and does not establish production readiness.

**Rejected**: Starting from repository-only or partial T055 evidence; accepting caller aggregates
or clocks; using one signature for distinct authorities; omitting an evidence category or approval
while claiming `GO`; treating stale, malformed, unsigned, drifted, threshold-breaching, or
`NOT_APPLICABLE` evidence as pending; treating synthetic test fixtures as external evidence; and
allowing T056 to publish, mutate SCM/production, invoke AI, deploy Kubernetes, or mark the system
ready.
