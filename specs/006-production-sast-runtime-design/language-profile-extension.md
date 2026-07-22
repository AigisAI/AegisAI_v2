# Language Profile Extension Contract

## Purpose

Define the only supported path for adding language-specific SAST coverage after Java v1.
Adding a file extension or enabling generic OpenGrep rules does not constitute an approved
language profile. Until this contract is satisfied, the repository uses `COMMON_DEEP_V1` and
the product must not claim language-complete SAST coverage or AI eligibility.

## Required Proposal

Every new profile proposal includes:

- immutable profile ID and version, for example `<LANGUAGE>_FAST_V1` and
  `<LANGUAGE>_DEEP_V1`
- trusted detection signals and deterministic selection precedence for polyglot repositories
- authoritative SAST scanner and explicit capability ownership
- supported source extensions, manifest/lockfile names, IaC formats, generated/vendor/fixture
  classification, and unsupported constructs
- Fast changed-file context algorithm and Deep full-repository scope
- buildless analysis limitations, confidence effects, and user-visible coverage wording
- CPU, memory, disk, process, file-descriptor, file/count/path, artifact, finding, log, and
  wall-clock limits calibrated by representative corpora
- pinned scanner, wrapper, rules, database, schema, normalizer, SBOM format, and compatibility
  matrix
- normalizer mapping, stable-fingerprint anchors, correlation semantics, and rule migrations
- golden/malicious/parser/privacy/performance corpus revisions and rule owners
- rollback target, kill-switch namespace, staged rollout policy, and operational runbook

The profile object and digest become part of the canonical scan key. An existing profile is
never edited in place; behavior changes produce a new profile version.

## Profile Selection

Selection uses trusted repository inventory, not customer-supplied commands or arbitrary
environment variables.

1. Resolve repository binding, fixed commit, requested lane, and tenant policy.
2. Run bounded preflight inventory without executing repository content.
3. Score only approved signals: source bytes/file counts, manifests, and lockfiles.
4. Select every independently approved language profile needed by the future polyglot plan,
   or reject/defer if the orchestrator cannot preserve profile resource and coverage semantics.
5. Record ignored/unsupported languages and never relabel `COMMON_DEEP_V1` as SAST-complete.

For v1, one plan selects one profile. Polyglot multi-profile execution is a future contract:
it must define resource composition, finding identity, coverage aggregation, and failure
semantics before implementation. Silently choosing only the dominant language is prohibited.

## Scanner and Rule Admission

A language scanner is admitted only when it can run without customer build, package install,
dynamic execution, arbitrary plugins, or runtime internet enrichment. Required output is a
bounded machine-readable schema accepted by an explicit normalizer.

- Scanner image/binary and wrapper are signed, provenance verified, SBOM-associated, and
  digest pinned.
- Rules are platform-managed immutable bundles with semantic rule IDs.
- Build-dependent rules are excluded or labeled unsupported; they cannot silently lower
  confidence and still count as must-detect coverage.
- Scanner-local dependency, secret, or IaC rules that overlap Trivy are disabled or marked
  supporting-only.
- Scanner-local SBOM output cannot replace the authoritative Syft inventory without a new
  architecture decision and migration contract.

## Normalization and Identity Admission

Before a profile canary, the normalizer must define:

- every severity/confidence/unknown mapping and maximum field length
- path, line/column, symbol/function/class/module, source/sink, CWE, and remediation mapping
- secret-value and unsafe-markup redaction behavior
- stable `symbolAnchor`, `sinkKind`, and `structuralHash` derivation
- behavior for missing symbols, generated code, multi-location flows, and cross-file findings
- semantic rule migrations and expected fixed/reopen behavior
- authoritative versus supporting cross-tool correlation

Repeated identical artifacts must normalize byte-for-byte identically. Line, branch, and
commit-only changes must preserve finding identity, while a semantic rule change must not
accidentally inherit prior finding state.

## Required Corpus and Gates

The profile satisfies every gate in `quality-gates.md`, including:

- at least 200 positive and 200 negative cases for the affected language/profile
- at least 10 positive and 10 negative cases per changed rule, or 20 each for Critical/High
- 100% golden exact pass, prior must-detect recall, malicious controls, parser rejection,
  fingerprint fixtures, and coverage/publication fixtures
- at least 95% must-detect recall and 90% Critical/High precision
- at least 30 performance runs per size bucket, absolute Fast/Deep SLOs, no more than 20% p95
  regression, and no more than 2% scanner failure
- zero cross-tenant, secret, evidence, egress, unsigned-artifact, sandbox, cleanup, or stale
  publication violations

Language-specific malicious cases include parser ambiguities, generated code, unusual
encodings, pathological syntax trees, extremely large functions/modules, import graphs,
scanner crash inputs, and symbol/line churn.

## Promotion Flow

1. `EXPERIMENTAL`: development and offline corpus only; never tenant selectable.
2. `VALIDATED`: all corpus/supply-chain gates pass and compatibility is frozen.
3. `INTERNAL`: production-equivalent scans of platform-owned repositories.
4. `CANARY`: deterministic tenant-safe 1% -> 5% -> 25% cohorts under rule-governance gates.
5. `ACTIVE`: final 1,000-scan/48-hour evidence and two-person approval pass.
6. `DEPRECATED`: no new default selection; existing plans remain reproducible.
7. `RETIRED`: unavailable for new plans; historical metadata remains resolvable.

Any zero-tolerance event suspends the profile and denies complete coverage/external actions.
Rollback selects the last-known-good profile/scanner-set digests; it never mutates historical
plans or findings.

## Acceptance Checklist

- [ ] Profile ID/version and canonical-key behavior are immutable.
- [ ] Trusted detection and polyglot precedence are deterministic.
- [ ] Fast/Deep scope, claimed coverage, and unsupported behavior are explicit.
- [ ] No build, install, dynamic execution, arbitrary plugins, or runtime updates are needed.
- [ ] Scanner/rule/data/schema/normalizer supply chain is signed and pinned.
- [ ] Normalization, fingerprint, correlation, and migration fixtures are complete.
- [ ] Resource/artifact/log/time limits are measured and enforced outside scanner control.
- [ ] All correctness, security, privacy, performance, and sample-sufficiency gates pass.
- [ ] Canary, telemetry, kill switch, rollback, and on-call ownership are operational.
- [ ] UI/API/policy wording cannot overstate SAST coverage.
