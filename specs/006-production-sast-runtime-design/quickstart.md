# Quickstart: Production SAST Runtime Design

## Goal

Use this feature package as the canonical implementation entry point for the production
SAST runtime and rule-governance design. The source product and platform baseline remains
`Security Scan SaaS Final Specification.docx`.

This package follows the completed production deployment operations baseline in
[`specs/005-production-deployment-operations/`](../005-production-deployment-operations/).
It narrows the next implementation boundary to deterministic scanner execution, result
normalization, coverage, evidence, and rule lifecycle without weakening the completed
Control, Scan, AI, and Data/Security plane boundaries.

## Canonical Use

- Agents should arrive here from [`AGENTS.md`](../../AGENTS.md).
- This package is the active implementation target for production SAST runtime design.
- `005-production-deployment-operations` remains the completed deployment-operations
  baseline.
- `004-production-runtime-infrastructure` remains the completed runtime-infrastructure
  baseline.
- `003-production-ai-inference-runtime` remains the completed advisory-only AI baseline.
- `002-production-scan-architecture` remains the completed production scan architecture
  baseline.
- `001-aegisai-mvp-foundation` remains the legacy MVP baseline.

## Document Map

- `Security Scan SaaS Final Specification.docx`: highest-priority product, security, and
  operations specification
- `.specify/memory/constitution.md`: repository guardrails
- `spec.md`: SAST runtime scope, requirements, and acceptance
- `research.md`: scanner responsibility and design decisions
- `data-model.md`: runtime, artifact, finding, coverage, evidence, and rule entities
- `contracts/sast-runtime.md`: implementation-ready boundary and state contracts
- `threat-model.md`: hostile repository, scanner, artifact, and supply-chain threats
- `rule-governance.md`: rule bundle lifecycle, tenant policy, canary, rollback, and kill switch
- `quality-gates.md`: quantitative release and production readiness gates
- `language-profile-extension.md`: mandatory admission path for languages after Java v1
- `plan.md`: implementation sequencing and legacy-path retirement strategy
- `tasks.md`: execution-ordered design and future implementation slices
- `checklists/requirements.md`: design completeness checklist

## Required Read Order

1. `Security Scan SaaS Final Specification.docx`
2. `.specify/memory/constitution.md`
3. `specs/002-production-scan-architecture/quickstart.md`
4. `specs/002-production-scan-architecture/contracts/scan-architecture.md`
5. `specs/004-production-runtime-infrastructure/contracts/runtime-infrastructure.md`
6. `specs/005-production-deployment-operations/contracts/deployment-operations.md`
7. `specs/006-production-sast-runtime-design/spec.md`
8. `specs/006-production-sast-runtime-design/research.md`
9. `specs/006-production-sast-runtime-design/data-model.md`
10. `specs/006-production-sast-runtime-design/contracts/sast-runtime.md`
11. `specs/006-production-sast-runtime-design/threat-model.md`
12. `specs/006-production-sast-runtime-design/rule-governance.md`
13. `specs/006-production-sast-runtime-design/quality-gates.md`
14. `specs/006-production-sast-runtime-design/language-profile-extension.md`
15. `specs/006-production-sast-runtime-design/plan.md`
16. `specs/006-production-sast-runtime-design/tasks.md`
17. `specs/006-production-sast-runtime-design/checklists/requirements.md`

## Architecture Baseline

- OpenGrep is authoritative only for source-code SAST findings.
- Trivy is authoritative for dependency vulnerability, secret, and IaC
  misconfiguration findings.
- Syft is authoritative for source-workspace SBOM generation and does not create
  vulnerability findings.
- Every production scan runs in one non-reused ephemeral microVM with `HARDENED` or
  `RESTRICTED` isolation.
- Repository access is fixed-commit, repo-read only, short-lived, non-persisted, and
  issued through Token Broker.
- Scanner wrappers own tool-specific CLI details. Shared contracts own inputs, output
  schemas, provenance, limits, and failure behavior.
- Raw artifacts are hostile input. A result ingestor validates size, schema, digest,
  provenance, and tenant/scan attribution before normalization.
- Findings are deterministic and scanner-derived. AI receives only bounded, redacted,
  policy-classified evidence after coverage and normalization.
- Partial, stale, quarantined, or security-blocked scans cannot publish PR/MR comments or
  blocking results.

## SAST Profiles

- `JAVA_FAST_V1`: changed Java files plus bounded context, Java manifests, secrets, and
  dependency metadata; OpenGrep and Trivy required; 15-minute hard timeout.
- `JAVA_DEEP_V1`: full Java repository static analysis, dependency/secret/IaC coverage,
  and SBOM; OpenGrep, Trivy, and Syft required; 60-minute hard timeout.
- `COMMON_DEEP_V1`: dependency/secret/IaC and SBOM coverage for repositories without an
  approved language-specific SAST profile; Trivy and Syft required; AI advisory disabled.

Fast and Deep lanes use separate queues and budgets but the same microVM security boundary.

## Execution Flow

1. Validate the immutable scan request and canonical scan key.
2. Select a versioned SAST profile and signed scanner set.
3. Provision one ephemeral microVM and attest its workload identity.
4. Inject a short-lived fixed-commit repo-read credential without persistence or logging.
5. Fetch the repository, enforce path/resource policy, and reject unsafe input.
6. Run signed, digest-pinned scanner wrappers without package install, build, dynamic
   execution, or runtime internet enrichment.
7. Upload bounded artifact envelopes to the result ingestor and wipe the credential.
8. Validate, normalize, fingerprint, correlate, reduce evidence, and evaluate coverage.
9. Send normalized findings to policy and reduced evidence references to AI when eligible.
10. Wipe the workspace, destroy the microVM, and record destruction evidence.

## Deployment Position

Oracle VPS and Docker Compose remain dev/demo paths. Production SAST execution requires the
separated Scan Plane and stronger-than-pod isolation defined by 004 and 005. This design does
not authorize live provider execution or introduce provider credentials as local defaults.

## Spec Kit Compatibility

When working on GitHub-style branches, use:

```powershell
$env:SPECIFY_FEATURE = "006-production-sast-runtime-design"
```

## Completion Gate

Before claiming the 006 design milestone complete:

1. Re-run the validation commands below.
2. Confirm `AGENTS.md`, `README.md`, and `docs/github-conventions.md` point to 006.
3. Confirm 002 through 005 remain linked as completed baselines.
4. Confirm scanner responsibilities do not overlap without an explicit correlation rule.
5. Confirm no contract accepts customer code execution, package install, build, dynamic
   tests, direct source upload, SCM write authority, or AI full-repository access.
6. Confirm every rule bundle and scanner image requires digest, signature, provenance,
   staged rollout, rollback, and kill-switch references.
7. Confirm partial, stale, failed, quarantined, and security-blocked scans fail closed.
8. Confirm evidence cannot contain full files or exceed the seven-day retention boundary.
9. Confirm all quantitative quality and security gates are explicit and testable.
10. Confirm any language after Java follows `language-profile-extension.md` before the product
    claims SAST-complete coverage.

## Validation Commands

```powershell
corepack pnpm lint
corepack pnpm test
corepack pnpm typecheck
corepack pnpm build
corepack pnpm --filter @aegisai/api prisma:validate
node --test test/runtime/*.test.mjs
git diff --check
```
