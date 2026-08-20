# Quickstart: Production Deployment Operations

## Goal

Use this completed feature package as the canonical baseline whenever live
production deployment operations resume. The repository-wide active implementation
entry point is now `specs/006-production-sast-runtime-design/quickstart.md`. The source
product and platform baseline remains `Security Scan SaaS Final Specification.docx`.

This package follows the completed production runtime infrastructure baseline in
[`specs/004-production-runtime-infrastructure/`](../004-production-runtime-infrastructure/).
It moves live production Kubernetes cluster provisioning and provider-specific
microVM platform rollout out of the 004 Deferred list and into an explicit
operations package with no local development defaults for provider credentials.

## Canonical Use

- Agents should arrive at the active 006 package from [`AGENTS.md`](../../AGENTS.md).
- This package is the completed provider-neutral contract baseline for production
  deployment operations; live provider execution remains deferred.
- Its preflight now consumes only a fresh Qualification Authority Ed25519
  attestation over an exact T056 `GO`. The derived binding fixes the T056 record,
  plan, repository commit, provider/adapter, rollback, kill-switch evidence, and
  current 005 contract revision without granting live-operation authority.
- `006-production-sast-runtime-design` is the active detailed SAST follow-up that must
  complete before live scanner rollout.
- `004-production-runtime-infrastructure` remains the completed runtime
  infrastructure baseline.
- `003-production-ai-inference-runtime` remains the completed production AI
  inference baseline.
- `002-production-scan-architecture` remains the completed production scan
  architecture baseline.
- `001-aegisai-mvp-foundation` remains the legacy MVP baseline and historical
  implementation reference.

## Document Map

- `Security Scan SaaS Final Specification.docx`: highest-priority product,
  security, and operations specification
- `.specify/memory/constitution.md`: repository guardrails
- `specs/004-production-runtime-infrastructure/`: completed runtime
  infrastructure baseline
- `specs/003-production-ai-inference-runtime/`: completed AI runtime baseline
- `specs/002-production-scan-architecture/`: completed production architecture
  baseline for scanner-first flows and plane separation
- `spec.md`: active deployment operations scope and acceptance criteria
- `research.md`: deployment operations decisions and rejected alternatives
- `data-model.md`: cluster, microVM rollout, credential boundary, and audit model
- `contracts/deployment-operations.md`: deployment operations contracts
- `plan.md`: implementation approach and project structure
- `tasks.md`: execution-ordered milestone task list
- `checklists/requirements.md`: quality checklist

## Required Read Order

1. `Security Scan SaaS Final Specification.docx`
2. `.specify/memory/constitution.md`
3. `specs/002-production-scan-architecture/quickstart.md`
4. `specs/002-production-scan-architecture/contracts/scan-architecture.md`
5. `specs/003-production-ai-inference-runtime/quickstart.md`
6. `specs/003-production-ai-inference-runtime/contracts/ai-inference-runtime.md`
7. `specs/004-production-runtime-infrastructure/quickstart.md`
8. `specs/004-production-runtime-infrastructure/contracts/runtime-infrastructure.md`
9. `specs/005-production-deployment-operations/spec.md`
10. `specs/005-production-deployment-operations/research.md`
11. `specs/005-production-deployment-operations/data-model.md`
12. `specs/005-production-deployment-operations/contracts/deployment-operations.md`
13. `specs/005-production-deployment-operations/plan.md`
14. `specs/005-production-deployment-operations/tasks.md`
15. `specs/005-production-deployment-operations/checklists/requirements.md`

## Architecture Baseline

Production deployment operations prepare live infrastructure without weakening
the completed plane boundaries:

- live production Kubernetes cluster provisioning MUST keep Control, Scan, AI,
  and Data/Security plane separation.
- Provider-specific microVM platform rollout MUST preserve stronger-than-pod
  scanner isolation.
- Provider credentials MUST NOT be committed, mirrored into examples, or added as
  local development defaults.
- AI Plane deployment MUST remain advisory-only and MUST NOT receive SCM
  credentials, full repositories, source archives, or raw scanner payloads.
- Scanner sandboxes MUST NOT install packages, build customer repositories, run
  dynamic tests, add direct source upload, or create auto-fix PR/MR flows.
- Preflight and handoff MUST fail closed without the exact current-contract T056
  `GO`, its valid short-lived Qualification Authority signature, and trusted UTC.
- Passing preflight or handoff MUST NOT execute Kubernetes, call a provider,
  mutate production, or establish production readiness.

## Execution Flow

1. Re-baseline repository documentation to this feature package.
2. Add deployment operations contracts and data model docs.
3. Add provider-neutral cluster provisioning inputs and validation tests.
4. Add provider-neutral microVM rollout inputs and validation tests.
5. Keep provider credential use as explicit deployment operation input, not local
   development defaults.
6. Verify the exact T056 `GO` and short-lived Qualification Authority entry
   signature, then reconstruct one immutable deployment qualification binding.
7. Validate the binding, three credential boundaries, three operator approvals,
   plane separation, audit signal, resource references, and bounded handoff.
8. Stop before provider credentials, Kubernetes access, provider APIs, or any
   real production mutation are required.

## Deployment Position

Oracle VPS and Docker Compose remain dev/demo paths. Production readiness is
defined around Kubernetes-compatible Control, Scan, AI, and Data/Security plane
boundaries with provider-specific microVM scan isolation configured through
explicit operations inputs.

## Spec Kit Compatibility

When working on GitHub-style branches, use:

```powershell
$env:SPECIFY_FEATURE = "005-production-deployment-operations"
```

## Completion Gate

The non-deferred 005 contract milestone is complete. When revalidating it:

1. Re-run the validation commands below.
2. Confirm this quickstart records the handoff and `AGENTS.md`, `README.md`, and
   `docs/github-conventions.md` point to `006-production-sast-runtime-design`.
3. Confirm `004-production-runtime-infrastructure` remains available as the
   completed runtime infrastructure baseline.
4. Confirm `003-production-ai-inference-runtime` remains available as the
   completed production AI inference baseline.
5. Confirm `002-production-scan-architecture` remains available as the completed
   production scan architecture baseline.
6. Confirm `001-aegisai-mvp-foundation` remains available as the legacy MVP baseline.
7. Confirm provider credentials are not introduced as local development defaults.
8. Confirm preflight has no evidence-free validation path; only a fresh signed
   T056 `GO` bound to the current 005 contract can produce its qualification binding.
9. Confirm signature, expiry, provider/adapter, repository commit, approval,
   rollback, unknown-field, and authority-widening drift all fail closed.
10. Confirm live production Kubernetes cluster provisioning and provider-specific
   microVM platform rollout preserve the completed plane boundaries.
11. Confirm repository validation grants no deployment, Kubernetes execution,
    provider/production mutation, or production-readiness authority.

## Validation Commands

```powershell
corepack pnpm lint
corepack pnpm test
corepack pnpm typecheck
corepack pnpm build
corepack pnpm qualification:validate
corepack pnpm --filter @aegisai/api prisma:validate
git diff --check
```
