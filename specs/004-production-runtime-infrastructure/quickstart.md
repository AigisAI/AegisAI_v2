# Quickstart: Production Runtime Infrastructure

## Goal

Use this feature package as the canonical implementation entry point for the
production runtime infrastructure milestone. The source product and platform
baseline remains `C:\Users\권태욱\Desktop\Security Scan SaaS Final Specification.docx`.

This package follows the completed production AI inference baseline in
[`specs/003-production-ai-inference-runtime/`](../003-production-ai-inference-runtime/)
and the completed production scan architecture baseline in
[`specs/002-production-scan-architecture/`](../002-production-scan-architecture/).
It reclassifies the deferred Kubernetes and microVM infrastructure work into an
implementation-ready package while preserving the scanner-first pipeline,
advisory-only AI boundary, and separated Control, Scan, AI, and Data/Security
planes.

`005-production-deployment-operations` is the active follow-up package for live
production Kubernetes cluster provisioning and provider-specific microVM platform
rollout.

## Canonical Use

- Agents should arrive here from [`AGENTS.md`](../../AGENTS.md).
- This package is the completed implementation baseline for production runtime
  infrastructure work before `005-production-deployment-operations`.
- `005-production-deployment-operations` is the active follow-up package for
  production deployment operations.
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
- `specs/003-production-ai-inference-runtime/`: completed AI runtime baseline
- `specs/002-production-scan-architecture/`: completed production architecture
  baseline for scanner-first flows and plane separation
- `spec.md`: active infrastructure scope and acceptance criteria
- `research.md`: infrastructure decisions and rejected alternatives
- `data-model.md`: deployment, autoscaling, and sandbox model
- `contracts/runtime-infrastructure.md`: runtime infrastructure contracts
- `plan.md`: implementation approach and project structure
- `tasks.md`: execution-ordered milestone task list
- `checklists/requirements.md`: quality checklist

## Required Read Order

1. `C:\Users\권태욱\Desktop\Security Scan SaaS Final Specification.docx`
2. `.specify/memory/constitution.md`
3. `specs/002-production-scan-architecture/quickstart.md`
4. `specs/002-production-scan-architecture/contracts/scan-architecture.md`
5. `specs/003-production-ai-inference-runtime/quickstart.md`
6. `specs/003-production-ai-inference-runtime/contracts/ai-inference-runtime.md`
7. `specs/004-production-runtime-infrastructure/spec.md`
8. `specs/004-production-runtime-infrastructure/research.md`
9. `specs/004-production-runtime-infrastructure/data-model.md`
10. `specs/004-production-runtime-infrastructure/contracts/runtime-infrastructure.md`
11. `specs/004-production-runtime-infrastructure/plan.md`
12. `specs/004-production-runtime-infrastructure/tasks.md`
13. `specs/004-production-runtime-infrastructure/checklists/requirements.md`

## Architecture Baseline

Production runtime infrastructure separates deployable planes and hardens scan
execution:

- Kubernetes production AI Plane deployment MUST preserve advisory-only AI.
- AI Plane pods MUST NOT receive SCM credentials, full repositories, source
  archives, or raw scanner payloads.
- Runtime autoscaling MUST be described around request latency, queue pressure,
  provider health, and tenant-aware audit signals.
- microVM-backed scanner provisioning MUST isolate customer repository fetch and
  scanner execution from the Control Plane and AI Plane.
- Scanner sandboxes MUST NOT install packages, build customer repositories, run
  dynamic tests, or add direct source upload.

## Execution Flow

1. Re-baseline repository documentation to this feature package.
2. Add runtime infrastructure contracts and data model docs.
3. Add Kubernetes AI Plane manifest skeletons and tests.
4. Add runtime autoscaling policy skeletons and tests.
5. Add scanner sandbox provisioning contracts for microVM-backed execution.
6. Keep provider-specific cluster credentials and production cluster rollout for
   explicit deployment operations, not local development defaults.

## Deployment Position

Oracle VPS and Docker Compose remain dev/demo paths. Production readiness is
defined around Kubernetes-compatible Control, Scan, AI, and Data/Security plane
boundaries with stronger-than-pod scan isolation.

## Spec Kit Compatibility

When working on GitHub-style branches, use:

```powershell
$env:SPECIFY_FEATURE = "004-production-runtime-infrastructure"
```

## Completion Gate

Before claiming this milestone is complete:

1. Re-run the validation commands below.
2. Confirm this quickstart, `AGENTS.md`, `README.md`, and
   `docs/github-conventions.md` all point to `004-production-runtime-infrastructure`.
3. Confirm `003-production-ai-inference-runtime` remains available as the
   completed production AI inference baseline.
4. Confirm `002-production-scan-architecture` remains available as the completed
   production scan architecture baseline.
5. Confirm `001-aegisai-mvp-foundation` remains available as the legacy MVP baseline.
6. Confirm Kubernetes AI Plane deployment preserves advisory-only AI boundaries.
7. Confirm scanner sandbox provisioning does not permit package install/build,
   dynamic testing, direct source upload, or AI access to full repositories.

## Validation Commands

```powershell
corepack pnpm lint
corepack pnpm test
corepack pnpm typecheck
corepack pnpm build
corepack pnpm --filter @aegisai/api prisma:validate
git diff --check
```
