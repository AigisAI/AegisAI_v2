# Quickstart: Production AI Inference Runtime

## Goal

Use this feature package as the canonical implementation entry point for the
trained production AI detector/planner inference runtime. The source product and
platform baseline remains `C:\Users\권태욱\Desktop\Security Scan SaaS Final Specification.docx`.

This package follows the completed production scan architecture baseline in
[`specs/002-production-scan-architecture/`](../002-production-scan-architecture/).
It narrows the remaining deferred work from 002 to production AI inference while
preserving the scanner-first pipeline, advisory-only AI boundary, and separated
Control, Scan, AI, and Data/Security planes.

## Canonical Use

- Agents should arrive here from [`AGENTS.md`](../../AGENTS.md).
- This package is the completed production AI detector/planner inference
  runtime baseline.
- `004-production-runtime-infrastructure` is the active follow-up package for
  Kubernetes AI Plane deployment and microVM scanner provisioning.
- `002-production-scan-architecture` remains the completed production scan
  architecture baseline.
- `001-aegisai-mvp-foundation` remains the legacy MVP baseline and historical
  implementation reference.

## Document Map

- `Security Scan SaaS Final Specification.docx`: highest-priority product,
  security, and operations specification
- `.specify/memory/constitution.md`: repository guardrails
- `specs/002-production-scan-architecture/`: completed production architecture
  baseline for scanner-first flows and plane separation
- `spec.md`: active AI inference runtime scope and acceptance criteria
- `research.md`: runtime decisions and rejected alternatives
- `data-model.md`: inference request, response, reduced evidence, and audit model
- `contracts/ai-inference-runtime.md`: shared AI inference runtime contracts
- `plan.md`: implementation approach and project structure
- `tasks.md`: execution-ordered milestone task list
- `checklists/requirements.md`: quality checklist

## Required Read Order

1. `C:\Users\권태욱\Desktop\Security Scan SaaS Final Specification.docx`
2. `.specify/memory/constitution.md`
3. `specs/002-production-scan-architecture/quickstart.md`
4. `specs/002-production-scan-architecture/contracts/scan-architecture.md`
5. `specs/003-production-ai-inference-runtime/spec.md`
6. `specs/003-production-ai-inference-runtime/research.md`
7. `specs/003-production-ai-inference-runtime/data-model.md`
8. `specs/003-production-ai-inference-runtime/contracts/ai-inference-runtime.md`
9. `specs/003-production-ai-inference-runtime/plan.md`
10. `specs/003-production-ai-inference-runtime/tasks.md`
11. `specs/003-production-ai-inference-runtime/checklists/requirements.md`

## Architecture Baseline

Production AI inference runs inside the AI Plane and only consumes reduced
evidence produced by the scanner-first pipeline. It is advisory-only:

- It MUST NOT create authoritative findings.
- It MUST NOT receive SCM credentials, repository archives, or full source trees.
- It MUST NOT override policy decisions or waiver/suppression state.
- It MAY return detector and planner advisories with confidence, rationale,
  recommended next actions, and model metadata.
- It MUST emit audit and observability signals without storing raw evidence
  beyond the declared retention boundary.

## Execution Flow

1. Re-baseline repository documentation to this feature package.
2. Add shared AI inference runtime contracts in `packages/shared`.
3. Add model gateway and fallback interfaces in `apps/ai`.
4. Add reduced evidence validation and rejection tests for forbidden payloads.
5. Add deterministic mock inference for local/dev execution.
6. Add production model provider wiring behind configuration and audit events.
7. Kubernetes/microVM production provisioning moved to
   `004-production-runtime-infrastructure`.

## Deployment Position

Oracle VPS and Docker Compose remain dev/demo paths. Production inference runtime
readiness is defined around the AI Plane running behind a model gateway with
tenant-aware audit, bounded reduced-evidence retention, and Kubernetes-compatible
deployment boundaries.

The Kubernetes-compatible deployment boundary is implemented in the follow-up
`004-production-runtime-infrastructure` package.

## Spec Kit Compatibility

When working on GitHub-style branches, use:

```powershell
$env:SPECIFY_FEATURE = "003-production-ai-inference-runtime"
```

## Completion Gate

Before claiming this milestone is complete:

1. Re-run the validation commands below.
2. Confirm this quickstart, `AGENTS.md`, `README.md`, and
   `docs/github-conventions.md` point to the currently active feature package.
3. Confirm `002-production-scan-architecture` remains available as the completed
   production scan architecture baseline.
4. Confirm `001-aegisai-mvp-foundation` remains available as the legacy MVP baseline.
5. Confirm AI remains advisory-only and never receives SCM credentials, full
   repositories, source archives, or raw scanner payloads.
6. Confirm Kubernetes AI Plane deployment and microVM scanner provisioning are
   tracked under `004-production-runtime-infrastructure`.

## Validation Commands

```powershell
corepack pnpm lint
corepack pnpm test
corepack pnpm typecheck
corepack pnpm build
corepack pnpm --filter @aegisai/api prisma:validate
git diff --check
```
