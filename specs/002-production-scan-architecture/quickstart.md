# Quickstart: Production Scan Architecture

## Goal

Use this feature package as the canonical implementation entry point for the
production-grade Security Scan SaaS architecture. The source product and platform baseline
is `C:\Users\권태욱\Desktop\Security Scan SaaS Final Specification.docx`.

## Canonical Use

- Agents should arrive here from [`AGENTS.md`](../../AGENTS.md).
- This package supersedes `001-aegisai-mvp-foundation` for new architecture work.
- `001-aegisai-mvp-foundation` remains available as the legacy MVP baseline and historical
  implementation reference.

## Document Map

- `Security Scan SaaS Final Specification.docx`: highest-priority product, security, and
  operations specification
- `.specify/memory/constitution.md`: repository guardrails
- `spec 2.2.md`: legacy product baseline, now lower precedence than the DOCX
- `spec.md`: active product scope and acceptance criteria for this milestone
- `research.md`: architecture decisions and rejected alternatives
- `data-model.md`: production scan architecture entities and state transitions
- `contracts/scan-architecture.md`: shared contracts and boundary definitions
- `plan.md`: implementation approach and project structure
- `tasks.md`: execution-ordered milestone task list
- `checklists/requirements.md`: quality checklist

## Required Read Order

1. `C:\Users\권태욱\Desktop\Security Scan SaaS Final Specification.docx`
2. `.specify/memory/constitution.md`
3. `specs/002-production-scan-architecture/spec.md`
4. `specs/002-production-scan-architecture/research.md`
5. `specs/002-production-scan-architecture/data-model.md`
6. `specs/002-production-scan-architecture/contracts/scan-architecture.md`
7. `specs/002-production-scan-architecture/plan.md`
8. `specs/002-production-scan-architecture/tasks.md`
9. `specs/002-production-scan-architecture/checklists/requirements.md`

## Architecture Baseline

Production is modeled as four separated trust boundaries:

- Control Plane: tenant, integration, webhook, scan planning, token broker, policy, comment
  dispatch, and dashboard APIs
- Scan Plane: ephemeral sandbox provisioning, repository fetch, Opengrep/Trivy/Syft adapter
  execution, normalization, correlation, and evidence pack construction
- AI Plane: advisory-only detector/planner interaction over reduced evidence; no direct SCM
  access, no full repository input, and no policy override authority
- Data and Security Plane: tenant-aware persistence, object storage with TTL, audit logs,
  KMS, and secrets manager boundaries

## Execution Flow

1. Re-baseline repository documentation to this feature package.
2. Add shared architecture contracts in `packages/shared`.
3. Extend Prisma with tenant-attributed skeleton entities for integrations, scan requests,
   scanner runs, findings, evidence, policy decisions, waivers, suppressions, and audits.
4. Add interface-level backend tests for Token Broker, Scan Plane, AI advisory, evidence,
   and policy boundaries.
5. Add the first standalone `apps/ai` detector/planner service skeleton for reduced
   advisory-only model runtime calls.
6. Keep real Opengrep/Trivy/Syft execution, microVM/Kubernetes provisioning, and trained
   model inference for later implementation packages.

## Deployment Position

Oracle VPS and Docker Compose deployment files remain supported for dev/demo operation.
They are not the production target for this architecture. Production readiness is defined
around separated Control, Scan, AI, and Data/Security planes on Kubernetes or equivalent
isolation.

## Spec Kit Compatibility

When working on GitHub-style branches, use:

```powershell
$env:SPECIFY_FEATURE = "002-production-scan-architecture"
```

## Completion Gate

Before claiming this milestone is complete:

1. Re-run the validation commands below.
2. Confirm this quickstart, `AGENTS.md`, `README.md`, and `docs/github-conventions.md`
   all point to `002-production-scan-architecture`.
3. Confirm Oracle VPS wording is dev/demo only.
4. Confirm `001-aegisai-mvp-foundation` remains available as the legacy MVP baseline.

## Validation Commands

```powershell
corepack pnpm lint
corepack pnpm test
corepack pnpm typecheck
corepack pnpm build
corepack pnpm --filter @aegisai/api prisma:validate
```
