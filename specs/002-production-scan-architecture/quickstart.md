# Quickstart: Production Scan Architecture

## Goal

Production implementation now continues in the narrower
[`003-production-runtime`](../003-production-runtime/quickstart.md) package,
authorized on 2026-11-07. Read this baseline first, then follow that package for
runtime changes. Its release gates supersede this skeleton milestone's completion.

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
5. Harden the skeleton with session-derived tenant context, CSRF and throttling, internal
   service authentication, bounded TTLs, deployable migrations, and clean-build smoke tests.
6. Add bounded repository path metadata classification for Java detailed and common-only
   mock scan profiles, preserving requests without a manifest and narrowing AI contracts
   to Java detailed findings with redacted evidence metadata.
7. Keep real Opengrep/Trivy/Syft execution, microVM/Kubernetes provisioning, and model
   inference for later implementation packages.

## Deployment Position

Oracle VPS and its legacy Docker Compose deployment remain dev/demo only.
The baseline production target separates Control, Scan, AI and Data/Security planes
on Kubernetes or equivalent isolation. The narrower 003 package records the user's
explicit single-EC2 private deployment deviation; it uses app Compose plus independent
containerd/gVisor and does not certify separate-node/general-service compliance.
Current facts and evidence are indexed in [production docs](../../docs/production/README.md).

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
node --test test/runtime/*.test.mjs
```

CI additionally applies every Prisma migration to a clean PostgreSQL 16 service before the
build is accepted.

For documentation-only maintenance, validate links, factual claims against existing
evidence and the changed-file scope. Do not repeat code suites or live scans/restores
when implementation has not changed. This exception does not relax code release gates.
