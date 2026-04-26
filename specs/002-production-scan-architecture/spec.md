# Feature Specification: Production Scan Architecture

**Feature ID**: `002-production-scan-architecture`  
**Status**: Active baseline  
**Primary Reference**: `C:\Users\권태욱\Desktop\Security Scan SaaS Final Specification.docx`

## Scope Alignment

- **Delivery Class**: Production architecture re-baseline, first implementation milestone
- **In Scope**: Documentation entrypoint migration, shared contracts, Prisma skeleton
  entities, and interface-level boundaries for Control, Scan, AI, and Data/Security planes
- **Out of Scope**: Real Opengrep/Trivy/Syft runtime execution, microVM/Kubernetes
  provisioning, private model inference, auto-fix PR/MR creation, customer code execution,
  package install/build, dynamic testing, GitHub Enterprise Server, self-managed GitLab,
  and customer-hosted scanners

## User Scenarios

### Story 1 - Architecture-Guided Agent Entry

As an implementation agent, I can start from the new quickstart and understand that the
DOCX production architecture is the highest-priority baseline.

**Acceptance**: `AGENTS.md`, `README.md`, and GitHub conventions point to
`002-production-scan-architecture`, while `001-aegisai-mvp-foundation` remains marked as
legacy.

### Story 2 - Scanner-First Contract Skeleton

As a backend implementer, I can use shared contracts for tenants, SCM integrations,
canonical scan identity, scan lanes, isolation classes, scanner runs, normalized findings,
evidence packs, policy decisions, waivers, suppressions, and audit events.

**Acceptance**: `packages/shared` exports those contract types plus small runtime helpers
for canonical scan key construction, evidence metadata, and isolation escalation.

### Story 3 - Tenant-Aware Persistence Skeleton

As a platform engineer, I can extend the database from MVP entities toward production
architecture entities without implementing scanner runtime behavior yet.

**Acceptance**: Prisma contains tenant-attributed skeleton models for integration,
repository binding, scan request, scanner run, normalized finding, evidence pack, policy
decision, waiver, suppression, and audit event.

## Functional Requirements

- **FR-001**: The DOCX specification MUST supersede `spec 2.2.md` for production scan
  architecture decisions.
- **FR-002**: `001-aegisai-mvp-foundation` MUST remain available as a legacy baseline.
- **FR-003**: GitHub Cloud integration MUST be modeled as GitHub App based.
- **FR-004**: GitLab Cloud integration MUST be modeled as project/group integration plus
  webhook based.
- **FR-005**: User login MUST remain separate from SCM repository access credentials.
- **FR-006**: SCM access MUST distinguish repo-read, comment-write, and integration-admin
  principals.
- **FR-007**: Scan identity MUST include tenant, repository binding, scan lane, target ref,
  fixed commit SHA, policy version, and scanner-set version.
- **FR-008**: The Scan Plane MUST be represented as deterministic scanner-first and scanner-first.
- **FR-009**: AI MUST be advisory-only and MUST NOT create authoritative findings, access
  SCM credentials, receive full repository input, or override policy decisions.
- **FR-010**: Evidence metadata MUST be tenant and scan scoped with explicit TTL.
- **FR-011**: Oracle VPS/Docker Compose deployment MUST be documented as dev/demo, not the
  production topology.

## Guardrails

- The system MUST NOT execute customer code.
- The system MUST NOT install packages or build customer repositories.
- The system MUST NOT persist full repository archives as long-lived data.
- The system MUST NOT expose raw scanner output as user-visible findings before
  normalization and policy evaluation.
- The system MUST NOT give Scan Plane comment-write or integration-admin authority.

## Success Criteria

- Validation commands in `quickstart.md` pass.
- The shared package can be imported by backend and frontend workspaces.
- Prisma validates with the new skeleton models.
- Static contract tests prove AI and Token Broker request shapes avoid credential values
  and full repository payloads.
