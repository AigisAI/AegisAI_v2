# Research: Production Scan Architecture

## Decision 1: Use the DOCX as the production architecture source of truth

- **Decision**: `Security Scan SaaS Final Specification.docx` supersedes `spec 2.2.md` for
  new production scan architecture work.
- **Rationale**: The DOCX contains the stronger multi-tenant security model: trust-boundary
  separation, ephemeral scan isolation, policy-as-code decisions, evidence TTL, auditability,
  and deterministic scanner-first behavior.
- **Rejected**: Updating `001-aegisai-mvp-foundation` in place. That would blur the legacy
  MVP baseline and the production-grade direction.

## Decision 2: Split user auth from SCM integration credentials

- **Decision**: Keep browser user authentication separate from GitHub App / GitLab Cloud
  integration credentials.
- **Rationale**: The DOCX requires repo-read, comment-write, and integration-admin principal
  separation. User OAuth tokens are not the right long-term repository access primitive.
- **Rejected**: Preserving OAuth repository access as the default path.

## Decision 3: Model scanner-first pipeline before implementing scanner runtime

- **Decision**: Add contracts and persistence for scanner runs, normalization, findings,
  evidence, policy decisions, and audits before adding Opengrep/Trivy/Syft execution.
- **Rationale**: The current codebase is still scaffold-level. Boundary-first integration
  gives future scanner work a safe target without prematurely introducing sandbox runtime
  complexity.
- **Rejected**: Implementing scanner binaries in the first milestone.

## Decision 4: Keep AI advisory-only

- **Decision**: AI contracts accept normalized findings and reduced, redacted evidence only.
- **Rationale**: The DOCX explicitly states that AI is not the authoritative finding or
  policy decision maker.
- **Rejected**: Feeding full repository contents or raw SCM data into AI.

## Decision 5: Reclassify Oracle VPS as dev/demo

- **Decision**: Existing Oracle VPS deployment assets remain useful but are no longer the
  production reference architecture.
- **Rationale**: Production requires separated Control, Scan, AI, and Data/Security planes
  with stronger-than-pod scan isolation.
- **Rejected**: Treating the current Docker Compose path as production v1.

## Decision 6: Add Java-first detailed scan planning before broader language profiles

- **Decision**: The next scan planning increment should add Java as the first detailed
  SAST profile while keeping other detected languages on common scanner coverage only.
- **Rationale**: The legacy MVP baseline is Java-first, and the DOCX v1 scanner set is
  Opengrep, Trivy, and Syft. Java-first planning provides a narrow production-aligned
  path without adding unapproved scanners or customer build execution.
- **Rejected**: Sending Java code to the AI Plane. AI receives only normalized findings,
  reduced redacted evidence, language metadata, and scan profile metadata.
- **Rejected**: Adding language-specific SAST routing for every detected language in the
  first increment. Non-Java languages should be detected for future expansion but should
  remain common-only until their own profiles are specified.
