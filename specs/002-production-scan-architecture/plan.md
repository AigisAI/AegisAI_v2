# Implementation Plan: Production Scan Architecture

**Feature ID**: `002-production-scan-architecture`  
**Spec**: `specs/002-production-scan-architecture/spec.md`

## Summary

Re-baseline AegisAI around the DOCX production security scan architecture while preserving
the existing MVP package as legacy. The first implementation milestone adds documentation,
shared contracts, Prisma skeleton entities, and tests that enforce the new trust boundaries.

## Technical Context

- TypeScript contracts remain in `packages/shared`.
- NestJS backend and React frontend continue to import shared contracts.
- Prisma remains the persistence schema source for application data.
- Scanner runtime, sandbox runtime, and AI inference are deferred.
- The metadata increment adds language-aware scan planning: Java receives
  the first detailed SAST profile, while non-Java languages continue through common
  scanner coverage only.

## Project Structure

```text
specs/002-production-scan-architecture/
  quickstart.md
  spec.md
  research.md
  data-model.md
  contracts/scan-architecture.md
  plan.md
  tasks.md
  checklists/requirements.md
packages/shared/src/
apps/api/prisma/schema.prisma
test/github-actions/
apps/api/test/architecture/
```

## Implementation Strategy

### Constitution compatibility

For this package, the DOCX and `AGENTS.md` supersede the constitution's legacy MVP
defaults for backend repository collection and AI-led analysis. Repository processing
belongs to the Scan Plane; AI receives reduced evidence for advisory use only. This
intentional departure preserves the constitution's shared contracts, Java-first scope,
authentication, tenant isolation, and validation guardrails. Phase 8 extends metadata
contracts and the existing mock boundary only; scanner execution remains deferred.

1. Add failing tests for active feature entrypoint, shared contracts, and Prisma skeleton.
2. Create the new feature package and update repo entrypoints.
3. Add shared production architecture contracts.
4. Extend Prisma with tenant-attributed skeleton entities.
5. Run lint, tests, typecheck, build, and Prisma validation.

## Java-First SAST Pipeline Metadata

This slice adds Java-first scan planning without implementing real scanner execution.
It classifies repository manifest metadata by path and manifest name only, then chooses
one of two scan profiles:

- `JAVA_DETAILED`: selected when Java files or Java build manifests are present.
- `COMMON`: selected when only non-Java languages or common surfaces are detected.

Java detailed scans should keep Opengrep, Trivy, and Syft as the approved v1 scanner set.
Java normalized findings remain Scan Plane outputs created from deterministic scanner
provenance. AI Plane work is limited to advisory metadata for Java detailed normalized
findings and reduced, redacted evidence. The AI Plane must not receive full Java files,
full repositories, raw unbounded scanner payloads, SCM credentials, or policy override
authority.

Non-Java languages should be detected for future routing but should not receive
language-specific SAST behavior in this slice. They continue through common scanner
coverage only and should not be marked eligible for Java-only AI advisory.

## Architecture Notes

- The default future path is a scanner-first pipeline and deterministic-first.
- Java is the first detailed language profile; other languages remain common-only until
  their own SAST profiles are specified.
- Token Broker is the future credential boundary for short-lived scan-scoped SCM access.
- Policy-as-code is the future decision boundary for dashboard, comment, warning, ticket,
  and block behavior.
- AI is advisory-only, receives reduced evidence, and its contract is eligible only
  for Java detailed normalized findings.
- Oracle VPS deployment is dev/demo only.
- Production topology assumes separated Control, Scan, AI, and Data/Security planes.
