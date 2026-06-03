# README Comprehensive Refresh Design

## Purpose

Refresh `README.md` into the repository's durable first-stop document for product
understanding, developer onboarding, and agent-safe execution. The README must make it
hard to start from the wrong milestone or accidentally imply unsupported production
runtime behavior.

## Audience

- Developers and implementation agents joining the repository
- Reviewers checking whether work follows the active production architecture baseline
- Operators looking for the current dev/demo deployment path
- Product or security readers who need a concise understanding of AegisAI's scope

## Source Order

README content follows this precedence:

1. `AGENTS.md`
2. `specs/002-production-scan-architecture/quickstart.md`
3. `C:\Users\권태욱\Desktop\Security Scan SaaS Final Specification.docx`
4. `specs/002-production-scan-architecture/`
5. `docs/github-conventions.md`
6. Legacy references: `specs/001-aegisai-mvp-foundation/` and `spec 2.2.md`

## Content Structure

The refreshed README will include:

- Product definition for AegisAI as a hosted security scan SaaS for GitHub Cloud and
  GitLab Cloud repositories.
- Current baseline section naming `002-production-scan-architecture` as the active
  implementation target and preserving `001-aegisai-mvp-foundation` as legacy.
- Architecture overview of the Control Plane, Scan Plane, AI Plane, and Data/Security
  Plane boundaries.
- Non-negotiable guardrails: no direct source upload, no customer code execution, no
  package install or repository build, no AI-authored authoritative findings, and
  separate user auth versus SCM integration credentials.
- Repository map for `apps/api`, `apps/web`, `packages/shared`, `specs`, `deploy`, and
  test support directories.
- Local development and validation commands based on existing `package.json` scripts and
  the quickstart validation path.
- Dev/demo deployment summary for Oracle VPS and Grafana Cloud observability, with clear
  language that this is not the production topology.
- GitHub workflow conventions and Spec Kit compatibility guidance.

## Constraints

- Do not claim real Opengrep, Trivy, Syft, sandbox, Kubernetes, policy engine, or AI
  inference runtime is implemented when the active milestone only provides skeletons and
  mock pipeline behavior.
- Keep Oracle VPS wording dev/demo only.
- Keep the DOCX production specification as the highest-priority product, platform,
  security, and operations baseline.
- Avoid replacing `quickstart.md`; README should point into it for execution order.
- Keep the document concise enough to be read end to end, while still complete enough to
  onboard a new contributor.

## Validation

Before completion:

- Confirm README points to `002-production-scan-architecture`.
- Confirm legacy MVP references remain available but lower precedence.
- Confirm Oracle VPS is described as dev/demo.
- Confirm validation commands match `quickstart.md`.
- Run a targeted README/doc consistency check by searching for stale `001` default
  language and production claims around Oracle VPS.
