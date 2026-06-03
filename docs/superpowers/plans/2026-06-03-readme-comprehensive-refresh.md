# README Comprehensive Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current lightweight README with a durable product, architecture,
developer onboarding, validation, and dev/demo deployment guide for AegisAI.

**Architecture:** Keep `README.md` as the first public-facing summary while preserving
`AGENTS.md` and `specs/002-production-scan-architecture/quickstart.md` as the execution
entrypoints. The README should summarize scope and commands, then link to the canonical
docs for deeper implementation order.

**Tech Stack:** Markdown documentation for a pnpm workspace using Node.js, NestJS, React,
TypeScript, Prisma, GitHub Actions, Oracle VPS dev/demo deployment, and Grafana Cloud
observability.

---

### Task 1: Replace README With Comprehensive Structure

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace README sections**

Use the following section order:

```markdown
# AegisAI

## What This Is
## Current Baseline
## Architecture At A Glance
## Non-Negotiable Guardrails
## Repository Map
## Start Here
## Local Development
## Validation
## Deployment Position
## GitHub Workflow
## Documentation Precedence
## Legacy Baseline
```

- [ ] **Step 2: Preserve canonical links**

The README must link to:

```text
AGENTS.md
specs/002-production-scan-architecture/quickstart.md
specs/002-production-scan-architecture/
docs/github-conventions.md
deploy/oracle/BOOTSTRAP.md
specs/001-aegisai-mvp-foundation/
spec 2.2.md
```

- [ ] **Step 3: Include exact validation commands**

The validation section must list:

```powershell
corepack pnpm lint
corepack pnpm test
corepack pnpm typecheck
corepack pnpm build
corepack pnpm --filter @aegisai/api prisma:validate
```

### Task 2: Run Documentation Consistency Checks

**Files:**
- Verify: `README.md`

- [ ] **Step 1: Check active feature references**

Run:

```powershell
Select-String -Path 'README.md' -Pattern '002-production-scan-architecture'
```

Expected: at least three matches across current baseline, start path, and documentation
precedence sections.

- [ ] **Step 2: Check legacy language is not default**

Run:

```powershell
Select-String -Path 'README.md' -Pattern 'agent-first MVP baseline|default implementation target.*001|Oracle.*production topology'
```

Expected: no matches.

- [ ] **Step 3: Check Oracle VPS is dev/demo only**

Run:

```powershell
Select-String -Path 'README.md' -Pattern 'dev/demo|not the production topology|Oracle VPS'
```

Expected: matches showing Oracle VPS is retained only for dev/demo deployment.

### Task 3: Run Lightweight Markdown Review

**Files:**
- Verify: `README.md`

- [ ] **Step 1: Inspect rendered Markdown structure in plain text**

Run:

```powershell
Get-Content -Raw 'README.md'
```

Expected: headings are ordered, links are readable, commands are copyable, and no section
claims deferred scanner, sandbox, policy engine, Kubernetes, or AI runtime implementation.

- [ ] **Step 2: Review git diff**

Run:

```powershell
git diff -- README.md docs/superpowers/specs/2026-06-03-readme-comprehensive-refresh-design.md docs/superpowers/plans/2026-06-03-readme-comprehensive-refresh.md
```

Expected: only the README refresh and supporting Superpowers design/plan documents appear
in this task's diff.
