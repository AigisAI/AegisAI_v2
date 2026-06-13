# AegisAI UML Diagram Set Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce four English, report-ready UML 2.x diagrams that describe the AegisAI target production system and render each PlantUML source as a high-resolution PNG.

**Architecture:** Each diagram is a focused PlantUML source under `docs/reports/uml`. Shared names, plane colors, security constraints, and target deployment boundaries follow the approved UML design and the active `005-production-deployment-operations` baseline. PlantUML compilation and image inspection provide syntax and visual verification.

**Tech Stack:** PlantUML, Java 23, Graphviz-compatible PlantUML layout, PNG rendering, PowerShell verification

---

## File Structure

- Create `docs/reports/uml/aegisai-use-case.puml`: actors, system boundary, use cases, and UML include/extend relationships.
- Create `docs/reports/uml/aegisai-component.puml`: four trust-plane packages, interfaces, external systems, and component dependencies.
- Create `docs/reports/uml/aegisai-scan-sequence.puml`: end-to-end scan execution with duplicate, isolation, AI fallback, and policy branches.
- Create `docs/reports/uml/aegisai-production-deployment.puml`: production Kubernetes nodes, hardened microVM isolation, managed security services, and network constraints.
- Generate matching `.png` files beside each source.

### Task 1: Use Case Diagram

**Files:**
- Create: `docs/reports/uml/aegisai-use-case.puml`
- Generate: `docs/reports/uml/aegisai-use-case.png`

- [ ] **Step 1: Create the UML system boundary and actors**

Define `Tenant Administrator`, `Security Engineer`, `Deployment Operator`, and
`GitHub Cloud / GitLab Cloud` as actors around an `AegisAI Security Scan SaaS`
rectangle.

- [ ] **Step 2: Add report-level use cases and relationships**

Use standard `<<include>>` and `<<extend>>` dependencies for repository
validation, deterministic scanning, advisory AI analysis, policy evaluation,
deployment preflight, handoff approval, and production provisioning.

- [ ] **Step 3: Compile and inspect**

Run:

```powershell
java -jar $env:PLANTUML_JAR -tpng -charset UTF-8 docs/reports/uml/aegisai-use-case.puml
```

Expected: exit code 0 and a non-empty landscape PNG with no overlapping labels.

### Task 2: Component Diagram

**Files:**
- Create: `docs/reports/uml/aegisai-component.puml`
- Generate: `docs/reports/uml/aegisai-component.png`

- [ ] **Step 1: Model components inside four packages**

Use UML components grouped into `Control Plane`, `Scan Plane`, `AI Plane`, and
`Data & Security Plane`. Add `Web Dashboard`, users, and SCM providers as
external elements.

- [ ] **Step 2: Connect declared interfaces**

Show scan planning, short-lived credential references, queued scan work,
normalized findings, reduced evidence, advisory output, policy-gated
publication, storage, and audit dependencies.

- [ ] **Step 3: Add security notes**

Explicitly state that the AI Plane is advisory-only, receives no SCM
credentials/full repository/raw scanner payload, and cannot override policy.

- [ ] **Step 4: Compile and inspect**

Run the PlantUML PNG command and confirm package boundaries and connector labels
remain readable at A4 landscape scale.

### Task 3: Scan Execution Sequence Diagram

**Files:**
- Create: `docs/reports/uml/aegisai-scan-sequence.puml`
- Generate: `docs/reports/uml/aegisai-scan-sequence.png`

- [ ] **Step 1: Add lifelines and the successful scan flow**

Model scan request validation, canonical scan key creation, queueing, ephemeral
sandbox provisioning, short-lived credential issuance, fixed-commit fetch,
Opengrep/Trivy/Syft execution, normalization, evidence reduction, advisory AI
review, policy evaluation, persistence, audit, and result retrieval.

- [ ] **Step 2: Add alternative flows**

Use `alt`, `else`, and `opt` fragments for duplicate active scans, sandbox
failure, Java AI eligibility, AI unavailability, and blocked publication.

- [ ] **Step 3: Compile and inspect**

Render the image and confirm all messages read top-to-bottom without crossed or
ambiguous flows.

### Task 4: Production Deployment Diagram

**Files:**
- Create: `docs/reports/uml/aegisai-production-deployment.puml`
- Generate: `docs/reports/uml/aegisai-production-deployment.png`

- [ ] **Step 1: Model physical and execution nodes**

Create a production Kubernetes environment containing separate Control, Scan,
AI, and Data & Security namespaces. Place an ephemeral scanner microVM within a
provider-specific hardened microVM platform connected to the Scan Plane.

- [ ] **Step 2: Model managed services and communication paths**

Add managed database, object storage with TTL, queue/event bus, KMS, external
secret manager or OIDC federation, audit sink, and rule/vulnerability mirrors.
Label protocols and private boundaries where useful.

- [ ] **Step 3: Add deployment constraints**

Use UML notes for stronger-than-pod isolation, provider-neutral cluster
provisioning, provider-specific microVM rollout, reference-only credential
handoff, and lack of AI-to-SCM connectivity.

- [ ] **Step 4: Compile and inspect**

Render the image and verify the production target excludes Oracle VPS and Docker
Compose.

### Task 5: Cross-Diagram Verification

**Files:**
- Verify: `docs/reports/uml/*.puml`
- Verify: `docs/reports/uml/*.png`

- [ ] **Step 1: Validate PlantUML syntax**

Run:

```powershell
java -jar $env:PLANTUML_JAR -checkonly -charset UTF-8 docs/reports/uml/*.puml
```

Expected: exit code 0 with no syntax errors.

- [ ] **Step 2: Validate generated artifacts**

Confirm there are exactly four `.puml` and four `.png` files, every PNG is
non-empty, and each image has report-suitable dimensions.

- [ ] **Step 3: Review terminology and security constraints**

Search all sources for consistent plane names and confirm no diagram grants the
AI Plane direct SCM access, authoritative findings, policy override, provider
secret values, or full repository input.

- [ ] **Step 4: Run repository whitespace validation**

Run:

```powershell
git diff --check
```

Expected: no errors from the newly created UML sources.

- [ ] **Step 5: Commit the diagram set**

```powershell
git add docs/reports/uml docs/superpowers/plans/2026-06-13-aegisai-uml-diagrams.md
git commit -m "docs: add AegisAI UML diagram set"
```
