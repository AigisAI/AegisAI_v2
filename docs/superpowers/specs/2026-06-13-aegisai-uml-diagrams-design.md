# AegisAI UML Diagram Set Design

## Purpose

Create a report-ready UML diagram set for the AegisAI graduation project. The
diagrams describe the target production architecture, including the active
`005-production-deployment-operations` design and the completed production scan,
AI inference, and runtime infrastructure baselines.

## Deliverables

The diagram set contains four PlantUML source files and four rendered PNG files:

1. Use Case Diagram
2. Component Diagram
3. Scan Execution Sequence Diagram
4. Production Deployment Diagram

All diagram labels and notes use English. Each PNG must be suitable for insertion
into a university graduation project report without additional editing.

## Output Location

Store sources and rendered images under:

```text
docs/reports/uml/
|-- aegisai-use-case.puml
|-- aegisai-use-case.png
|-- aegisai-component.puml
|-- aegisai-component.png
|-- aegisai-scan-sequence.puml
|-- aegisai-scan-sequence.png
|-- aegisai-production-deployment.puml
`-- aegisai-production-deployment.png
```

## Shared Modeling Rules

- Follow standard UML 2.x notation supported by PlantUML.
- Use stereotypes only to clarify architecture-specific roles or trust
  boundaries.
- Model the final target architecture, not only the currently executable local
  implementation.
- Keep user authentication separate from SCM integration credentials.
- Preserve explicit Control, Scan, AI, and Data & Security Plane boundaries.
- Show the AI Plane as advisory-only.
- Do not model direct source upload, customer package installation, customer
  repository builds, or dynamic test execution.
- Do not imply that the AI Plane has SCM credentials, direct SCM access, full
  repository access, or policy override authority.
- Show production Kubernetes and hardened microVM scanner isolation as target
  deployment elements.
- Treat Oracle VPS and Docker Compose as dev/demo only and omit them from the
  production deployment diagram.

## Diagram 1: Use Case Diagram

### Actors

- Tenant Administrator
- Security Engineer
- Deployment Operator
- GitHub Cloud / GitLab Cloud

### System Use Cases

- Manage SCM Integration
- Bind Repository
- Request Security Scan
- Monitor Scan Status
- Review Findings and Evidence
- Manage Policy, Waiver, and Suppression
- Receive Advisory AI Analysis
- Publish Approved Security Feedback
- Prepare Deployment Preflight
- Approve Deployment Handoff
- Execute Production Provisioning
- Audit Security and Deployment Operations

### Required Relationships

- Repository binding includes SCM integration management.
- Scan request includes repository and commit validation.
- Advisory AI analysis extends deterministic scan processing and cannot replace
  authoritative scanner findings.
- Security feedback publication includes policy evaluation.
- Production provisioning includes deployment preflight and approved handoff.
- SCM interaction is limited to approved integration and publication paths.

## Diagram 2: Component Diagram

### Primary Components

- Web Dashboard
- Control Plane API
- Authentication and Authorization
- Tenant and Repository Registry
- Scan Planner
- Token Broker
- Policy Engine
- Comment Publisher
- Queue / Event Bus
- Sandbox Provisioner
- Repository Fetch Worker
- Opengrep Adapter
- Trivy Adapter
- Syft Adapter
- Finding Normalizer and Correlator
- Evidence Pack Builder
- AI Inference Gateway
- Evidence Reduction and Prompt Guard
- Advisory Detector / Planner
- Findings Database
- Object Storage with TTL
- Audit Log Store
- KMS
- Secrets Manager
- Rule and Vulnerability Database Mirrors

### Boundaries and Dependencies

- Group components into Control, Scan, AI, and Data & Security Plane packages.
- Show external dependencies on Tenant Users and GitHub Cloud / GitLab Cloud.
- The Control Plane may request short-lived SCM credentials through the Token
  Broker, but credential values must not be persisted.
- The Scan Plane receives a fixed repository target and short-lived read
  credential, then emits normalized findings and reduced evidence.
- The AI Plane receives only reduced, redacted evidence and returns advisory
  output.
- The Policy Engine is the authoritative publication gate.
- All critical operations emit audit signals without secret values or forbidden
  repository payloads.

## Diagram 3: Scan Execution Sequence Diagram

### Lifelines

- Security Engineer
- Web Dashboard
- Control Plane API
- Scan Planner
- Token Broker
- Queue / Event Bus
- Sandbox Provisioner
- Scanner Adapters
- Finding Normalizer
- Evidence Pack Builder
- AI Inference Gateway
- Policy Engine
- Findings Store
- Audit Store

### Main Flow

1. The user requests a scan for a bound repository and fixed commit.
2. The Control Plane validates the tenant, repository binding, and canonical scan
   key.
3. The Scan Planner creates the scan request and enqueues isolated execution.
4. The Scan Plane provisions an ephemeral hardened sandbox.
5. The Token Broker issues a short-lived, read-only credential reference.
6. The sandbox fetches the fixed commit and runs Opengrep, Trivy, and Syft.
7. Scanner output is normalized, correlated, and persisted as authoritative
   findings.
8. A reduced and redacted evidence pack is created.
9. The AI Plane reviews only eligible reduced evidence and returns advisory
   analysis.
10. The Policy Engine evaluates deterministic findings and advisory context.
11. Results and audit events are persisted.
12. The dashboard returns scan status and report data to the user.

### Alternative and Failure Flows

- Reject duplicate active scans using the canonical scan key.
- Escalate isolation or fail safely when sandbox requirements cannot be met.
- Continue with deterministic findings when AI inference is unavailable or
  ineligible.
- Prevent publication when policy, evidence, or freshness validation fails.
- Never expose credential values, full repositories, source archives, or raw
  scanner payloads to the AI Plane.

## Diagram 4: Production Deployment Diagram

### Nodes

- User Device
- GitHub Cloud / GitLab Cloud
- Production Kubernetes Environment
- Control Plane Namespace
- Scan Plane Namespace
- AI Plane Namespace
- Data & Security Plane Namespace
- Hardened microVM Platform
- Ephemeral Scanner microVM
- Managed Database
- Object Storage
- Queue / Event Bus
- KMS
- External Secrets Manager
- Audit Sink
- Rule / Vulnerability Database Mirrors

### Deployment Constraints

- Represent the four planes as separate namespaces or equivalent trust
  boundaries.
- Place repository fetch and scanner execution inside ephemeral hardened
  microVMs, not ordinary shared application pods.
- Permit private east-west communication only through declared service
  interfaces.
- Show the AI Plane without SCM network or credential access.
- Show external credential handoff by Secret Manager reference or ephemeral OIDC
  federation, never embedded provider secrets.
- Show findings persistence, evidence TTL storage, KMS protection, and audit
  export.
- Attach deployment notes for provider-neutral provisioning and
  provider-specific microVM rollout.

## Visual Style

- Use a restrained monochrome base with a small number of distinct colors for
  trust boundaries.
- Use consistent colors for the four planes across all diagrams.
- Use orthogonal connectors where supported.
- Avoid decorative graphics, gradients, shadows, and informal icons.
- Use a readable sans-serif font and a white background.
- Keep titles concise and suitable as report figure captions.
- Prefer landscape layout for component and deployment diagrams.
- Keep each rendered image legible when scaled to an A4 report page.

## Validation

- PlantUML sources must compile without errors.
- Rendered PNG files must be non-empty and visually inspected.
- Actor, component, lifeline, and node names must remain consistent across all
  diagrams.
- Relationships must use valid UML semantics for the selected diagram type.
- No diagram may imply forbidden AI authority or repository access.
- No diagram may contain provider credentials or local development defaults.
- The diagram set must reflect the active 005 production deployment operations
  target and preserve the 002-004 architecture boundaries.

## Non-Goals

- Provider-specific Terraform, Pulumi, Helm, or cloud CLI implementation
- Live Kubernetes provisioning
- Live microVM platform rollout
- Database-level entity relationship diagrams
- Detailed class diagrams or state machine diagrams
- UI wireframes
