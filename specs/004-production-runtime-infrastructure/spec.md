# Specification: Production Runtime Infrastructure

## Scope

This milestone turns the deferred Kubernetes and microVM infrastructure work
from 003 into an implementation-ready feature package. It does not replace the
completed scanner-first architecture or the completed AI inference runtime. It
defines the production deployment and isolation contracts needed to run those
planes safely.

## In Scope

- Kubernetes production AI Plane deployment manifests
- Runtime autoscaling policy for the AI Plane
- Kubernetes-compatible service, health, configuration, and secret boundaries
- microVM-backed scanner provisioning model
- Scanner sandbox lifecycle and isolation requirements
- Tenant, scan, runtime, and sandbox audit attribution
- Dev/demo Oracle VPS path preservation as a non-production deploy path

## Out of Scope

- Provisioning a live production Kubernetes cluster
- Vendor-specific cluster credential handling
- Customer code execution outside hardened scan isolation
- Package install/build, dynamic testing, auto-fix PR/MR, or direct source upload
- AI finding authority or policy override
- AI access to SCM credentials, full repositories, source archives, or raw scanner payloads

## Requirements

- Kubernetes AI Plane manifests MUST keep AI advisory-only.
- Kubernetes AI Plane manifests MUST NOT expose SCM credentials or repository
  source inputs to AI containers.
- Runtime autoscaling MUST include request latency, queue pressure, provider
  health, and failure/fallback signals.
- Scanner sandbox provisioning MUST model microVM-backed stronger-than-pod
  isolation.
- Scanner sandbox provisioning MUST separate repository fetch and scanner
  execution from Control Plane and AI Plane responsibilities.
- The system MUST NOT execute customer code outside hardened scan isolation.
- The system MUST NOT install packages, build customer repositories, run dynamic
  tests, add direct source upload, or create auto-fix PR/MR flows in this package.
- Oracle VPS and Docker Compose MUST remain documented as dev/demo paths only.

## Acceptance

- Entry-point docs preserve `004-production-runtime-infrastructure` as the
  completed runtime infrastructure baseline.
- `003-production-ai-inference-runtime` remains linked and preserved as the
  completed AI inference baseline.
- `002-production-scan-architecture` remains linked and preserved as the
  completed production scan architecture baseline.
- Contracts describe `AiPlaneDeployment`, `RuntimeAutoscalingPolicy`, and
  `ScannerSandboxProvisioning`.
- The completion gate stays synchronized with CI.
