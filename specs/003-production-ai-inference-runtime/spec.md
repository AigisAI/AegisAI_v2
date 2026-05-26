# Specification: Production AI Inference Runtime

## Scope

This milestone turns the deferred 002 trained production AI detector/planner
inference item into an implementation-ready feature package. It does not replace
the deterministic scanner-first pipeline. It adds a production AI Plane runtime
that consumes reduced evidence and returns advisory detector/planner output.

## In Scope

- Trained production AI detector/planner inference boundary
- Reduced evidence request validation
- Model gateway interface and provider selection
- Deterministic local/dev fallback behavior
- Advisory-only response shape
- Tenant, scan, model, and request audit attribution
- Observability fields for latency, provider status, model version, fallback use,
  and rejection reasons

## Out of Scope

- Authoritative finding generation by AI
- Policy decision override by AI
- SCM credential handling inside the AI Plane
- Full repository, source archive, or raw scanner payload ingestion
- Customer code execution, package install/build, dynamic testing, or auto-fix PR/MR
- Kubernetes/microVM provisioning implementation

## Requirements

- The AI runtime MUST NOT create authoritative findings.
- The AI runtime MUST NOT receive SCM credentials.
- The AI runtime MUST NOT receive full repositories, source archives, or raw
  scanner payloads.
- The runtime MUST accept only reduced evidence derived from normalized findings
  and evidence pack metadata.
- The runtime MUST return advisory detector and planner output with confidence,
  rationale, model metadata, and fallback status.
- The runtime MUST keep tenant and scan attribution on every request and audit
  event.
- The runtime MUST expose deterministic fallback behavior for local/dev tests.
- The runtime MUST support production provider configuration without hard-coding
  provider credentials in code.

## Acceptance

- Shared contracts describe `AiInferenceRequest`, `AiInferenceResponse`, and
  `ReducedEvidence`.
- Entry-point docs identify `003-production-ai-inference-runtime` as the active
  feature package.
- The completed 002 baseline remains linked and preserved.
- The completion gate stays synchronized with CI.
