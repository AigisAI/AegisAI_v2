# Plan: Production AI Inference Runtime

## Approach

Implement the AI inference runtime in thin, testable slices. The first slice is
documentation and active feature re-baselining. Later slices add shared contracts,
runtime interfaces, provider adapters, fallback behavior, audit events, and
observability.

## Target Boundaries

- `packages/shared`: public AI inference runtime contracts
- `apps/ai`: model gateway, reduced evidence validation, provider adapters, and
  fallback runtime
- `apps/api`: AI advisory client integration and audit attribution
- `specs/003-production-ai-inference-runtime`: active feature package

## Runtime Shape

1. API and Scan Plane produce normalized findings and reduced evidence.
2. AI Plane receives an `AiInferenceRequest` through a model gateway.
3. The gateway validates that forbidden payload classes are absent.
4. A configured provider or deterministic fallback returns advisory output.
5. The API persists advisory metadata and audit events without treating AI output
   as authoritative findings or policy decisions.

## Key Interfaces

- Model gateway: provider-neutral inference boundary
- Reduced evidence validator: input payload guardrail
- Fallback provider: deterministic local/dev behavior
- Audit emitter: tenant, scan, model, provider, and rejection attribution
- Observability emitter: latency, error, fallback, and model metadata

## Completion Strategy

Use TDD for each implementation slice. Keep the production scan architecture
guardrails from 002 intact and add tests whenever a new AI runtime boundary is
introduced.
