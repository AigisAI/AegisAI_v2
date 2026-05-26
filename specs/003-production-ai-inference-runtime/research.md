# Research: Production AI Inference Runtime

## Decisions

### Model gateway first

Use a provider-neutral model gateway interface before wiring a concrete provider.
This keeps tests deterministic, isolates provider configuration, and prevents
credential handling from leaking into application code.

### Reduced evidence only

The AI Plane receives reduced evidence, normalized finding context, and evidence
metadata only. This preserves the 002 boundary that AI is advisory-only and does
not inspect full repositories or SCM credentials.

### Deterministic fallback

Local/dev execution uses a deterministic fallback provider. Production provider
errors can degrade to fallback advisories when policy allows, and every fallback
use is auditable.

### Audit and observability as first-class outputs

Each inference request needs model metadata, latency, provider status, rejection
reason, fallback state, tenant id, and scan id attribution.

## Rejected Alternatives

### AI as finding authority

Rejected because 002 defines scanner-first findings and policy authority outside
the AI Plane.

### Direct repository ingestion

Rejected because the AI Plane must not receive SCM credentials, source archives,
or full repository content.

### Provider-specific contracts

Rejected for the baseline because it would couple product contracts to a single
vendor and make deterministic testing harder.
