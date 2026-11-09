# H4 observability phase: private single-host diagnostic plane

User deployment instruction authorizes this next phase after non-destructive H1
adoption. Keep the existing EC2 and independent scanner; no paid external compute.
H1 remains partial until reconstruction/coverage acceptance. H4 remains partial
until actual request/scan/queue/broker/worker correlation and real alert delivery.

Deploy actual Grafana, Loki, Prometheus and Alloy, with Tempo monolithic as the
explicit trace backend. Local diagnostic storage is bounded, non-authoritative
and lost with the host; it is not HA, durable audit storage or general-service
compliance. The authoritative existing evidence and DB remain unchanged.

A dedicated internal bridge uses an unused checked subnet, no public ports, no
metadata/Internet route and no Docker socket/SCM/AWS credentials. Reserve an exact
proxy address for the existing ingress. Grafana has no initial admin password,
no basic/anonymous login, and accepts auth-proxy identity only from that proxy.
The proxy overwrites client identity headers after a SessionAuthGuard-protected
internal API check; the fixed role is Viewer. Do not reuse SCM OAuth credentials
or trust caller-supplied identity. Preserve existing owner numeric admission,
CSRF/throttling and expired-session rejection. Unauthorized Grafana requests must
never reach its data APIs. The rest of /ops and legacy APIs stay closed.

API telemetry is opt-in, manual OpenTelemetry spans only, with no automatic SQL,
AWS/SCM SDK, raw body/header/query or source capture. Restrict route labels to a
bounded allowlist; trace/scan IDs are not metric labels. SDK/export failures are
bounded and must not fail the app. Keep Node20 workspace CI compatibility and
Node22 production. API logs use bounded OpenTelemetry log batches; host status logs rotate to
bounded allowlisted files. Alloy receives only those streams, never all Docker
logs or a Docker socket.
Root runtime exporter reads only coarse health/resource/catalog/retention status,
not credentials or customer data. Actual host health metrics and operational logs
are first delivery; deep worker tracing cannot be claimed from HTTP spans alone.

Proposed caps: Grafana 384MiB, Loki 256MiB, Prometheus 256MiB, Alloy 192MiB,
Tempo 256MiB, exporter 64MiB. Check coexistence with API replicas and 1GiB scanner
reserve before installation. Preserve >3GiB disk; bound ingestion/cardinality,
short diagnostic retention, log rotation and collection shutdown at high-water.
Do not delete app images, volumes, authoritative data or retained recovery assets.

Validate vendor configuration and auth/identity-spoof rejection, sanitize/bound
telemetry, then CI and immutable app image. Install hidden backends first; attach
Grafana ingress only after owner auth and actual queries pass. Preserve prior
app/proxy config for recovery. No application DB migration or new real scan is
needed for backend/HTTP telemetry acceptance. Full scan tracing needs its own
bounded actual path later. External alert receiver/destination must be selected
rather than fabricating successful delivery.

Primary configuration references:
- https://grafana.com/docs/grafana/latest/setup-grafana/configure-access/configure-authentication/auth-proxy/
- https://grafana.com/docs/tempo/latest/reference-tempo-architecture/deployment-modes/
- https://grafana.com/docs/alloy/latest/collect/opentelemetry-to-lgtm-stack/
