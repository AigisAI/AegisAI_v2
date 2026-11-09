# Private observability delivery

Issue #342, stacked on the non-destructive Terraform adoption in #340.
This is an opt-in diagnostic plane on the existing EC2, not G/H completion.
Grafana, Loki, Prometheus, Alloy and monolithic Tempo are pinned by digest.
No host ports, Internet/metadata route, Docker socket or application credentials
are supplied to their containers. A separate internal bridge is checked for
conflicts. CPU, memory, processes, logs, ingestion and retention are bounded.

`prepare.py prepare` pulls exact images and validates available vendor parsers.
`prepare.py start` starts hidden backends only. CI verifies actual startup,
unauthenticated/direct-header-spoof denial and Prometheus self-scraping. This does
not verify app telemetry, owner access, external alerts or worker correlation.
Run `verify_stack.py` for that narrow backend proof; never use it as full H4 proof.

The app overlay is installed only after immutable candidate verification. Ingress
locations require session-derived auth, overwrite caller identities, strip app
cookies and use the fixed Viewer role. Reserve 172.29.240.2 for the existing proxy.
Only after actual auth/query checks should this snippet be attached, validated and
reloaded with the previous mounted configuration retained for rollback. The
snippet is not automatically installed by preparation/start.

The host exporter needs a root-owned bounded systemd unit and the checked bridge;
it binds only the bridge gateway. It emits coarse host resource logs, never
customer/source logs. At <3328MiB free it stops only Alloy/Tempo/Loki collection;
restart is manual after investigating. No images, volumes or backups are pruned.
Grafana secret_key is independently generated outside Git, with UID472-only read.
There is no initial admin, anonymous/basic access or Grafana login-token session.

Local diagnostics are disposable, not authoritative evidence or durable audit.
Root recovery starts the primary app without telemetry if its optional bridge
is missing; diagnostic recovery must follow separately. No new DB migration is
needed. AI remains optional/off and the existing scanner is unchanged.

## Actual progress

2026-11-09: initial image preparation stopped at the disk-reserve guard without
application changes. The owner explicitly approved 30->50GiB on the same root
volume. Terraform permits only that volume-size update and requires a no-op
confirmation; encrypted EBS, instance count, IAM and ingress remain unchanged.
Prometheus/Loki vendor syntax and API auth/sanitization tests passed. Hidden vendor startup, direct spoof denial and Prometheus self-scrape passed.
Remaining immutable API delivery, protected Grafana access, actual pipeline
queries, external alerts and deep worker trace correlation are still pending.
