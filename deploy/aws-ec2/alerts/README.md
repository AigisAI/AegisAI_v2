# Private Slack operational alerts

The owner selected Slack on 2026-11-09. This operator-only addon sends fixed host
health summaries to the exact Incoming Webhook the owner supplies. No tenant,
repository, source, credentials, raw exceptions or arbitrary metric labels leave
the host. No app/observability container receives the webhook or Docker socket.

Run `test_alerts.py` before installing. `setup_portal.py` listens on loopback8768;
expose only `/ops/slack-setup` through existing Tailscale Serve, never Funnel.
It requires an unguessable one-time path, exact Origin, CSRF and bounded form,
accepts only HTTPS hooks.slack.com/services URLs without redirects, expires after
15min, logs no requests and never redisplays the secret. The owner-selected save
button explicitly sends a real connection-test message. Root-only encrypted-disk
`webhook.json` is stored only after Slack accepts it. Remove the temporary Serve
path on completion/expiry. Creating/choosing the Slack workspace/channel remains
an account-owner action. No Slack config tokens or bot-wide read permission.

The timer is enabled only after API metrics and owner configuration exist. It
queries the actual private Prometheus every minute: collector/API target down,
free disk below4GiB, available memory below512MiB, or observation failure.
Two minutes of sustained failure precede an alert; one hourly reminder at most,
and one recovery only for a successfully delivered failure. Failed sends retry
without falsely marking delivered. State, locks and receipts are root-only.
Service memory64MiB/CPU10%/45s timeout, no AWS API privilege or new compute.

This is an outbound notification integration, not a Slack conversation agent.
Actual delivery and failure/recovery proof remain pending until the receiver is
configured and exercised. Full H4 still requires actual deep scan/queue/broker/
worker trace correlation; host alerts cannot certify that or G1-G4 completion.

Primary setup reference:
https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/
