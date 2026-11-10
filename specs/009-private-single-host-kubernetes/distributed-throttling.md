# Preserve limits across API replicas, issue363

The actual HPA run exposed per-replica in-memory accounting: two API processes
accepted240 health requests against a120-request limit. Replace only non-test
private API storage with atomic shared Redis sliding hit expiry/blocking. Keep
route decorators/limits/tracker/session/CSRF semantics. Test environments retain
their existing isolated memory store. No schema, SCM, scan or AI change.

Use Redis server time, hashed route/tracker keys, atomic Lua, bounded hit logs,
expiring keys and non-extending blocks. Bound startup/command waits/queue length;
fail closed with sanitized503 on store failure and reconnect automatically.
Register shutdown independently from session Redis health/client ownership.

Verify two actual HTTP application instances against disposable Redis7 pinned
to the same public image digest as the existing server. Prove one shared burst,
parallel atomic limit, expiry/block consistency, route isolation and outage
failure behavior. Never point the test at production Redis or create a user
session/scan. The compiled API candidate retains full canonical/private SQL/native
CI, vulnerability/SBOM/signature gates before actual RollingUpdate deployment.
