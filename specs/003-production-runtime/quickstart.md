# Production runtime execution

The user authorized production implementation on 2026-11-07 after confirming that
both the local 002 milestone and origin/main contain simulated analysis. This
package is the narrower active feature. Enter through the 002 quickstart, retain
its product baseline/read order, then read `spec.md`, `plan.md`, and `tasks.md` here.
For worker/gateway changes also read `runtime-execution.md`, `data-model.md`, and
`single-host-security-review.md` before implementation.

Keep candidate ingress closed until the applicable release gates for its explicitly
approved scope pass. A working EC2, HTTPS endpoint or mock pipeline alone is not
production readiness. Current accepted private scope is recorded below; it does
not imply the broader general-service gates passed.

Current private operating evidence is indexed in
[production documentation](../../docs/production/README.md). Accepted private gates
and remaining general-service gaps are separate; see the current release section below.

Execution order: durable identity/control data, trusted SCM integration, durable
queue/outbox, isolated deterministic scanner execution, evidence/policy, real UI
integration, then operational recovery and release verification. The user constrained
deployment to one existing EC2 with no additional compute on 2026-11-07. Investigate
a dedicated containerd/gVisor sandbox runtime on that host; ordinary app containers
must never execute scanners. This deviates from the baseline's separate-node
topology: record security review and operating scope before processing repositories,
and do not claim multi-tenant baseline compliance. AI remains optional and
advisory-only. See `single-instance-decision.md`.

Validation: run all six commands from the 002 quickstart. Additionally apply
migrations to a dedicated verification PostgreSQL database and run
`node --test --test-concurrency=1 test/persistence/*.test.mjs` with `PERSISTENCE_TEST_DATABASE_URL` set.
This integration suite must never use the production database. Repeat verification
after deploying a candidate, including process restart, tenant isolation, concurrent
deduplication, revoked integration rejection and DB outage behavior.

After the PostgreSQL suite, run `test/worker-native/*.test.mjs` serially in the
Linux API image as container UID 0, with only the disposable verification database
and test directory supplied. These acceptance tests require Unix permissions and a
dedicated UID probe; do not skip them on Windows or run them against production.
CI and `deploy/aws-ec2/deploy-candidate.sh` enforce this additional gate before any
production migration or candidate replacement. No real SCM key is mounted for it.

Per the user's 2026-11-08 request, use targeted validation for intermediate changes
instead of repeating unchanged suites. `deploy-candidate.sh <release> <hash>
runtime-results` runs the affected queue/results suites plus native private-channel
acceptance before the result/lifecycle candidate; it does not repeat unchanged
provider authentication checks. Default `full`, CI and final completion retain the
complete validation path. Record the selected profile with each candidate.

Record evidence and unfinished gates in tasks.md; keep 002/AGENTS/README/conventions
linked to this package. Do not open ingress based only on the initial persistence slice.

## Current private release

The explicit one-owner/private-organization Java profile passed real scan, managed
boot, encrypted evidence/offsite restore and private access rollback acceptance on
2026-11-08. The owner confirmed repositories and the completed result in the actual
private UI. Only whitelisted real runtime APIs are enabled. This does not complete
the broader separate-node/multi-tenant baseline or future AI work. See the current
deployment checkpoint and deploy/aws-ec2/PRODUCTION-ACCESS.md for exact evidence.

For frontend-only corrections with byte-identical API/shared/dependency inputs,
use deploy-web.py with affected web tests/types/lint/build/route checks. Do not
repeat unchanged SQL/native/scanner suites. The managed-runtime release passed
all six canonical checks; full releases/CI retain the complete gate. Include the
frontend override in root recovery and supersede it on a full replacement.

For documentation-only maintenance, check local links, evidence accuracy and file
scope. Do not rerun unchanged code suites, actual scans or backup restores.

## Mandatory rollout/scaling expansion — 2026-11-09

User instruction makes Blue/Green, Canary, actual Kubernetes RollingUpdate and
HPA implementation plus measured verification mandatory, all currently incomplete.
Follow [existing execution plan](../../docs/reports/2026-11-07-production-deployment-plan.md)
4/G, 4/H and 9 and [remaining work](../../docs/production/remaining-work.md).
The existing commit-based private release is deployed; new requirements do not
retroactively certify new strategies. Keep one existing EC2, no extra compute,
scanner boundaries and applicable 005/006 gates. Capacity and architecture review
precede changes; lab-only proof cannot substitute for actual-service completion.

The user also restored four mandatory platform requirements on 2026-11-09:
H1 Terraform IaC/reproducibility; H2 GitOps/CD; H3 deployment image scanning,
SBOM and signature enforcement; H4 AWS correlated logs, metrics and tracing.
Follow section 4/H of the same execution plan. Existing CI/hash checks are only
partial foundations. All H requirements remain incomplete; documentation changes
do not authorize production topology, new resources or privilege changes.

H4 observability explicitly requires Grafana, Loki and Prometheus, all actually
used and verified. Keep OpenTelemetry tracing and choose its storage backend
separately; metric/log dashboards alone do not complete distributed tracing.
Preserve the one-existing-EC2 resource/cost constraints. This stack declaration
does not authorize installation or production changes.

## Owner-approved private Kubernetes continuation

On2026-11-09 the owner approved the concrete single-host operating scope. Continue
through [009](../009-private-single-host-kubernetes/quickstart.md), retaining
the existing private/gVisor/data/auth/AI boundaries. This supersedes the private
installation hold only; general005/006 T053-T056 qualification remains unpassed.
No extra compute, public ingress or runtime IAM expansion.
