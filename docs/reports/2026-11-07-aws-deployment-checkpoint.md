# AWS deployment checkpoint — 2026-11-07 KST

> Historical state as of 2026-11-07. The heading "current" below is relative to
> that report date. See [current production docs](../production/README.md) and
> [release evidence](../production/release-evidence.md) for the deployed runtime.

## Intent and outcome

### Current verified state (supersedes historical checkpoints below)

- Current candidate ec2-runtime-20261107-044312, dirty snapshot; archive SHA-256
  d786900aa0f1ee3c744cf56d9071b7b2713918c9fcaca03004b3d8f06c16688e.
- Separate organization SCM App and identity-only login App are configured. Actual
  organization discovery verified five selected repositories, administrator authority
  and token revocation without fetching source. The user completed real HTTPS login;
  persisted GitHub identity and active tenant were independently verified.
- Optional canonical GitHub OAuth issuer is accepted; other issuers are rejected.
  State/PKCE and secure Redis-backed sessions remain enforced. Private account
  admission is required. Registration helpers are stopped and their routes removed.
- Durable PostgreSQL dispatch queue deployed: transactional creation, fencing,
  bounded retries, dead letters and cancellation. All 20 real-DB persistence,
  migration and queue checks passed in the target image. No worker is enabled.
- Latest API suite passed 85 tests; default suite totals 157 tests across packages.
  Target provider/HTTP checks passed 38 tests; lint/typecheck/build/schema and
  compiled runtime checks passed. Hosted CI has not run.
- AWS temporary operator authentication works. The existing EC2 security group now
  has zero public inbound rules; operations and HTTPS use Tailscale only.
- Separate containerd/gVisor installed on the same host. Trusted fixture verified
  non-root, no network, read-only root, resource limits and inaccessible host/metadata.
  Pinned scanner image java-v2 passed synthetic Java/SBOM/offline SCA checks; no repository input.
  Static core replaces the self-extracting CLI, which correctly failed no-exec temp storage.
  Image index: sha256:2a9af6fa8284b6c585370234f95179a58cb48e739fd9118a6e10e01ddd395d20.
  Offline vendor DB layer: sha256:1fadb75c96dd1976fe41094735fc756b4034f3a6a005b7331500fe46d665ac91,
  updated 2026-11-07T00:44:27Z; known CVE-2021-44228 detected. Missing DB fails visibly.
- The user prohibits additional compute. The single-host baseline deviation is
  recorded in specs/003-production-runtime/single-instance-decision.md; this is
  not a claim of separate-node or general multi-tenant compliance.
- Root replacement task `replacevol-02964a569f346d10c` succeeded. Active root
  `vol-06b3fb819818cd306` is encrypted; automatic reboot restoration and all four
  workload health checks passed. Actual identity survived. Original unencrypted root
  and source snapshot are retained; encrypted rollback snapshot `snap-06fb0ff2da292f167`
  completed and is encrypted. The user did not authorize original-copy deletion.
  Do not describe historical copies as all encrypted.
  Temporary storage incurs charges; no new EC2 was created.
- Rechecked live organization administration and persisted one integration/five
  bindings for the actual OAuth identity. No source was fetched. Fresh live backup
  restored into a disposable database with matching three migrations, one identity,
  one integration, five bindings and zero scans (3.507 seconds; not an RTO claim).
- Post-candidate fresh live backup restore matched the same durable entity counts
  (0.967 seconds for this small deployment, not an RTO claim). Authentication preflight
  was reapplied and remains 200; root and application APIs remain 503. Unused build
  cache cleanup reclaimed 5.125 GB while preserving images and data volumes.
- Only login preflight is exposed. Root application remains closed. Immutable fetch,
  ten-minute credential broker, worker/results/evidence/policy/UI and full operating
  acceptance remain release gates. No customer repository has been processed.


### Latest GitHub installation discovery candidate

- Candidate: `ec2-runtime-20261107-031233`, dirty source snapshot, base commit
  `a8e51eb26d082fefe420cb150b43815f09fbbcf7`, 166 packaged files.
- Archive SHA-256: `709a08db643d636b72e00da3f3b1fc5e74911164b322fd6885600a684ec88562`.
- Added `POST /api/integrations/github-app/install`: authenticated/CSRF-protected
  personal installation ownership verification, selected repository metadata from
  GitHub, scoped Metadata-read token revoked before persistence. Organization
  installs, caller-fabricated metadata and suspended installations are rejected.
- App key remains external; the root-only host directory is mounted read-only.
  No real App signing key has been located or provisioned. Live provider acceptance
  remains pending; the 16 provider/HTTP tests use controlled provider responses.
- All 130 default tests, lint, typecheck, build, Prisma validation and two compiled
  runtime tests passed. Target Linux Node 22 image passed the 16 App regression
  tests plus eight PostgreSQL persistence tests before replacing workloads.
- First image test caught missing root tsconfig.base.json in the runner before
  app replacement. The runner now includes it; a fresh candidate passed the gate.
- Existing GitHub OAuth pair activated for the AWS HTTPS origin. Redirect client
  ID, callback, login-only scopes, S256 PKCE and Secure/HttpOnly/SameSite=Lax cookie
  were verified without exposing values. Provider registration compatibility and
  an actual completed login remain unverified. Browser automation could not inspect
  GitHub settings because its safety layer could not determine the current URL.
- Database migration: no pending migrations. All four workloads healthy after
  replacement and an explicit API restart; OAuth configuration and dependency
  health rechecked after restart. Backup restored into a disposable verification database; two
  migration records found, 0.665 seconds for the bootstrap database only.
- Tailscale HTTPS still reports applicationReady=false and application routes 503.
  No application ingress promotion occurred. Hosted CI has not been triggered.

Remaining launch conditions include provider callback/App setup, scan credential
broker with enforced ten-minute maximum lifetime, immutable commit resolution,
durable queue, isolated scanners, evidence/policy/UI and operational acceptance.
AWS API/IAM access for isolated scanner infrastructure is still unavailable.

### Latest persistence candidate update

The user authorized runtime implementation; `003-production-runtime` is now the
active narrower package. The earlier bootstrap findings below are retained as
history. In-process Control Plane maps have been replaced with PostgreSQL-backed
identity, tenant, integration, repository and scan-request persistence. Transactions
handle concurrent idempotence; tenant checks, revocation and audit retention are
covered. Pending simulated mutation endpoints return 503 in production.

- Candidate: `ec2-runtime-20261107-014329`, uncommitted snapshot of the same base.
- Archive SHA-256: `91197520574d9e1c68931307b959843a15f211c36f445f6f93b99cb4ed32632b`.
- Lint, typecheck, build, Prisma validation, 114 default tests and two compiled
  runtime tests passed. Dedicated PostgreSQL suite passed eight tests including
  its parent suite, locally and inside the target Linux Node 22 API image.
- CI is configured to run the persistence suite; hosted CI has not been run.
- Candidate migrations applied with no pending migration. All four app/dependency
  containers healthy. API restart followed by dependency health verification passed.
- Live checks: health 200, unauthenticated integrations 401, internally authenticated
  mock scan/token mutation endpoints 503 with `PRODUCTION_RUNTIME_NOT_READY`.
- Pre-candidate backup restored successfully into a unique disposable database;
  both migration records verified. Latest restore took 0.668 seconds for the
  bootstrap database with no customer data. This is not a production RTO claim.
  Initial restore found a missing ownership role in the test cluster; the verifier
  now creates the required NOLOGIN role there before restoring. Production roles
  and data were not changed by the restore exercise.
- Verification database container stopped after checks. Private HTTPS still returns
  applicationReady false and application routes 503; no ingress promotion occurred.

Real GitHub App integration, isolated scanner execution, durable queue, evidence,
policy/UI wiring, actual OAuth login and broader operational acceptance remain
unfinished. The user confirms existing app/auth configuration exists; its location
was subsequently recovered from the original Oracle server at `/opt/aegisai/.env`.
GitHub/GitLab OAuth pairs match the running original API; they are staged on AWS
in a root-only pending configuration file. The original service is unchanged.
Provider callback compatibility with the new AWS hostname is not yet verified.
No GitHub App signing configuration was found in the inspected deployment.
Credentials alone do not complete the missing runtime.

User intent is a real production deployment using the existing AWS EC2 instance,
with private access through Tailscale. This is not a completed production launch.
The infrastructure entrypoint works; application readiness remains false.

- Host: Ubuntu 24.04, 2 vCPU, approximately 8 GB RAM, 29 GB root filesystem.
- Tailscale hostname: `aegisai-aws`.
- Private HTTPS: `https://aegisai-aws.tailaca7d2.ts.net`.
- `/healthz`: HTTP 200 with `infrastructure: up`, `applicationReady: false`.
- All other paths: HTTP 503, preparation message.
- HTTPS was verified from the Windows tailnet client and from the server, without
  disabling certificate verification. Tailscale ping also passed.
- No Funnel or public HTTP/HTTPS application listener was enabled.
- Existing public SSH access was retained. AWS security-group inventory has not
  been inspected through the AWS API.

## Completed work

- Installed Docker Engine, Compose and Buildx using Ubuntu packages.
- Installed Tailscale from its official package source; the user enrolled the node.
- Corrected SSH attachment file ACLs so only the current user can read the key.
- Fixed clean-container build failure by explicitly generating Prisma Client.
- Added OpenSSL to API build/runtime stages to fix Prisma engine startup.
- Changed API and frontend builder Node images from Node 20 to Node 22.
- Built images on the target host and applied both Prisma migrations to a fresh DB.
- PostgreSQL, Redis, API and web preflight containers are healthy.
- Internal API health reports database and sessionStore both up.
- Runtime secrets were generated on the host, outside the source release, mode 0600.
- Added a separate private ingress that blocks application access until ready.

The preflight app's web listener is `127.0.0.1:8080`; the pending ingress is
`127.0.0.1:8081`. PostgreSQL, Redis and API have no host port publications.

## Source provenance

The preflight workload came from an explicitly uncommitted local snapshot:

- Base commit: `a8e51eb26d082fefe420cb150b43815f09fbbcf7`.
- Release: `ec2-demo-20261107-011527`.
- Source archive SHA-256:
  `344a6e2080eb349eec6f0a47ab8b957f3e11f6d65d94e6411276dd581605f002`.
- Release directory: `/opt/aegisai/releases/ec2-demo-20261107-011527`.
- Private runtime configuration: `/opt/aegisai/shared/runtime.env`.
- Pending ingress configuration: `/opt/aegisai/shared/ingress-pending.conf`.

Do not treat this dirty snapshot as an approved immutable production release.
No source commits, pushes, merges or GitHub deployment workflows were triggered.
The existing Oracle deployment was not modified.

## Verified checks and limits

Local lint, typecheck, build, 113 default tests and 2 compiled-runtime tests passed.
Prisma schema validation passed using a command-local placeholder database URL;
actual migration application was separately verified against the EC2 database.
Container Node 22 builds, migration application and live dependency health passed
after the Dockerfile fixes. The complete test suite has not been rerun inside the
Node 22 container. OAuth login, real scans, restart persistence, backup restoration,
load/SLO checks and production isolation have not passed acceptance.

## Blocking product gaps discovered

1. Local 002 Control Plane stores integrations, repository bindings and scan
   requests in process Maps. PostgreSQL schema presence does not implement persistence.
2. Local Scan Plane emits mock results and does not execute the approved scanners.
3. Latest fetched `origin/main` (`7c9346958fdd77ee549086844e83404662e47593`)
   wires `MockAnalysisApiClient` directly in AnalysisApiModule; switching branches
   alone does not provide a real analysis runtime.
4. Runtime OAuth values are explicitly unconfigured and origins use
   `https://pending.invalid`. Do not enable login or application ingress with them.
5. Single-host Compose is not the product specification's production isolation
   topology. The chosen production runtime must satisfy the plane and per-scan
   sandbox requirements before processing customer repositories.

The user has been asked whether a separate implementation branch/repository exists.
If none exists, production implementation requires a follow-on feature package
that explicitly reclassifies the runtime work deferred by 002. Preserve existing
tenant isolation, secure sessions, CSRF, deterministic-first and advisory-only rules.

## Next operator actions

Resolve the source/runtime gap, create a reproducible release, configure actual
OAuth and the final origin, verify persistence and real scanner isolation, complete
backup/restore and operational checks, then replace the pending ingress deliberately.
Do not disable TLS or cookies to bypass authentication setup. Do not remove data
volumes during redeployment. Tailscale node key expiry and access policy also need
an explicit production operating policy; neither was changed in this session.
