# Private profile integration plan

Use current dev as the branch base; retain its API, UI, shared root exports, 006
contracts and SQL unchanged. Add apps/private-api, apps/private-web and a generated
client package packages/private-runtime-db. Private contracts are a shared subpath.
This is an explicit transition boundary, not an automatic rewrite of operating data.

Keep the tested private source/gateway/broker behavior, changing package references
and schema ownership only where required. The private container retains the existing
/app/apps/api execution layout so installed host workers and maintenance entrypoints
remain compatible. Docker/Compose chooses private targets explicitly. General dev
images never run private migrations and private images never run dev migrations.

Use one repository/lockfile/CI with distinct verification databases. Add cross-client
isolation checks, namespace checks, target migration-history preflight, and candidate
artifact packaging. Build/test images in CI; the current PC has no Docker runtime.
Stop before deploying anything to the existing EC2. Do not merge or trigger Oracle CD.

Validate intermediate changes only as affected, then one complete hosted CI pass
for the final candidate. Existing production functional proofs remain historical;
new candidate tests do not imply a production rollout or 006 external qualification.
