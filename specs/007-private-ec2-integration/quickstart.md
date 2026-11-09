# Private EC2 integration execution

Enter through AGENTS.md and the canonical 006 quickstart first. This is the
user-authorized narrower integration profile, requested on 2026-11-09. Read
spec.md, plan.md, runtime-execution.md and the same-host security review before
changing runtime boundaries. The DOCX remains the product baseline.

The work stops before deployment. Do not update production images, services,
secrets, ingress or database. Read-only target preflight is allowed. No additional
EC2, Fargate, cluster or NAT is authorized. AI remains optional and initially off.

Retain the current dev API/schema/006 contracts and qualification gates. Add a
named private runtime profile with isolated Prisma client/migrations, shared
contracts under packages/shared/private-runtime, the existing UI theme, and
explicit private Docker/Compose targets. A private test pass is not a T053-T056
pass, Kubernetes readiness, general multi-tenancy or separate-node certification.

Validation order: generate both Prisma clients; build shared contracts; affected
private API/UI checks; real PostgreSQL and Linux Unix-role checks on a disposable
private DB; then the canonical dev validation/qualification gates in hosted CI.
Never point tests at the existing production database. Read-only target checks
must reject incompatible migration history rather than applying dev migrations.

Completion requires a dev-based mergeable candidate, passing old and private
checks, immutable source/image artifacts with provenance, and an explicit deploy
command which remains unexecuted. Record material limits and artifacts in tasks.md.
