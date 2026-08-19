# T053 Isolated Integration Qualification v1

This package is the immutable provider handoff for the 41 T052 schema/parser and
malicious-repository cases expanded across all three signed profiles (123 execution cells).

- `isolated-integration.manifest.json` binds the exact source case, fixture, profile,
  materialization projection, provisioning contract, and cleanup requirements for every cell.
- `materialization-policy.json` is a closed declarative action allowlist. It has no shell,
  command, argv, environment, script, URL, package-install, build, dynamic-test, customer-content,
  host-materialization, or public-internet authority.
- Every cell requires a new production-equivalent microVM. Hostile objects may be materialized
  only inside that guest. Provider and qualification-runtime signatures, zero prohibited effects,
  phase-bound zero egress, and complete destruction evidence within 60 seconds are mandatory.
- Repository validation never launches a scanner or microVM and cannot produce a passing T053
  verdict. Until a live dependency set, dual plan approvals, and 123 valid dual-signed receipts
  exist, the only valid aggregate state is `PENDING_PROVIDER_EXECUTION`.
- The verifier derives evaluation time only from its service-owned trusted UTC clock and rejects
  caller time overrides. Both detached plan approvals must strictly precede the earliest cell start.
- A T053 pass grants entry to T054 only. It never grants finding, policy, publication, rollout,
  Kubernetes, or production-readiness authority.

Manifest: `sha256:dda19ac6bd431dd3a6b0be1d52b17942dc01c0e57c3c71f06521c8c07718ffe4`
Source snapshot: `sha256:8daee3b29765ff85f74819acec75f2bb803ba423585af6b4d12c3803e5460f92`

Do not hand-edit generated assets. Change the reviewed generator, increment the immutable
revision, regenerate, and run `corepack pnpm qualification:validate`.
