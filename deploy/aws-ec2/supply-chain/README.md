# Signed private deployment images

H3 targets the private API/web images. Customer repository analysis remains in the
separate containerd/gVisor scanner and is never run in CI/app containers.

CI builds exact pinned Node22/NGINX bases, scans the actual saved image archives
with checksum-pinned Trivy0.76.2, converts the same complete reports to CycloneDX,
and rejects HIGH/CRITICAL/UNKNOWN findings including unfixed entries. No ignore
file/waiver is allowed; supported OS, actual OS/API language package coverage,
48h DB freshness and 24h scan age are required. Report config digests must match
the actual image archive and its source label. Runtime keeps patched pnpm10.34.9
for the existing offline migration ABI; unused npm/npx are removed. Express/Joi
and compatible nested dependencies are patched without changing app features.

Commit-pinned GitHub Actions/attest signs the candidate+image files with SLSA
build provenance and each image SBOM with CycloneDX attestations. Only the private
candidate job receives OIDC/attestation write permissions; fork PRs issue no
candidate. No deployment credentials/customer repositories enter the build.
Primary image artifacts retain3days as before; small signed security records
retain90days. The live encrypted host retains installed candidates/rollback data.

`verify_candidate.py` uses the checksum-verified GitHubCLI2.103.3 with local
bundles and vendor trusted roots, without GitHub user credentials. Enforce exact
repository/workflow, OIDC issuer, GitHub-hosted runner and separately approved
source+signer SHA. The candidate cannot install its verifier or grant itself
trust. Actual CI tests verify good signatures and reject changed subjects,
wrong source, altered signatures and missing SBOM bundles. Local policy tests
cover vulnerabilities, EOL/coverage, stale DB, SBOM and hostile JSON.

Production entry is the reviewed root-owned source tree's
`deploy_signed_candidate.py <dir> --manifest-sha256 <sha> --approved-source <sha>`.
Default verifies only; `--apply` admits the verified candidate to the existing
private deployment flow. It verifies before image load, ingress pause or SQL.
Install the reviewed operator tree separately, preserving its repository layout,
and point `/opt/aegisai/operator/supply-chain/current` to it. Never install this
verifier by executing an incoming candidate's code.

Bootstrap: verify and deploy the first signed release while the current known
release remains available for recovery. Only after health/read/telemetry accepts
it, enable root-only `supply-chain-required.json` with reviewed approvedSources.
Thereafter direct current deploy helper invocation also requires a root-owned
fresh verification receipt; no unsigned fallback is permitted. Arbitrary host
root/Docker administrator actions are outside this deployment-entry trust model.
Keep prior assets; do not relabel unsigned legacy builds as signed/approved.

Before calling H3 complete, exercise real host reject paths with unchanged live
state and record active policy + signed running image proof. No new real customer
scan or unchanged DB restore is needed. H1 reproduction, H4 deep worker tracing,
external Kubernetes qualification and G1-G4 remain separate and incomplete.
