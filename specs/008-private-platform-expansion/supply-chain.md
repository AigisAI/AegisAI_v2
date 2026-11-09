# H3 private API/web deployment supply chain

The owner made deployment-image vulnerability checks, SBOM, provenance, signature
verification and actual reject proof mandatory. This phase targets API/web images,
not customer repository scanners. Keep the running service until its replacement
passes. Existing EC2/public GitHub Actions only; no registry, compute, runtime IAM
expansion or secret transfer. GitHub repository visibility was checked as PUBLIC.

Use exact vendor-checksummed Trivy and GitHub CLI, a commit-pinned actions/attest,
and GitHub-hosted CI OIDC. Public build metadata may enter the standard public
Sigstore transparency log; no runtime/customer source or credentials enter CI.
Build provenance/SBOM bundles and scan reports accompany the immutable candidate.
Bind compressed image archive hashes through the manifest to OCI image/config
IDs using the existing content-addressed checker. No hash-only substitution for
signature verification. SBOM is CycloneDX and must contain actual components.

Policy initially has no waivers: reject known HIGH/CRITICAL vulnerabilities,
unsupported/empty scan results, malformed or stale vulnerability DB metadata,
missing/empty SBOM and missing/mismatched/tampered signed artifacts. Reports retain
all severities. Do not silently use ignore-unfixed or an ignore file. Any later
exception needs a documented reason, exact scope, approver and expiry.

Trusted host verification runs before image load, ingress pause or migration.
The verifier is installed from reviewed operator source, not executed from an
unverified bundle. Exact repository, signer workflow, GitHub-hosted runner and
separately operator-approved source/signer commit must match cryptographic claims.
Candidate contents cannot grant themselves trust. Offline signature bundles let
the host verify without a GitHub user/token; use vendor trusted roots, never roots
supplied by the candidate. Do not allow unsigned fallback or relaxed replacement
on scanner/signature failure. Keep previous runtime/data/recovery assets.

Validate meaningful negative cases and at least actual cryptographic rejection;
record unchanged live state for rejected candidates. Then apply the verified
signed release with targeted app health/read/telemetry checks, without rerunning
unchanged real scans or DB restores. H3 does not complete H1 reconstruction, H4
worker correlation, external Kubernetes qualification, GitOps or rollout/scaling.
