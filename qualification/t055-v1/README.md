# T055 Supply-Chain and Rollback Qualification v1

This immutable handoff defines exactly 169 production-equivalent drills before final go/no-go:
144 artifact mount/digest/signature/provenance drills over all 36 T054 artifacts, one unlisted
component rejection, six internal vulnerability-database drills, three result-schema drills, and
15 ordered rollback drills across the three scanner profiles.

- T055 cannot issue a plan until the exact T054 manifest, PASSED result, dependency set, complete
  per-artifact verification set, and execution plan are rebound by a Qualification Authority
  Ed25519 entry attestation. Provider qualification cannot be transferred.
- The trust bundle is independently pinned by `SAST_T055_TRUST_POLICY_DIGEST`. Every T054
  artifact signature and provenance envelope is reloaded and verified before T055 evidence is
  accepted.
- Positive artifact drills require a read-only mount, exact mount rehash, exact signature and
  provenance envelope digests, successful verification, and allowlist admission. Each negative
  drill isolates digest, signature, provenance, allowlist, stale DB, network, or schema rejection
  before artifact invocation or external egress.
- Rollback evidence is ordered per profile: suspend candidate, fence queue admission, abort and
  clean in-flight work, derive and reverify the exact last-known-good release set, then activate
  that baseline through a digest-chained append-only audit entry.
- Detached Security Engineering and Scan Platform approvals must strictly predate execution.
  Supply Chain Authority, MicroVM Provider, and Qualification Runtime signatures are required on
  every receipt. Attempt, sandbox, workload, attestation, audit, receipt, and cell identities are
  globally single-use.
- Repository validation executes no scanner, customer code, package installation, repository
  build, dynamic test, provider workload, network request, Kubernetes action, or production
  mutation. Without external T054 and drill evidence it remains
  `BLOCKED_T054_QUALIFICATION`.
- A complete pass authorizes entry to T056 only. It grants no finding, policy, publication,
  deployment, Kubernetes, or production-readiness authority.

Manifest: `sha256:cb4b009f58577ed1dd43472bb4579b8927a6327c5fa8ef9a4429e1b5c2b39f0f`
T054 manifest: `sha256:fdbede0e8361b739988770f9ecc53b22afd2d6b9e44a4e3659c6d1bd6147a4c4`
Drill policy: `sha256:289a9b5abcdd7cd559b0871d5cff7b0d1876e3c74f0201c065dedd370b166a2b`

Do not hand-edit generated assets. Change the reviewed generator, increment the immutable
revision, regenerate, and run `corepack pnpm qualification:validate`.
