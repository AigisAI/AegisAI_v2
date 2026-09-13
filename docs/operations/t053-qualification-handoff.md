# T053 external qualification handoff

The next execution step is a real production-equivalent microVM qualification run.
Repository implementation and ordinary CI do not establish that the provider is ready.
As of 2026-09-08, the project owner confirmed that the test server and signing/approval
materials are not prepared. Track preparation and execution in
[issue #317](https://github.com/AigisAI/AegisAI_v2/issues/317).

Read the [006 quickstart](../../specs/006-production-sast-runtime-design/quickstart.md)
in its required order after [reconciling the checkout](../resuming-development.md).
This handoff indexes the existing contract; it grants no provider, deployment, or
production-readiness authority.

## Current execution boundary

| Stage | Repository package | Required external result | Status before provider execution |
| --- | --- | --- | --- |
| T053 | 123 case/profile cells and offline verifier | Fresh microVM for each cell, two receipt signatures, complete destruction evidence | `PENDING_PROVIDER_EXECUTION` |
| T054 | 3,462 end-to-end cells and offline verifier | Exact signed T053 pass, same-provider end-to-end and performance receipts | `BLOCKED_T053_QUALIFICATION` |
| T055 | 169 supply-chain and rollback cells | Exact signed T054 pass and same-provider signed drills | `BLOCKED_T054_QUALIFICATION` |
| T056 | 54 mandatory gates and immutable decision verifier | Exact signed upstream chain, six evidence categories, independent approvals | `BLOCKED_T055_QUALIFICATION` |
| 005 entry | T056-bound preflight and handoff | Fresh current-contract `GO` and Qualification Authority deployment-entry attestation | Unavailable without verified entry evidence |

T053-T056 stay unchecked in the active task list until their real evidence passes.
`GO` permits only entry to the separately authorized 005 operations workflow. It is not
Kubernetes execution, deployment completion, or production readiness.

## Inputs to prepare

| Input | Responsible role | Required handoff |
| --- | --- | --- |
| Qualification environment | Scan Platform and microVM provider | Named standalone/staging provider, adapter, production-equivalent isolation and audit/cleanup capabilities |
| Immutable dependencies | Scan Platform and supply-chain owners | Digest/signature/provenance-bound scanner set, images, wrappers, rules, database, schemas, normalizers, materializer, runner, harness, kernel/rootfs, provider and trust policy |
| Trust bundle | Approved signing authorities | Canonical Ed25519 public keys for Security Engineering, Scan Platform, microVM provider, and qualification runtime; raw bundle digest bound to dependency `TRUST_POLICY` |
| Execution plan | Qualification operator | Plan generated from the checked-in package and exact external dependency set; record commit, plan and dependency digests |
| Detached approvals | Security Engineering and Scan Platform | Both signatures over that plan, strictly before the earliest execution start |
| Execution receipts | MicroVM provider and qualification runtime | Exactly 123 unique cell receipts with both signatures, observed outcomes, phase egress, prohibited-effect counters, and complete cleanup evidence |

The dependency set is valid for at most 24 hours. Prepare assets first, then coordinate
plan approval and execution within the approved validity window. Private keys, provider
credentials, kubeconfigs, and customer source do not belong in GitHub issues or this
repository. Record approved locations and content digests instead.

The provider uses only platform-owned qualification fixtures. Each cell gets a fresh
microVM; each receipt must prove credential wipe, process-tree termination, writable-volume
destruction, result-ingress closure, microVM termination, and final audit commitment within
60 seconds of cleanup start. Do not substitute a development container or fabricate
observations to make the verifier pass.

## Repository preparation and offline verification

Use the validated issue branch, install workspace dependencies as described by the main
README, and run the full [006 validation path](../../specs/006-production-sast-runtime-design/quickstart.md#validation-commands).
Database validation and the rollback probe use a disposable PostgreSQL 16 database.
Record the commit and CI run; neither is a provider receipt.

The package-only check requires no external server:

```powershell
corepack pnpm qualification:validate
```

Its successful exit means the repository packages are valid while external qualification
remains pending/blocked. The separate T053 evidence verifier can demonstrate that boundary:

```powershell
node tools/sast-qualification/verify-isolated-integration-evidence.mjs
```

With no external inputs, expect `PENDING_PROVIDER_EXECUTION` and exit code **2**, not a
passing qualification result. Exit **0** is reserved for complete valid external evidence;
exit **1** indicates failure. Do not catch code 2 and relabel it as a T053 pass.

After the external dependency set is prepared, generate the plan using
`tools/sast-qualification/generate-isolated-integration-plan.mjs --dependency-set` with
its file path. The command writes JSON to stdout and does not execute the provider.
Preserve that exact output using UTF-8 without a BOM; do not alter or regenerate the
plan after its detached approvals are signed.

After approved external execution, invoke
`tools/sast-qualification/verify-isolated-integration-evidence.mjs` with **all five**
file arguments: `--dependency-set`, `--plan`, `--approvals`, `--receipts`, and
`--trust-bundle`. Partial argument sets are rejected. The verifier owns its UTC evaluation
clock; no caller-selected timestamp is accepted. Retain the immutable verifier result and
the digests of its exact inputs in the approved evidence store.

Only a real verified T053 pass allows the exact same-provider T054 chain to begin.
Continue through T055 and T056 using the existing generators/verifiers under
`tools/sast-qualification/`; do not skip upstream gates. For detailed schemas and
thresholds, follow the [runtime contract](../../specs/006-production-sast-runtime-design/contracts/sast-runtime.md#isolated-integration-qualification-v1)
and [quality gates](../../specs/006-production-sast-runtime-design/quality-gates.md#t053-production-equivalent-isolated-integration-gates).

## Record when resuming

Update issue #317 with the selected provider and responsible operator, approved evidence
locations, immutable repository/dependency/plan identities, approval readiness, intended
execution window, and current missing inputs. Keep receipt and result references bound to
the exact run. Mark a stage complete only after its verifier accepts actual external
evidence; keep the remaining stages and production rollout explicitly pending.
