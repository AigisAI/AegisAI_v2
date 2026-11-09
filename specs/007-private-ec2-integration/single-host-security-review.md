# Same-host private operating profile: implementation review

This records the constrained design review, not independent certification or
acceptance of every release gate. The user's explicit single-EC2 decision replaces
the initial topology for this private deployment only. The DOCX separate-node
baseline remains the target for general multi-tenant service.

## Permitted scope

- Admit only GitHub account 161540124; derive its tenant from verified OAuth.
- Bind only selected repositories in organization 241095585 after live active
  administrator verification. Reject other principals and organizations in worker
  admission even if an installation exists.
- One actual scan at a time on this 2-vCPU/8-GB host. Dispatch library capacity is
  not permission to start two heavy workers. No public onboarding or webhook intake.
- Initially support the documented deterministic Java rules and dependency metadata.
  Unsupported profiles and missing coverage fail visibly. AI remains unavailable.
- Never execute repository scripts, Maven/Gradle, tests or package installation.

## Boundaries and residual risks

The application uses Docker; scanning uses a separate root-only containerd socket,
state/root paths and gVisor runtime. A sandbox gets no application socket, host
credentials, AWS metadata, network or source-write authority. Source and output
must be per-scan bounded ephemeral storage. Credentials must be removed before
parsing. Fixed trusted binaries/rules are distinct from repository contents.

gVisor reduces direct host syscall exposure but shares host hardware, host kernel
and a privileged runtime manager. A runtime/host compromise can affect both planes.
Host failure or resource pressure affects application and scans together. This
profile cannot claim separate-node isolation or high availability. Resource and
timeout caps, admission limits and fail-closed cleanup are necessary mitigations;
they do not remove these residual risks.

## Verified evidence and open conditions

Verified: private Tailscale-only ingress, zero public inbound security-group rules,
numeric login admission and actual persisted OAuth identity; organization discovery
and discovery-token revocation; trusted gVisor fixture with non-root UID, no network,
read-only root, capability removal, no-new-privileges, CPU/memory/PID limits and
inaccessible metadata/control service/sockets. Vendor scanner image built from
pinned binary checksums. On 2026-11-08, the authorized selected private Java
repository completed three real tools with LIMITED coverage; the owner confirmed
the persisted result in the actual private UI. Source/sandbox cleanup, managed
secret reboot and encrypted offsite restore passed. See the current checkpoint.

Before repository input, also require: encrypted root verification; real scanner
positive/negative tests; immutable bounded source fetch; broker lease/revocation;
per-scan tmpfs/output/timeout limits; worker fencing/reconciliation; cleanup under
timeout/crash; restricted-profile rejection; output normalization/redaction; durable
coverage and results. Expose the UI only after evidence/policy, restart/backup and
end-to-end acceptance pass. No ordinary runc fallback is allowed.

Evidence paths, accepted private gates and broader follow-up are recorded in
tasks.md and the AWS deployment checkpoint. This review does not certify the
broader separate-node/general-service baseline.
