# Isolated deterministic scanner image

Vendor binaries are pinned by release and SHA-256 from their official GitHub
release assets. Package installation here builds our own trusted scanner image;
customer repositories must never be built, executed or have packages installed.

Use the statically linked `opengrep-core` release, not the self-extracting one-file
CLI. The latter failed the no-exec temporary-filesystem fixture. Keeping the
scanner executable in the read-only image preserves no-exec temporary storage.

Run only through the dedicated gVisor runtime with a unique sandbox, no network,
non-root UID, no capabilities, read-only root/input, bounded ephemeral output/temp
storage, CPU/memory/process/time limits and cleanup verification. Never mount a
Docker/containerd socket or SCM/IAM credentials in the parsing environment.

The included Java rules are a transparent initial ruleset. They do not assert
complete Java security coverage or a vulnerability-free repository. Trivy's offline
database readiness and every scanner's execution/coverage state must be reported;
missing databases, unsupported languages, parser errors and timeouts must not be
reported as successful clean coverage. AI cannot create authoritative findings.

The image alone is not a worker or release acceptance. Its native scanner execution,
output bounds/redaction, orchestration, repository fetch/revocation, durable results,
policy, UI and operating-scope review remain separate checks.

Target acceptance now passed using `verify-scanner-tools.py`: three synthetic Java
positives, a safe negative, declared dependency SBOM, cold-DB explicit failure and
offline Log4Shell detection with a current vendor DB. This is fixture acceptance,
not comprehensive language/dependency coverage. `refresh-vulnerability-db.py`
fetches only the public vendor artifact, verifies its OCI layer digest, bounds
download/expansion and rejects stale metadata. A scheduled refresh/capacity policy
and per-scan freshness enforcement are still required before launch.

`runtime.py` is the host supervisor execution library, not an activated consumer.
`verify-runtime.py` exercises trusted synthetic inputs on the target gVisor host:
all three tools, immutable image/no pulls, scan-owned no-exec tmpfs, forced timeout,
output flood and verified container/storage cleanup. Invoke it only as an operator
after installing the reviewed image alias and vendor DB. It must never be pointed
at an uploaded/local customer directory. Gateway, queue delivery, fencing, results
and the remaining release gates are still unfinished.

`github_fetch.py` is the trusted gateway's bounded immutable-object helper. Its
caller must supply an authenticated authority recheck before every source request.
`verify-fetch.py` passed synthetic-provider checks against actual scan-owned tmpfs,
including scope/hash/size/path failures, single-use behavior, expiry, authority loss
and credential revocation on storage/provider failures. This is not live GitHub
fetch acceptance and does not activate repository processing.
