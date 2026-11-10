# Restricted catalog projection, issue354

Do not weaken restricted PodSecurity or expose a host directory/socket. The API
currently rejects symlinks, while Kubernetes ConfigMap volumes use atomic-writer
symlinks. Add an explicit opt-in projected mode: accept only current.json ->
..data/current.json -> one contained timestamp directory/current.json, with
root-owned non-writable parent/directory/file checks and O_NOFOLLOW/fstat on the
final regular file. Regular mode continues to reject all symlinks. Preserve the
4096-byte,60-second freshness, schema and fail-closed scanner-ready checks.

Actual kubelet volume roots are mode0777 even when read-only. For projected mode,
require a unique exact /run/aegisai-runtime read-only per-mount entry in bounded
/proc/self/mountinfo; directory mode alone cannot prove write authority. Root
ownership, contained pointers, non-writable timestamp directory/final regular file
and no-follow/fstat remain required. Verify both actual ro and rw mounts as UID1000
in CI, not only a root-owned ordinary-directory fixture. Kernel mount format:
https://www.kernel.org/doc/html/latest/filesystems/proc.html

A root-only bounded publisher reads only the existing root-authored catalog,
selects non-secret status fields and preserves its original timestamp. It updates
one named ConfigMap; it cannot turn stale source into fresh/ready data. Pods get
only a read-only ConfigMap, no hostPath or Kubernetes API credential. Keep the
native worker/source bundle unchanged. To fit the existing60-second freshness
bound, use watched projection with10-second kubelet sync and5-second publication.
Record actual propagation; publisher/control failure must close new admission.

Validate actual native root-owned projection, default symlink denial, escape/
non-root/writable target rejection, rotation and stale fail-closed behavior in
the disposable Linux verification image. Run full existing private/canonical CI
and H3 image signatures after this API change. This phase does not switch traffic
or itself satisfy GitOps, rollout/scaling, deep scan traces or reconstruction.

Reference: https://kubernetes.io/docs/concepts/configuration/configmap/
