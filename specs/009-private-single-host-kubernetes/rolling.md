# Signed native RollingUpdate and Git image recovery, issue365

Before importing the next image, retain exactly the currently active separately
approved release plus the new verified release. Existing admitted images retain
restart continuity; this is not a new freshness waiver for a normal promotion.
The root promotion path must validate target signature/scan freshness before
changing immutable Git desired release state. Preserve no more than two image
pairs; derive metric source labels from this protected image map, not Pod labels.

Put non-secret release digest/source and reviewed private ingress values in Git.
Root selects an exact Git commit; Argo may reconcile the app but cannot change
its own Application spec. Install a native admission policy enforcing that bound.
Operator ConfigMaps, EndpointSlices, HPA replicas, credentials and scanner remain
outside chart ownership. No registry, new compute or AWS permissions.

First adopt the current release values without replacing healthy Pods. Then
promote the CI-signed shared-throttle candidate via actual Deployment RollingUpdate,
maxSurge1/maxUnavailable0, preserving API HPA1-2/maximum3 and old web/data.
Verify the real owner session/results/evidence and shared throttling on both
API replicas using bounded requests, without a synthetic session/new scan.

A deliberately non-ready probe configuration in a separately reviewed Git commit
can verify bad-candidate exclusion. It must keep the old Ready replica serving,
and the promotion verifier must automatically restore the prior Git revision on
failure. Observe actual rollout, health, replicas and Git/image recovery. Do not
count this as Blue/Green/Canary or general qualification.

Actual2026-11-10: normal rollout16.988s, non-ready candidate exclusion and automatic
Git recovery55.125s. First old-image recovery exposed kubelet GC removing unused
approved images; the promoter restored the working version. image_retention.py
restores missing archives only after fresh trusted H3 verification and pins the
current/previous pairs with io.cri-containerd.pinned plus a separate operator label.
It intentionally does not use K3s vendor-owned pin labels (K3s clears those on boot).
Native CRI must return pinned=true; labels alone are insufficient. Admission
retains at most two approved release pairs; only older operator-owned pins may
be removed, without deleting image data or changing vendor/scanner images.
Promotion checks actual presence/pinning before Git mutation. After this repair,
actual previous-image rollback10.074s and current-image promotion10.023s passed,
all observed health200. Existing owner session, data/evidence and original HTML
were verified on the final3ed source. G3 closes only for this approved scope.
Reference: https://github.com/k3s-io/k3s/blob/v1.37.2%2Bk3s1/pkg/agent/containerd/containerd.go
