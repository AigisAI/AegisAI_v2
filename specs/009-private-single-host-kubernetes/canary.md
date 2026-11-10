# Measured private Canary, issue369

Enter canonical002/private003 and integrated006/008/009 first. Keep the one-host
scope, independent gVisor/data boundary, optional AI, source verification and
unpassed general qualification. Read blue-green.md and its actual checkpoint.

Use signed current3ed/previousf340 API versions, each at most1 during this bounded
profile. Freeze only fallback Deployment HPAmax1 and retain it Ready; totalAPI3,
web2. Original ingress and HPA1..2 recover independently before strategy Pods stop.
No app code/schema/scan/data restore or AWS resources/permissions change.

Pin official Traefik Docker3.7.17 amd64 digest and matching TraefikService CRD
hash.3.7.18 is a newer upstream release but its official Docker tag was not yet
published when selected. Do not claim3.7.17 is the latest upstream release. Disable
Kubernetes/Docker discovery, plugins, telemetry, compression, auth middleware,
public listeners and ACME. The internal router has no API/SCM/AWS token, uses
restricted PodSecurity, read-only filesystem and96MiB/250m limits.

Rollouts changes only the named TraefikService weighted stable/candidate pair.
A root publisher validates that exact service/port/weight tuple, observes it with
the existing root kubeconfig, and projects a bounded non-secret Traefik file
configuration through a read-only ConfigMap. It may not select arbitrary URLs,
templates or secrets. Traefik watches that directory. This explicit adapter avoids
giving the router Kubernetes discovery/Secret privileges. Root owns the projection;
Rollouts owns weights/selectors; the existing Argo Deployment profile stays intact.
Actual loaded router weights, ready EndpointSlices/image refs and child-service
request counters must agree before a phase is counted.

Before execution, use three stages10%,50%,100%,60 real read-only health requests
per measured stage at at most2RPS, one client and5s timeout. Observe the actual
stable/candidate counter deltas;60 requests must account exactly, distribution
must differ from target by no more than10 percentage points, statuses all200,
and measured p95 no more than1second. Report controlled requests separately from
normal user traffic; this is not a throughput benchmark. Preserve original HTML
and the real owner session. Avoid synthetic sessions or unbounded source labels.

After each paused weight, collect actual Prometheus router counters/histograms.
Native AnalysisRun must require real candidate samples>=3, 5xx ratio<=1%, p95<=1s.
Use exact finite baseline counters to distinguish fresh candidate traffic from
prior measurements; missing/error/NaN metrics cannot approve. Root resumes the
pause only after actual routing/count checks; native analysis gates progression.

For one bounded failure, keep the candidate Pod Ready but point its Service only
to a deliberately closed container port. Generate the same limited requests.
The router must produce real candidate502s, Prometheus must observe them, and a
native failed AnalysisRun must automatically abort Rollouts and set weights100/0.
Verify real subsequent requests reach the unchanged stable version. Restore the
candidate port and original ingress/HPA in finally and an independent timer.
Readiness failure, manual-only abort, fake metrics or config files cannot closeG2.

Primary references reviewed2026-11-10:
- https://argoproj.github.io/argo-rollouts/features/traffic-management/traefik/
- https://argoproj.github.io/argo-rollouts/analysis/prometheus/
- https://doc.traefik.io/traefik/reference/install-configuration/providers/others/file/
- https://doc.traefik.io/traefik/reference/routing-configuration/http/load-balancing/service/
- https://github.com/docker-library/official-images/blob/master/library/traefik
