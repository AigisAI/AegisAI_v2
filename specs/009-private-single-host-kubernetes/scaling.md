# Actual bounded API scaling, issue361

Keep one existing host, current signed API/web, original UI, persistent data and
independent one-scan supervisor. Scale API only1-2, surge ceiling3. This is not
host HA or node autoscaling. Argo must ignore/respect API spec.replicas before
the HPA starts; root owns the HPA and system metrics configuration.

Use the already vendor-checksummed K3s airgap metrics-server0.9.0 image by its
installed digest. Maximum64MiB/200mCPU, non-root restricted Pod, no hostPath,
read-only root, bounded tmp. Only Kubernetes API and this node's TLS kubelet
are reachable. Verify kubelet against existing public server CA; sign a bounded
service certificate with root's existing private control CA and set APIService
caBundle. No insecure kubelet TLS flag or aggregate certificate skip. Root creates
only the encrypted-control-store TLS Secret. No AWS secret/privilege change.

HPA uses actual CPU resource metrics, min1/max2, bounded scale-up/down rates and
stabilization. One rate/concurrency/time-bounded stream of real HTTP requests may
demonstrate1->2. Do not fake metrics, consume customer code, create scans or alter
production records. Stop load and verify2->1; interrupt only the metrics collector
briefly to prove missing metrics never scale to zero or bypass the max. Restore
collector in finally, then verify health, signed replicas and existing counts.

Evidence must contain actual replicas, CPU/conditions, request count/rate/errors,
timings and preserved service/data limits. If the workload does not cross the real
threshold, record that outcome and investigate; do not label config-only HPA done.

References checked2026-11-10:
- https://github.com/k3s-io/k3s/tree/v1.37.2%2Bk3s1/manifests/metrics-server
- https://github.com/kubernetes-sigs/metrics-server/tree/v0.9.0/manifests/base
- https://kubernetes.io/docs/concepts/workloads/autoscaling/horizontal-pod-autoscale/
