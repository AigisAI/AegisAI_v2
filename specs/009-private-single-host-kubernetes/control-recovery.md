# Private control state recovery

Read the latest production recovery checkpoint before operating this path.
Use an existing root-protected SQLite backup and its matching server token.
Run `control_recovery.py rehearse <absolute backup directory>` from a
hash-verified operator source directory. The script checks the live revision,
image pair, scanner readiness and host capacity before it copies the backup.

The restored K3s API runs briefly in a separate network namespace with a
loopback listener, an independent data directory and a bounded systemd unit.
Agent, scheduler and controller manager are disabled. The production K3s data,
kubeconfig and container runtime sockets are inaccessible to the trial. Query
the restored API for the Argo revision, both Deployment image references, the
inactive strategy profiles and the type of one encrypted Secret. Store logs
under the protected rehearsal directory. The script stops the unit and removes
the trial database, token and generated kubeconfig.

Use `dns_limits.py install` to install and start the root timer. The helper
reconciles CoreDNS to 50m/32Mi requests and 200m/64Mi limits and waits for the
replacement to be Ready with `maxUnavailable: 0`. The timer runs after boot
and once per minute. K3s retains the packaged manifest and its other settings.

This procedure verifies restoration of the Kubernetes control state in a
separate API on the existing host. H1 still tracks off-host Kubernetes recovery,
host reconstruction, Terraform resource coverage and actual cost.

Primary references

- [K3s SQLite backup and restore](https://docs.k3s.io/datastore/backup-restore)
- [K3s packaged components](https://docs.k3s.io/installation/packaged-components)
