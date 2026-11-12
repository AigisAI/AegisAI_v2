# AegisAI

**Private security scanning for GitHub organization repositories.**

AegisAI analyzes Java repositories at a specified commit and lets authorized users
review findings and encrypted evidence. The verified deployment runs on one AWS EC2
instance with private HTTPS access through Tailscale.

## Architecture

- **Access and API.** K3s runs the web and API workloads. Separate GitHub Apps handle
  user sign-in and organization repository access.
- **Scan isolation.** A separate containerd/gVisor runtime runs Opengrep, Trivy, and
  Syft. Repository access is scoped to the scan, and temporary source is removed
  after the job.
- **Results and evidence.** PostgreSQL stores tenant-scoped results, Redis backs
  shared sessions and request limits, and S3 stores KMS-encrypted evidence.

[Verified scan and release](https://github.com/AigisAI/AegisAI_v2/blob/f4aef9ee6755f6ef738b4723398267b7d4d18726/docs/production/scan-tracing-release.md)

## Deployment and autoscaling

The default API uses **Kubernetes RollingUpdate with an HPA of 1–2 replicas**.
RollingUpdate controls how a release replaces Pods. The HPA adjusts the API replica
count based on load.

| Mode | How AegisAI used it | Evidence |
| --- | --- | --- |
| **RollingUpdate** | Default deployment strategy. Readiness kept an unhealthy candidate out of traffic, and rollback to the previous image was verified. | [RollingUpdate and HPA](https://github.com/AigisAI/AegisAI_v2/blob/f4aef9ee6755f6ef738b4723398267b7d4d18726/docs/production/2026-11-10-rollout-scaling-checkpoint.md) |
| **HPA** | Default API autoscaling. CPU load drove the API from one replica to two and back to one. | [RollingUpdate and HPA](https://github.com/AigisAI/AegisAI_v2/blob/f4aef9ee6755f6ef738b4723398267b7d4d18726/docs/production/2026-11-10-rollout-scaling-checkpoint.md) |
| **Blue/Green** | Verified separately on the private API with Argo Rollouts. Switched traffic between the active and preview versions and verified the return to the original version. | [Blue/Green verification](https://github.com/AigisAI/AegisAI_v2/blob/f4aef9ee6755f6ef738b4723398267b7d4d18726/docs/production/2026-11-10-blue-green-checkpoint.md) |
| **Canary** | Verified separately on the private API with Argo Rollouts. Prometheus detected candidate errors, and traffic returned to the stable version **17.2 seconds after the failure decision**. | [Canary verification](https://github.com/AigisAI/AegisAI_v2/blob/f4aef9ee6755f6ef738b4723398267b7d4d18726/docs/production/2026-11-10-canary-checkpoint.md) |

After each Blue/Green and Canary exercise, the service returned to the default
RollingUpdate path and the API HPA returned to its 1–2 replica range.

## Verified operations

| Area | What was verified |
| --- | --- |
| **Release delivery** | GitHub Actions verified the signed images. The same release commit passed AWS OIDC verification before Argo CD promoted the images. [Release evidence](https://github.com/AigisAI/AegisAI_v2/blob/f4aef9ee6755f6ef738b4723398267b7d4d18726/docs/production/aws-control-backup-delivery-gate.md) |
| **Scan observability** | Tempo traces connected API requests, queued work, and scanner outcomes. Matching Loki logs identified the failure stage for a rejected scan. [Successful and failed scan traces](https://github.com/AigisAI/AegisAI_v2/blob/f4aef9ee6755f6ef738b4723398267b7d4d18726/docs/production/scan-tracing-release.md) |
| **Infrastructure and recovery** | Terraform imported existing AWS resources and verified a no-change plan. An encrypted S3 backup restored the K3s control state in an isolated API. [Terraform and recovery evidence](https://github.com/AigisAI/AegisAI_v2/blob/f4aef9ee6755f6ef738b4723398267b7d4d18726/docs/production/aws-control-backup-delivery-gate.md) |

## Local Development

Requirements:

| Requirement | Version / Note |
| --- | --- |
| Node.js | `>=20.0.0 <23.0.0` |
| Package manager | Corepack-enabled pnpm workspace, currently `pnpm@10.0.0` |
| Runtime services | PostgreSQL and Redis when exercising paths that need them |

Install dependencies:

```powershell
corepack enable
corepack pnpm install
```

Run development servers:

```powershell
corepack pnpm dev
corepack pnpm dev:api
corepack pnpm dev:web
```

Prisma helpers:

```powershell
corepack pnpm --filter @aegisai/api prisma:generate
corepack pnpm --filter @aegisai/api prisma:validate
corepack pnpm --filter @aegisai/api prisma:migrate:dev
```

Environment examples:

| File | Use |
| --- | --- |
| [`.env.example`](./.env.example) | Root application defaults |
| [`apps/web/.env.example`](./apps/web/.env.example) | Web runtime defaults |
| [`deploy/oracle/.env.example`](./deploy/oracle/.env.example) | Oracle VPS dev/demo deployment defaults |

For repository conventions, see [AGENTS.md](./AGENTS.md), the
[architecture quickstart](./specs/002-production-scan-architecture/quickstart.md),
and [GitHub conventions](./docs/github-conventions.md).
