import { createHash, randomBytes, randomUUID } from "node:crypto";
import { BadRequestException, ConflictException, ForbiddenException } from "@nestjs/common";
import type { Prisma } from "@aegisai/private-runtime-db";
import type {
  FetchCapabilityIssue, FetchGatewayClaim, FetchGatewayCompletion, FetchGatewayOutcome, ScanDispatchLease
} from "@aegisai/shared/private-runtime";
import { ConfigService } from "../config/config.service";
import { PrismaService } from "../prisma/prisma.service";
import { serializable } from "../prisma/transaction";

const BROKER_ID = "private-single-host";
const OPEN = ["ISSUED", "CONSUMING"] as ("ISSUED" | "CONSUMING")[];
const activeScan = { status: { in: ["QUEUED", "PLANNING"] as ("QUEUED" | "PLANNING")[] },
  isolationClass: "STANDARD" as const,
  tenant: { status: "ACTIVE" as const }, repositoryBinding: { integration: { status: "ACTIVE" as const } } };
const hash = (kind: string, value: string) => createHash("sha256").update(`${kind}:${value}`).digest("hex");
const secret = () => randomBytes(32).toString("base64url");
function lost(): ConflictException {
  return new ConflictException({ errorCode: "FETCH_AUTHORITY_LOST", message: "Fetch authority is expired or no longer owned." });
}
async function now(tx: Prisma.TransactionClient): Promise<Date> {
  return (await tx.$queryRaw<{ now: Date }[]>`SELECT clock_timestamp() AS now`)[0].now;
}
function validSecret(value: string): boolean {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

/** Durable private capability library only. No routes, timers, provider token or startup activation. */
export class FetchCapabilityService {
  private epoch?: string;
  private readonly admitted: Map<string,string>;
  constructor(private readonly prisma: PrismaService, config: ConfigService) {
    const ids = (config.getOptional("ALLOWED_GITHUB_USER_IDS") || "").split(",");
    if (!ids.length || ids.some((id) => !/^[1-9][0-9]*$/.test(id))) {
      throw new BadRequestException("Explicit private account admission is required");
    }
    this.admitted = new Map(ids.map((id) => [
      `tenant_${createHash("sha256").update(`github:${id}`).digest("hex").slice(0,32)}`, id
    ]));
  }

  admittedTenantIds(): string[] { return [...this.admitted.keys()]; }

  /** Root supervisor result authority, only after independently confirmed fetch. */
  async requireHandoff(tx: Prisma.TransactionClient, lease: ScanDispatchLease, credentialId: string, starting: boolean) {
    await this.authority(tx,lease.tenantId);
    const timestamp=await now(tx);
    const capability=await tx.scanFetchCapability.findFirst({where:{
      id:credentialId,tenantId:lease.tenantId,scanRequestId:lease.scanRequestId,dispatchJobId:lease.jobId,
      issuerEpoch:this.epoch,status:"CONSUMED",leaseFingerprint:hash("lease",lease.leaseToken),
      ...(starting?{expiresAt:{gt:timestamp}}:{}),
      dispatchJob:{status:"LEASED",leaseToken:lease.leaseToken,leaseExpiresAt:{gt:timestamp},
        scanRequest:{status:{in:starting?["PLANNING","RUNNING"]:["RUNNING"]},isolationClass:"STANDARD",
          tenant:{status:"ACTIVE"},repositoryBinding:{integration:{status:"ACTIVE"}}}}
    },include:{dispatchJob:{include:{scanRequest:true}}}});
    if(!capability) throw lost();
    return {scan:capability.dispatchJob.scanRequest,timestamp};
  }

  async healthy(): Promise<boolean> {
    return !!this.epoch && (await this.prisma.scanBrokerRuntime.findUnique({where:{id:BROKER_ID}}))?.epoch===this.epoch;
  }

  private async authority(tx: Prisma.TransactionClient, tenantId: string): Promise<void> {
    if (!this.admitted.has(tenantId)) throw new ForbiddenException("Tenant is not admitted to this private runtime");
    const state = await tx.scanBrokerRuntime.findUnique({ where: { id: BROKER_ID } });
    if (!this.epoch || state?.epoch !== this.epoch) throw lost();
  }

  private async audit(tx: Prisma.TransactionClient, tenantId: string, scanRequestId: string,
    id: string, event: string): Promise<void> {
    await tx.auditEvent.create({ data: { tenantId, scanRequestId, eventType: event,
      actor: "fetch-token-broker", targetType: "fetch_capability", targetId: id } });
  }

  private async suspend(tx: Prisma.TransactionClient, tenantId: string, scanRequestId: string,
    capabilityId: string, timestamp: Date): Promise<void> {
    const scan = await tx.scanRequest.findFirstOrThrow({ where: { id: scanRequestId, tenantId },
      include: { repositoryBinding: true } });
    await tx.scmIntegration.updateMany({ where: { id: scan.repositoryBinding.scmIntegrationId, tenantId, status: "ACTIVE" },
      data: { status: "SUSPENDED" } });
    await tx.scanDispatchJob.updateMany({ where: { tenantId, scanRequestId, status: { in: ["PENDING", "LEASED"] } },
      data: { status: "CANCELED", leaseToken: null, leasedBy: null, leaseExpiresAt: null, lastErrorCode: "DISPATCH_REJECTED" } });
    await tx.scanRequest.updateMany({ where: { id: scanRequestId, tenantId, status: { in: ["QUEUED", "PLANNING", "RUNNING"] } },
      data: { status: "FAILED", completedAt: timestamp } });
    await this.audit(tx, tenantId, scanRequestId, capabilityId, "token.revocation_unconfirmed");
  }

  /** Explicit bootstrap under the future single broker's process lock. */
  async startEpoch(): Promise<void> {
    const epoch = randomUUID();
    await serializable(this.prisma, async (tx) => {
      const timestamp = await now(tx);
      await tx.scanBrokerRuntime.upsert({ where: { id: BROKER_ID },
        create: { id: BROKER_ID, epoch }, update: { epoch } });
      const uncertain = await tx.scanFetchCapability.findMany({ where: { status: "CONSUMING" } });
      for (const cap of uncertain) await this.suspend(tx, cap.tenantId, cap.scanRequestId, cap.id, timestamp);
      await tx.scanFetchCapability.updateMany({ where: { status: { in: OPEN } },
        data: { status: "REVOKED", finishedAt: timestamp } });
    });
    this.epoch = epoch;
  }

  private async owned(tx: Prisma.TransactionClient, lease: ScanDispatchLease, timestamp: Date) {
    await this.authority(tx, lease.tenantId);
    const job = await tx.scanDispatchJob.findFirst({ where: { id: lease.jobId, tenantId: lease.tenantId,
      scanRequestId: lease.scanRequestId, status: "LEASED", leaseToken: lease.leaseToken,
      leaseExpiresAt: { gt: timestamp }, scanRequest: activeScan },
      include: { scanRequest: { include: { repositoryBinding: { include: { integration: true } } } } } });
    if (!job) throw lost();
    return job;
  }

  async issue(lease: ScanDispatchLease, ttlSeconds = 600): Promise<FetchCapabilityIssue> {
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > 600) {
      throw new BadRequestException("Fetch capability TTL must be 1–600 seconds");
    }
    const capability = secret();
    return serializable(this.prisma, async (tx) => {
      const timestamp = await now(tx);
      const job = await this.owned(tx, lease, timestamp);
      if (await tx.scanFetchCapability.findFirst({ where: { dispatchJobId: job.id, status: "CONSUMING" } })) {
        throw new ConflictException("Gateway reconciliation required before another fetch");
      }
      await tx.scanFetchCapability.updateMany({ where: { dispatchJobId: job.id, status: "ISSUED" },
        data: { status: "REVOKED", finishedAt: timestamp } });
      const expiresAt = new Date(timestamp.getTime()+ttlSeconds*1000);
      const cap = await tx.scanFetchCapability.create({ data: {
        tenantId: lease.tenantId, scanRequestId: job.scanRequestId, dispatchJobId: job.id,
        issuerEpoch: this.epoch!, fingerprint: hash("fetch",capability), leaseFingerprint: hash("lease",lease.leaseToken),
        issuedAt: timestamp, expiresAt
      } });
      await this.audit(tx, cap.tenantId, cap.scanRequestId, cap.id, "fetch.capability.issued");
      return { credentialId: cap.id, capability, expiresAt: expiresAt.toISOString(), expiresInSeconds: ttlSeconds };
    });
  }

  async consume(lease: ScanDispatchLease, capability: string): Promise<FetchGatewayClaim> {
    if (!validSecret(capability)) throw lost();
    const claimToken = secret();
    return serializable(this.prisma, async (tx) => {
      const timestamp = await now(tx);
      const job = await this.owned(tx, lease, timestamp);
      const cap = await tx.scanFetchCapability.findFirst({ where: {
        tenantId: lease.tenantId, dispatchJobId: job.id, scanRequestId: job.scanRequestId,
        fingerprint: hash("fetch",capability), leaseFingerprint: hash("lease",lease.leaseToken),
        issuerEpoch: this.epoch, status: "ISSUED", expiresAt: { gt: timestamp }
      } });
      if (!cap) throw lost();
      const binding = job.scanRequest.repositoryBinding;
      if (binding.integration.provider !== "GITHUB" || binding.integration.integrationType !== "GITHUB_APP" ||
          !/^[1-9][0-9]*$/.test(binding.providerRepoId) ||
          !/^[1-9][0-9]*$/.test(binding.integration.externalInstallationId) ||
          !/^[a-f0-9]{40}$/.test(job.scanRequest.commitSha)) throw lost();
      await tx.scanFetchCapability.update({ where: { id: cap.id }, data: {
        status: "CONSUMING", claimFingerprint: hash("claim",claimToken)
      } });
      await this.audit(tx, cap.tenantId, cap.scanRequestId, cap.id, "fetch.capability.claimed");
      return { credentialId: cap.id, claimToken, expiresAt: cap.expiresAt.toISOString(),
        tenantId: cap.tenantId, scanRequestId: cap.scanRequestId, dispatchJobId: cap.dispatchJobId,
        repositoryBindingId: binding.id, providerRepoId: binding.providerRepoId, fullName: binding.fullName,
        providerUserId: this.admitted.get(cap.tenantId)!,
        installationId: binding.integration.externalInstallationId, commitSha: job.scanRequest.commitSha };
    });
  }

  async complete(tenantId: string, credentialId: string, claimToken: string,
    outcome: FetchGatewayOutcome): Promise<FetchGatewayCompletion> {
    if (!validSecret(claimToken) || !outcome || typeof outcome.success !== "boolean" || typeof outcome.upstreamRevoked !== "boolean") throw lost();
    return serializable(this.prisma, async (tx) => {
      await this.authority(tx, tenantId);
      const timestamp = await now(tx);
      const cap = await tx.scanFetchCapability.findFirst({ where: { id: credentialId, tenantId,
        issuerEpoch: this.epoch, status: "CONSUMING", claimFingerprint: hash("claim",claimToken) },
        include: { dispatchJob: { include: { scanRequest: { include: { repositoryBinding: { include: { integration: true } } } } } } } });
      if (!cap) throw lost();
      const job = cap.dispatchJob;
      const valid = job.status === "LEASED" && job.leaseToken !== null && job.leaseExpiresAt !== null &&
        job.leaseExpiresAt > timestamp && hash("lease",job.leaseToken) === cap.leaseFingerprint && cap.expiresAt > timestamp &&
        ["QUEUED","PLANNING"].includes(job.scanRequest.status) &&
        job.scanRequest.isolationClass === "STANDARD" &&
        job.scanRequest.repositoryBinding.integration.status === "ACTIVE" &&
        !!await tx.tenant.findFirst({ where: { id: tenantId, status: "ACTIVE" } });
      const handoffAllowed = outcome.success && outcome.upstreamRevoked && valid;
      await tx.scanFetchCapability.update({ where: { id: cap.id }, data: {
        status: handoffAllowed ? "CONSUMED" : "REVOKED", finishedAt: timestamp
      } });
      if (!outcome.upstreamRevoked) await this.suspend(tx, tenantId, cap.scanRequestId, cap.id, timestamp);
      await this.audit(tx, tenantId, cap.scanRequestId, cap.id, handoffAllowed ? "fetch.capability.consumed" : "fetch.capability.revoked");
      return { handoffAllowed, integrationSuspended: !outcome.upstreamRevoked };
    });
  }

  /** Gateway rechecks this before every source request; returns no source or secret. */
  async validateClaim(tenantId: string, credentialId: string, claimToken: string): Promise<boolean> {
    if (!validSecret(claimToken)) throw lost();
    return serializable(this.prisma, async (tx) => {
      await this.authority(tx, tenantId);
      const timestamp = await now(tx);
      const cap = await tx.scanFetchCapability.findFirst({ where: {
        id: credentialId, tenantId, issuerEpoch: this.epoch, status: "CONSUMING",
        expiresAt: { gt: timestamp }, claimFingerprint: hash("claim",claimToken),
        dispatchJob: { status: "LEASED", leaseExpiresAt: { gt: timestamp }, scanRequest: activeScan }
      }, include: { dispatchJob: { select: { leaseToken: true } } } });
      if (!cap?.dispatchJob.leaseToken || hash("lease",cap.dispatchJob.leaseToken) !== cap.leaseFingerprint) throw lost();
      return true;
    });
  }
}
