import { randomUUID } from "node:crypto";

import { BadRequestException, ConflictException, Injectable } from "@nestjs/common";
import type { Prisma, ScanDispatchJob } from "@prisma/client";
import type { ScanDispatchFailureCode, ScanDispatchLease } from "@aegisai/shared";
import { RUNTIME_REJECTION_REASONS, type RuntimeRejectionReason } from "@aegisai/shared";

import { PrismaService } from "../prisma/prisma.service";
import { serializable } from "../prisma/transaction";

const LEASE_MS = 60_000;
const MAX_ATTEMPTS = 5;
const GLOBAL_LEASE_LIMIT = 2;
const clearLease = { leaseToken: null, leasedBy: null, leaseExpiresAt: null };
const activeScan = {
  status: { in: ["QUEUED", "PLANNING", "RUNNING"] as ("QUEUED" | "PLANNING" | "RUNNING")[] },
  tenant: { status: "ACTIVE" as const },
  repositoryBinding: { integration: { status: "ACTIVE" as const } }
};

function backoff(attempt: number): number {
  return Math.min(60_000, 1000 * 2 ** attempt);
}

async function databaseTime(tx: Prisma.TransactionClient): Promise<Date> {
  const [row] = await tx.$queryRaw<{ now: Date }[]>`SELECT clock_timestamp() AS now`;
  return row.now;
}

function leaseResponse(job: ScanDispatchJob): ScanDispatchLease {
  return {
    jobId: job.id, tenantId: job.tenantId, scanRequestId: job.scanRequestId,
    attempt: job.attempts, leaseToken: job.leaseToken!, expiresAt: job.leaseExpiresAt!.toISOString()
  };
}

/** Durable at-least-once dispatch library. No consumer, timers or HTTP routes. */
@Injectable()
export class ScanDispatchService {
  constructor(private readonly prisma: PrismaService) {}

  private async rejectInactive(tx: Prisma.TransactionClient): Promise<void> {
    const invalid = await tx.scanDispatchJob.findMany({
      where: { status: { in: ["PENDING", "LEASED"] }, NOT: { scanRequest: activeScan } },
      select: { id: true, tenantId: true, scanRequestId: true }, take: 100
    });
    for (const job of invalid) {
      await tx.scanDispatchJob.update({ where: { id: job.id }, data: { status: "CANCELED", ...clearLease } });
      await tx.scanRequest.updateMany({
        where: { id: job.scanRequestId, tenantId: job.tenantId, status: { in: ["QUEUED", "PLANNING", "RUNNING"] } },
        data: { status: "CANCELED", completedAt: await databaseTime(tx) }
      });
    }
  }

  private async retry(
    tx: Prisma.TransactionClient, job: ScanDispatchJob, now: Date, code: ScanDispatchFailureCode
  ): Promise<void> {
    const exhausted = job.attempts >= MAX_ATTEMPTS;
    await tx.scanDispatchJob.update({ where: { id: job.id }, data: {
      status: exhausted ? "DEAD" : "PENDING", ...clearLease, lastErrorCode: code,
      availableAt: new Date(now.getTime() + backoff(job.attempts))
    } });
    await tx.scanRequest.updateMany({
      where: { id: job.scanRequestId, tenantId: job.tenantId, status: { in: ["QUEUED", "PLANNING", "RUNNING"] } },
      data: { status: exhausted ? "FAILED" : "QUEUED", ...(exhausted ? { completedAt: now } : {}) }
    });
    await tx.auditEvent.create({ data: {
      tenantId: job.tenantId, scanRequestId: job.scanRequestId,
      eventType: exhausted ? "scan.dispatch.dead" : "scan.dispatch.retry",
      actor: "dispatch-queue", targetType: "scan_dispatch_job", targetId: job.id,
      metadata: { attempt: job.attempts, failureCode: code }
    } });
  }

  async claim(workerId: string, eligibleTenantIds?: readonly string[]): Promise<ScanDispatchLease | null> {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(workerId)) {
      throw new BadRequestException("Invalid dispatch worker identity");
    }
    if (eligibleTenantIds && (eligibleTenantIds.length > 100 ||
        eligibleTenantIds.some((id) => typeof id !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(id)))) {
      throw new BadRequestException("Invalid private dispatch admission");
    }
    if (eligibleTenantIds?.length === 0) return null;
    return serializable(this.prisma, async (tx) => {
      await this.rejectInactive(tx);
      const now = await databaseTime(tx);
      const expired = await tx.scanDispatchJob.findMany({
        where: { status: "LEASED", leaseExpiresAt: { lte: now } }, take: 100
      });
      for (const job of expired) await this.retry(tx, job, now, "LEASE_EXPIRED");
      const active = await tx.scanDispatchJob.count({ where: { status: "LEASED" } });
      if (active >= GLOBAL_LEASE_LIMIT) return null;
      const job = await tx.scanDispatchJob.findFirst({
        where: {
          status: "PENDING", attempts: { lt: MAX_ATTEMPTS }, availableAt: { lte: now },
          scanRequest: activeScan,
          ...(eligibleTenantIds ? { tenantId: { in: [...eligibleTenantIds] } } : {}),
          tenant: { status: "ACTIVE", dispatchJobs: { none: { status: "LEASED" } } }
        }, orderBy: [{ createdAt: "asc" }, { id: "asc" }]
      });
      if (!job) return null;
      const leased = await tx.scanDispatchJob.update({ where: { id: job.id }, data: {
        status: "LEASED", attempts: { increment: 1 }, leaseToken: randomUUID(),
        leasedBy: workerId, leaseExpiresAt: new Date(now.getTime() + LEASE_MS)
      } });
      await tx.scanRequest.update({
        where: { tenantId_id: { tenantId: job.tenantId, id: job.scanRequestId } },
        data: { status: "PLANNING" }
      });
      return leaseResponse(leased);
    });
  }

  private async owned(
    tx: Prisma.TransactionClient, tenantId: string, jobId: string, token: string, now: Date
  ): Promise<ScanDispatchJob> {
    const job = await tx.scanDispatchJob.findFirst({ where: {
      id: jobId, tenantId, status: "LEASED", leaseToken: token,
      leaseExpiresAt: { gt: now }, scanRequest: activeScan, tenant: { status: "ACTIVE" }
    } });
    if (!job) throw new ConflictException({
      errorCode: "DISPATCH_LEASE_LOST", message: "Dispatch lease is expired or no longer owned."
    });
    return job;
  }

  async heartbeat(tenantId: string, jobId: string, leaseToken: string): Promise<ScanDispatchLease> {
    return serializable(this.prisma, async (tx) => {
      const now = await databaseTime(tx);
      const job = await this.owned(tx, tenantId, jobId, leaseToken, now);
      const updated = await tx.scanDispatchJob.update({ where: { id: job.id }, data: {
        leaseExpiresAt: new Date(now.getTime() + LEASE_MS)
      } });
      return leaseResponse(updated);
    });
  }

  async acknowledge(tenantId: string, jobId: string, leaseToken: string): Promise<void> {
    return serializable(this.prisma, async (tx) => {
      const job = await this.owned(tx, tenantId, jobId, leaseToken, await databaseTime(tx));
      await tx.scanDispatchJob.update({ where: { id: job.id }, data: { status: "SUCCEEDED", ...clearLease } });
      await tx.auditEvent.create({ data: {
        tenantId, scanRequestId: job.scanRequestId, eventType: "scan.dispatch.acknowledged",
        actor: "dispatch-queue", targetType: "scan_dispatch_job", targetId: job.id,
        metadata: { attempt: job.attempts }
      } });
      // Dispatch acknowledgement is not scanner completion.
    });
  }

  async fail(tenantId: string, jobId: string, leaseToken: string, code: ScanDispatchFailureCode): Promise<void> {
    if (!["UPSTREAM_UNAVAILABLE", "DISPATCH_REJECTED"].includes(code)) {
      throw new BadRequestException("Invalid dispatch failure code");
    }
    return serializable(this.prisma, async (tx) => {
      const now = await databaseTime(tx);
      const job = await this.owned(tx, tenantId, jobId, leaseToken, now);
      await this.retry(tx, job, now, code);
    });
  }

  async reject(tenantId:string,jobId:string,leaseToken:string,reason:RuntimeRejectionReason):Promise<void> {
    if(!RUNTIME_REJECTION_REASONS.includes(reason)) throw new BadRequestException("Invalid runtime rejection");
    await serializable(this.prisma,async tx=>{
      const timestamp=await databaseTime(tx);
      const job=await this.owned(tx,tenantId,jobId,leaseToken,timestamp);
      await tx.scanDispatchJob.update({where:{id:job.id},data:{status:"DEAD",...clearLease,lastErrorCode:"DISPATCH_REJECTED"}});
      await tx.scanRequest.update({where:{id:job.scanRequestId},data:{status:"FAILED",completedAt:timestamp}});
      await tx.scanFetchCapability.updateMany({where:{tenantId,dispatchJobId:job.id,status:"ISSUED"},data:{status:"REVOKED",finishedAt:timestamp}});
      await tx.auditEvent.create({data:{tenantId,scanRequestId:job.scanRequestId,eventType:"scan.runtime.rejected",
        actor:"private-runtime",targetType:"scan_request",targetId:job.scanRequestId,metadata:{reason}}});
    });
  }
}
