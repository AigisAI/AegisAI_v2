import { randomUUID } from "node:crypto";

import { ForbiddenException, Injectable, NotFoundException, ServiceUnavailableException } from "@nestjs/common";
import { buildCanonicalScanKey, shouldEscalateIsolation } from "@aegisai/shared";
import type { ScmIntegration } from "@prisma/client";

import { PrismaService } from "../prisma/prisma.service";
import { serializable } from "../prisma/transaction";
import type {
  ControlPlaneIntegration, ControlPlaneRepositoryBinding, ControlPlaneScanRequest,
  CreateScanRequestInput, InstallIntegrationInput, InstallIntegrationOptions
} from "./control-plane.types";

const repositorySelect = {
  id: true, tenantId: true, scmIntegrationId: true, providerRepoId: true,
  fullName: true, defaultBranch: true, isPrivate: true
} as const;
const scanSelect = {
  id: true, tenantId: true, repositoryBindingId: true, lane: true, targetRef: true,
  commitSha: true, policyVersion: true, scannerSetVersion: true, canonicalKey: true,
  isolationClass: true, status: true
} as const;

function integrationResponse(row: ScmIntegration): ControlPlaneIntegration {
  return {
    id: row.id, tenantId: row.tenantId, provider: row.provider,
    integrationType: row.integrationType, externalInstallationId: row.externalInstallationId,
    repoReadPrincipalId: row.repoReadPrincipalId, status: row.status,
    ...(row.commentWritePrincipalId ? { commentWritePrincipalId: row.commentWritePrincipalId } : {}),
    ...(row.integrationAdminPrincipalId
      ? { integrationAdminPrincipalId: row.integrationAdminPrincipalId } : {})
  };
}

@Injectable()
export class ControlPlaneService {
  constructor(private readonly prisma: PrismaService) {}

  // Only trusted provider code may call this after verifying installation ownership.
  async installIntegration(
    input: InstallIntegrationInput,
    options: InstallIntegrationOptions
  ): Promise<ControlPlaneIntegration> {
    return serializable(this.prisma, async (tx) => {
      const tenant = await tx.tenant.findFirst({ where: { id: input.tenantId, status: "ACTIVE" } });
      if (!tenant) throw new ForbiddenException("Active tenant required");
      const integration = await tx.scmIntegration.upsert({
        where: { tenantId_provider_externalInstallationId: {
          tenantId: input.tenantId, provider: options.provider,
          externalInstallationId: input.externalInstallationId
        } },
        create: {
          id: `integration_${randomUUID()}`, tenantId: input.tenantId,
          ...options, externalInstallationId: input.externalInstallationId,
          repoReadPrincipalId: input.repoReadPrincipalId,
          commentWritePrincipalId: input.commentWritePrincipalId,
          integrationAdminPrincipalId: input.integrationAdminPrincipalId
        }, update: {}
      });
      if (integration.status !== "ACTIVE") {
        throw new ForbiddenException("Integration requires verified reauthorization");
      }
      for (const repository of input.repositories ?? []) {
        await tx.repositoryBinding.upsert({
          where: { tenantId_scmIntegrationId_providerRepoId: {
            tenantId: input.tenantId, scmIntegrationId: integration.id,
            providerRepoId: repository.providerRepoId
          } },
          create: {
            id: `repository_binding_${randomUUID()}`, tenantId: input.tenantId,
            scmIntegrationId: integration.id, ...repository
          }, update: {}
        });
      }
      return integrationResponse(integration);
    });
  }

  async listIntegrations(tenantId: string): Promise<ControlPlaneIntegration[]> {
    const rows = await this.prisma.scmIntegration.findMany({
      where: { tenantId, tenant: { status: "ACTIVE" } }, orderBy: { id: "asc" }
    });
    return rows.map(integrationResponse);
  }

  async removeIntegration(tenantId: string, integrationId: string): Promise<{ deleted: true; id: string }> {
    return serializable(this.prisma, async (tx) => {
      const integration = await tx.scmIntegration.findFirst({
        where: { id: integrationId, tenantId, tenant: { status: "ACTIVE" } }
      });
      if (!integration) throw new NotFoundException("Integration not found");
      if (integration.status !== "REVOKED") {
        await tx.scmIntegration.updateMany({
          where: { id: integrationId, tenantId }, data: { status: "REVOKED" }
        });
        await tx.scanRequest.updateMany({
          where: {
            tenantId, repositoryBinding: { tenantId, scmIntegrationId: integrationId },
            status: { in: ["QUEUED", "PLANNING", "RUNNING"] }
          }, data: { status: "CANCELED", completedAt: new Date() }
        });
        await tx.scanDispatchJob.updateMany({
          where: {
            tenantId, scanRequest: { tenantId, repositoryBinding: { tenantId, scmIntegrationId: integrationId } },
            status: { in: ["PENDING", "LEASED"] }
          }, data: { status: "CANCELED", leaseToken: null, leasedBy: null, leaseExpiresAt: null }
        });
        await tx.auditEvent.create({ data: {
          tenantId, eventType: "integration.revoked", actor: "control-plane",
          targetType: "scm_integration", targetId: integrationId
        } });
      }
      return { deleted: true, id: integrationId };
    });
  }

  async listRepositoryBindings(tenantId: string): Promise<ControlPlaneRepositoryBinding[]> {
    return this.prisma.repositoryBinding.findMany({
      where: { tenantId, tenant: { status: "ACTIVE" }, integration: { tenantId, status: "ACTIVE" } },
      select: repositorySelect, orderBy: { id: "asc" }
    });
  }

  async createScanRequest(input: CreateScanRequestInput, pendingLimit?: number): Promise<ControlPlaneScanRequest> {
    return serializable(this.prisma, async (tx) => {
      const repository = await tx.repositoryBinding.findFirst({
        where: {
          id: input.repositoryBindingId, tenantId: input.tenantId,
          tenant: { status: "ACTIVE" }, integration: { tenantId: input.tenantId, status: "ACTIVE" }
        }
      });
      if (!repository) throw new NotFoundException("Active repository binding not found for tenant");
      const commitSha = input.commitSha.toLowerCase();
      const canonicalKey = buildCanonicalScanKey({ ...input, commitSha });
      if(pendingLimit && !await tx.scanRequest.findUnique({where:{canonicalKey},select:{id:true}}) &&
        await tx.scanRequest.count({where:{tenantId:input.tenantId,status:{in:["QUEUED","PLANNING","RUNNING"]}}})>=pendingLimit) {
        throw new ServiceUnavailableException({errorCode:"SCAN_CAPACITY_REACHED",message:"The private scan queue is full. Try again after an active scan finishes."});
      }
      const scan = await tx.scanRequest.upsert({
        where: { canonicalKey },
        create: {
          id: `scan_request_${randomUUID()}`, tenantId: input.tenantId,
          repositoryBindingId: input.repositoryBindingId, lane: input.lane,
          targetRef: input.targetRef, commitSha, policyVersion: input.policyVersion,
          scannerSetVersion: input.scannerSetVersion, canonicalKey,
          isolationClass: input.isolationSignals && shouldEscalateIsolation(input.isolationSignals)
            ? "HARDENED" : "STANDARD"
        }, update: {}, select: scanSelect
      });
      if (["QUEUED", "PLANNING"].includes(scan.status)) {
        await tx.scanDispatchJob.upsert({
          where: { scanRequestId: scan.id },
          create: { id: `dispatch_job_${randomUUID()}`, tenantId: input.tenantId, scanRequestId: scan.id },
          update: {}
        });
      }
      return scan;
    });
  }

  async getScanRequest(tenantId: string, scanRequestId: string): Promise<ControlPlaneScanRequest> {
    const row = await this.prisma.scanRequest.findFirst({
      where: { id: scanRequestId, tenantId, tenant: { status: "ACTIVE" } }, select: scanSelect
    });
    if (!row) throw new NotFoundException("Scan request not found");
    return row;
  }
}
