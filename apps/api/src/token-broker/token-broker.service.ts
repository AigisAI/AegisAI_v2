import {
  BadRequestException,
  Injectable,
  NotFoundException
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import {
  MAX_SCAN_CREDENTIAL_TTL_SECONDS,
  type SastCredentialLeaseMetadata,
  type TokenBrokerLeaseCompletionRequest,
  type TokenBrokerIssueRequest
} from '@aegisai/shared';

import { ControlPlaneService } from '../control-plane/control-plane.service';
import { PrismaService } from '../prisma/prisma.service';
import { RepositoryCredentialLeaseStore } from './repository-credential-lease.store';
import { TokenCredentialIssuerService } from "./token-credential-issuer.service";
import type { TokenBrokerAuditEvent, TokenBrokerIssueResponse } from "./token-broker.types";
import { WorkloadIdentityAttestationService } from './workload-identity-attestation.service';

@Injectable()
export class TokenBrokerService {
  constructor(
    private readonly tokenCredentialIssuer: TokenCredentialIssuerService,
    private readonly controlPlaneService: ControlPlaneService,
    private readonly workloadIdentityAttestation: WorkloadIdentityAttestationService,
    private readonly credentialLeaseStore: RepositoryCredentialLeaseStore,
    private readonly prisma: PrismaService
  ) {}

  async issue(input: TokenBrokerIssueRequest): Promise<TokenBrokerIssueResponse> {
    await this.assertBoundToScan(input);
    const issuedCredential = await this.reserveAndIssue(input);
    try {
      return {
        tenantId: input.tenantId,
        repositoryBindingId: input.repositoryBindingId,
        scanRequestId: input.scanRequestId,
        attemptId: input.attemptId,
        workloadIdentityRef: input.workloadIdentityRef,
        principal: input.principal,
        commitSha: input.commitSha,
        ttlSeconds: input.ttlSeconds,
        auditReason: input.auditReason,
        credentialId: issuedCredential.credentialId,
        credentialType: issuedCredential.credentialType,
        credentialValue: issuedCredential.credential.revealForTransport(),
        issuedAt: issuedCredential.issuedAt,
        expiresAt: issuedCredential.expiresAt,
        expiresInSeconds: input.ttlSeconds,
        auditEventType: "token.issued"
      };
    } finally {
      issuedCredential.credential.wipe();
    }
  }

  async withCredential<T>(
    input: TokenBrokerIssueRequest,
    consumer: (credential: Uint8Array) => Promise<T>
  ): Promise<T> {
    await this.assertBoundToScan(input);
    const issued = await this.reserveAndIssue(input);
    try {
      return await issued.credential.use(consumer);
    } finally {
      issued.credential.wipe();
      await this.credentialLeaseStore.markWiped(
        issued.credentialId,
        input.tenantId,
        input.attemptId,
        this.terminalTimestamp(issued.issuedAt)
      );
    }
  }

  async completeLease(
    input: TokenBrokerLeaseCompletionRequest
  ): Promise<SastCredentialLeaseMetadata> {
    this.workloadIdentityAttestation.verify(input.workloadIdentityAttestation, {
      tenantId: input.tenantId,
      repositoryBindingId: input.repositoryBindingId,
      scanRequestId: input.scanRequestId,
      attemptId: input.attemptId,
      workloadIdentityRef: input.workloadIdentityRef,
      commitSha: input.commitSha
    });
    const lease = await this.credentialLeaseStore.findByAttempt(
      input.tenantId,
      input.attemptId
    );
    if (!lease) {
      throw new NotFoundException('Credential lease not found for attempt.');
    }
    if (
      lease.credentialId !== input.credentialId ||
      lease.repositoryBindingId !== input.repositoryBindingId ||
      lease.scanRequestId !== input.scanRequestId ||
      lease.workloadIdentityRef !== input.workloadIdentityRef ||
      lease.commitSha !== input.commitSha
    ) {
      throw new BadRequestException(
        'Credential cleanup does not match the immutable lease scope.'
      );
    }
    const terminalAt = this.terminalTimestamp(lease.issuedAt);
    if (input.disposition === 'WIPED') {
      return this.credentialLeaseStore.markWiped(
        input.credentialId,
        input.tenantId,
        input.attemptId,
        terminalAt
      );
    }
    if (input.disposition === 'REVOKED') {
      return this.credentialLeaseStore.revoke(
        input.credentialId,
        input.tenantId,
        input.attemptId,
        terminalAt
      );
    }
    throw new BadRequestException(
      'Credential cleanup disposition is outside policy.'
    );
  }

  async listAuditEvents(tenantId: string): Promise<TokenBrokerAuditEvent[]> {
    const rows = await this.prisma.auditEvent.findMany({
      where: {
        tenantId,
        eventType: 'token.issued',
        actor: 'token-broker'
      },
      orderBy: [{ occurredAt: 'asc' }, { id: 'asc' }]
    });
    return rows.map((row) => ({
      id: row.id,
      tenantId: row.tenantId,
      eventType: 'token.issued',
      actor: 'token-broker',
      targetType: row.targetType,
      targetId: row.targetId,
      occurredAt: row.occurredAt.toISOString(),
      metadata: row.metadata as TokenBrokerAuditEvent['metadata']
    }));
  }

  private async assertBoundToScan(input: TokenBrokerIssueRequest): Promise<void> {
    if (
      input.principal !== 'REPO_READ' ||
      !Number.isInteger(input.ttlSeconds) ||
      input.ttlSeconds < 1 ||
      input.ttlSeconds > MAX_SCAN_CREDENTIAL_TTL_SECONDS
    ) {
      throw new BadRequestException('Token scope or TTL is outside the scan credential policy.');
    }

    this.workloadIdentityAttestation.verify(input.workloadIdentityAttestation, {
      tenantId: input.tenantId,
      repositoryBindingId: input.repositoryBindingId,
      scanRequestId: input.scanRequestId,
      attemptId: input.attemptId,
      workloadIdentityRef: input.workloadIdentityRef,
      commitSha: input.commitSha
    });

    const scanRequest = await this.controlPlaneService.getScanRequest(
      input.tenantId,
      input.scanRequestId
    );
    if (
      scanRequest.repositoryBindingId !== input.repositoryBindingId ||
      scanRequest.commitSha !== input.commitSha
    ) {
      throw new BadRequestException('Token request does not match the immutable scan scope.');
    }
  }

  private async reserveAndIssue(input: TokenBrokerIssueRequest) {
    const credentialId = `credential_${randomUUID()}`;
    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + input.ttlSeconds * 1000);
    await this.credentialLeaseStore.reserve({
      credentialId,
      tenantId: input.tenantId,
      repositoryBindingId: input.repositoryBindingId,
      scanRequestId: input.scanRequestId,
      attemptId: input.attemptId,
      workloadIdentityRef: input.workloadIdentityRef,
      commitSha: input.commitSha,
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString()
    });

    let issuedCredential: ReturnType<TokenCredentialIssuerService['issue']> | undefined;
    try {
      issuedCredential = this.tokenCredentialIssuer.issue(input, issuedAt);
      await this.credentialLeaseStore.activate(
        credentialId,
        input.tenantId,
        input.attemptId,
        issuedCredential.credential.fingerprint()
      );
      await this.recordIssueAudit(input, credentialId, issuedCredential.issuedAt);
      return {
        credentialId,
        ...issuedCredential
      };
    } catch (error) {
      issuedCredential?.credential.wipe();
      await this.credentialLeaseStore.revoke(
        credentialId,
        input.tenantId,
        input.attemptId,
        this.terminalTimestamp(issuedAt.toISOString())
      );
      throw error;
    }
  }

  private terminalTimestamp(issuedAt: string): string {
    return new Date(
      Math.max(Date.now(), Date.parse(issuedAt))
    ).toISOString();
  }

  private async recordIssueAudit(
    input: TokenBrokerIssueRequest,
    credentialId: string,
    occurredAt: string
  ): Promise<void> {
    await this.prisma.auditEvent.create({
      data: {
        id: `audit_event_${randomUUID()}`,
        tenantId: input.tenantId,
        scanRequestId: input.scanRequestId,
        eventType: "token.issued",
        actor: "token-broker",
        targetType: "scan_request",
        targetId: input.scanRequestId,
        occurredAt: new Date(occurredAt),
        metadata: {
          repositoryBindingId: input.repositoryBindingId,
          attemptId: input.attemptId,
          workloadIdentityRef: input.workloadIdentityRef,
          credentialId,
          principal: input.principal,
          commitSha: input.commitSha,
          ttlSeconds: input.ttlSeconds,
          auditReason: input.auditReason
        }
      }
    });
  }
}
