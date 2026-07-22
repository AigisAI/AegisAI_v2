import { createHash } from 'node:crypto';

import { Injectable } from '@nestjs/common';
import {
  SAST_FORBIDDEN_CAPABILITIES,
  buildSastCanonicalScanKeyPreimage,
  buildSastProfileDigestPreimage,
  evaluateSastQueueAdmission,
  findSastProfileLimitReasonCodes,
  isSastScanPlanValid,
  isSastProfileSelectionPolicyValid,
  isTrustedSastRepositoryMetadataValid,
  isScannerSetDescriptorValid,
  isSignedSastArtifactDescriptorValid,
  selectSastScanProfile,
  type SastCoverageClaim,
  type SastPlanningReasonCode,
  type SastScanPlan,
  type SastScanPlanningInput,
  type SastScanPlanningResult,
  type SastScanProfile,
  type SastUserVisiblePlanningState,
  type ScannerSetDescriptor
} from '@aegisai/shared';

import { ControlPlaneService } from './control-plane.service';
import type { ControlPlaneScanRequest } from './control-plane.types';

@Injectable()
export class SastScanPlannerService {
  constructor(private readonly controlPlaneService: ControlPlaneService) {}

  plan(input: SastScanPlanningInput): SastScanPlanningResult {
    const scanRequest = this.controlPlaneService.getScanRequest(input.tenantId, input.scanRequestId);

    if (!this.isFullCommitSha(scanRequest.commitSha)) {
      return this.reject(scanRequest, input.requestedAt, 'FIXED_COMMIT_REQUIRED');
    }

    if (!isTrustedSastRepositoryMetadataValid(input.repositoryMetadata)) {
      return this.reject(scanRequest, input.requestedAt, 'TRUSTED_METADATA_INVALID');
    }

    if (
      input.repositoryMetadata.repositoryBindingId !== scanRequest.repositoryBindingId ||
      input.repositoryMetadata.fixedCommitSha.toLowerCase() !== scanRequest.commitSha.toLowerCase()
    ) {
      return this.reject(scanRequest, input.requestedAt, 'TRUSTED_METADATA_SCOPE_MISMATCH');
    }

    if (!isSastProfileSelectionPolicyValid(input.profilePolicy)) {
      return this.reject(scanRequest, input.requestedAt, 'PROFILE_POLICY_INVALID');
    }

    if (input.profilePolicy.policyVersion !== scanRequest.policyVersion) {
      return this.reject(scanRequest, input.requestedAt, 'PROFILE_POLICY_VERSION_MISMATCH');
    }

    if (!input.scannerSet) {
      return this.reject(scanRequest, input.requestedAt, 'SCANNER_SET_INVALID');
    }

    if (input.scannerSet.scannerSetVersion !== scanRequest.scannerSetVersion) {
      return this.reject(scanRequest, input.requestedAt, 'SCANNER_SET_VERSION_MISMATCH');
    }

    const profileSelection = selectSastScanProfile({
      lane: scanRequest.lane,
      metadata: input.repositoryMetadata,
      policy: input.profilePolicy
    });
    if (profileSelection.state === 'REJECTED' || !profileSelection.profile) {
      return this.reject(
        scanRequest,
        input.requestedAt,
        profileSelection.reasonCodes,
        profileSelection.coverageClaim
      );
    }

    const limitReasonCodes = findSastProfileLimitReasonCodes(
      input.repositoryMetadata,
      profileSelection.profile
    );
    if (limitReasonCodes.length > 0) {
      return this.reject(
        scanRequest,
        input.requestedAt,
        limitReasonCodes,
        profileSelection.coverageClaim,
        profileSelection.profile
      );
    }

    const scannerSetReasonCodes = this.scannerSetReasonCodes(
      input.scannerSet,
      profileSelection.profile
    );
    if (scannerSetReasonCodes.length > 0) {
      return this.reject(
        scanRequest,
        input.requestedAt,
        scannerSetReasonCodes,
        profileSelection.coverageClaim,
        profileSelection.profile
      );
    }

    const profileDigest = this.digest(buildSastProfileDigestPreimage(profileSelection.profile));
    const isolationClass =
      scanRequest.isolationClass === 'RESTRICTED' ? 'RESTRICTED' : 'HARDENED';
    const canonicalScanKey = this.digest(
      buildSastCanonicalScanKeyPreimage({
        tenantId: scanRequest.tenantId,
        repositoryBindingId: scanRequest.repositoryBindingId,
        lane: scanRequest.lane,
        targetRef: scanRequest.targetRef,
        fixedCommitSha: scanRequest.commitSha,
        inventoryDigest: input.repositoryMetadata.inventoryDigest,
        policyVersion: scanRequest.policyVersion,
        profile: profileSelection.profile,
        profileDigest,
        scannerSet: input.scannerSet,
        isolationClass
      })
    );
    const plan = this.buildPlan(
      scanRequest,
      profileSelection.profile,
      profileDigest,
      canonicalScanKey,
      input.scannerSet,
      isolationClass,
      input.repositoryMetadata.inventoryDigest,
      input.requestedAt
    );

    if (!isSastScanPlanValid(plan)) {
      return this.reject(
        scanRequest,
        input.requestedAt,
        'PLAN_CONTRACT_INVALID',
        profileSelection.coverageClaim,
        profileSelection.profile
      );
    }

    const queueAdmission = evaluateSastQueueAdmission({
      lane: scanRequest.lane,
      tenantId: scanRequest.tenantId,
      repositoryBindingId: scanRequest.repositoryBindingId,
      requestedAt: input.requestedAt,
      policySet: input.queuePolicySet,
      usage: input.queueUsage
    });

    const planning: SastUserVisiblePlanningState = {
      state: queueAdmission.state,
      profileId: profileSelection.profile.id,
      coverageClaim: profileSelection.coverageClaim,
      queueName: queueAdmission.queueName,
      queuePolicyVersion: queueAdmission.queuePolicyVersion,
      queuePolicyDigest: queueAdmission.queuePolicyDigest,
      canonicalScanKey,
      reasonCodes: [...profileSelection.reasonCodes, ...queueAdmission.reasonCodes],
      retryAfterSeconds: queueAdmission.retryAfterSeconds,
      updatedAt: input.requestedAt
    };
    this.controlPlaneService.recordSastPlanningState(
      scanRequest.tenantId,
      scanRequest.id,
      planning
    );

    return {
      planning,
      plan: queueAdmission.state === 'REJECTED' ? undefined : plan
    };
  }

  private buildPlan(
    scanRequest: ControlPlaneScanRequest,
    profile: SastScanProfile,
    profileDigest: `sha256:${string}`,
    canonicalScanKey: `sha256:${string}`,
    scannerSet: ScannerSetDescriptor,
    isolationClass: 'HARDENED' | 'RESTRICTED',
    inventoryDigest: `sha256:${string}`,
    createdAt: string
  ): SastScanPlan {
    const tenantScope = encodeURIComponent(scanRequest.tenantId);
    const scanScope = encodeURIComponent(scanRequest.id);
    const profileSnapshot = this.deepFreeze(structuredClone(profile));
    const scannerSetSnapshot = this.deepFreeze(structuredClone(scannerSet));

    return this.deepFreeze({
      tenantId: scanRequest.tenantId,
      scanRequestId: scanRequest.id,
      canonicalScanKey,
      profile: profileSnapshot,
      profileDigest,
      policyVersion: scanRequest.policyVersion,
      repositoryState: {
        repositoryBindingId: scanRequest.repositoryBindingId,
        fixedCommitSha: scanRequest.commitSha.toLowerCase(),
        targetRef: scanRequest.targetRef,
        inventoryDigest,
        shallowFetchPreferred: true,
        submodulesEnabled: false,
        lfsObjectsFetched: false
      },
      scannerSet: scannerSetSnapshot,
      isolationClass,
      resultIngressRef: `result-ingress://${tenantScope}/${scanScope}`,
      evidenceOutputRef: `evidence-output://${tenantScope}/${scanScope}`,
      auditSinkRef: `audit-sink://${tenantScope}/${scanScope}`,
      forbiddenCapabilities: [...SAST_FORBIDDEN_CAPABILITIES],
      createdAt
    });
  }

  private scannerSetReasonCodes(
    scannerSet: ScannerSetDescriptor,
    profile: SastScanProfile
  ): SastPlanningReasonCode[] {
    const reasonCodes: SastPlanningReasonCode[] = [];
    const scanners = scannerSet?.scanners;
    const ruleBundles = Array.isArray(scannerSet?.ruleBundles) ? scannerSet.ruleBundles : [];

    if (!scanners || profile.requiredScanners.some((scanner) => !scanners[scanner])) {
      reasonCodes.push('REQUIRED_SCANNER_MISSING');
    }

    if (
      profile.requiredScanners.some(
        (scanner) =>
          (scanner === 'OPENGREP' || scanner === 'TRIVY') &&
          !ruleBundles.some((bundle) => bundle.scanner === scanner)
      )
    ) {
      reasonCodes.push('REQUIRED_RULE_BUNDLE_MISSING');
    }

    if (
      !scannerSet?.vulnerabilityDatabase ||
      !isSignedSastArtifactDescriptorValid(scannerSet.vulnerabilityDatabase)
    ) {
      reasonCodes.push('VULNERABILITY_DATABASE_INVALID');
    }
    if (!scannerSet?.schemaBundle || !isSignedSastArtifactDescriptorValid(scannerSet.schemaBundle)) {
      reasonCodes.push('SCHEMA_BUNDLE_INVALID');
    }
    if (
      !scannerSet?.normalizerBundle ||
      !isSignedSastArtifactDescriptorValid(scannerSet.normalizerBundle)
    ) {
      reasonCodes.push('NORMALIZER_BUNDLE_INVALID');
    }

    let scannerSetValid = false;
    try {
      scannerSetValid = isScannerSetDescriptorValid(scannerSet);
    } catch {
      scannerSetValid = false;
    }
    if (!scannerSetValid) {
      reasonCodes.push('SCANNER_SET_INVALID');
    }

    return Array.from(new Set(reasonCodes));
  }

  private reject(
    scanRequest: ControlPlaneScanRequest,
    updatedAt: string,
    reasonCodes: SastPlanningReasonCode | SastPlanningReasonCode[],
    coverageClaim: SastCoverageClaim = 'NONE',
    profile?: SastScanProfile
  ): SastScanPlanningResult {
    const planning: SastUserVisiblePlanningState = {
      state: 'REJECTED',
      profileId: profile?.id,
      coverageClaim,
      reasonCodes: Array.isArray(reasonCodes) ? [...reasonCodes] : [reasonCodes],
      updatedAt
    };
    this.controlPlaneService.recordSastPlanningState(
      scanRequest.tenantId,
      scanRequest.id,
      planning
    );

    return { planning };
  }

  private digest(preimage: string): `sha256:${string}` {
    return `sha256:${createHash('sha256').update(preimage, 'utf8').digest('hex')}`;
  }

  private isFullCommitSha(value: string): boolean {
    return /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i.test(value);
  }

  private deepFreeze<T>(value: T): T {
    if (value && typeof value === 'object' && !Object.isFrozen(value)) {
      for (const nested of Object.values(value)) {
        this.deepFreeze(nested);
      }
      Object.freeze(value);
    }

    return value;
  }
}
