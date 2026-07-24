import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual
} from 'node:crypto';

import {
  MAX_SAST_SANDBOX_ATTESTATION_TTL_SECONDS,
  SAST_SANDBOX_ATTESTATION_AUDIENCE,
  SAST_SANDBOX_ATTESTATION_ISSUER,
  SAST_SANDBOX_ATTESTATION_VERSION,
  buildSastScanPlanDigestPreimage,
  isSastSandboxRuntimePolicyValid,
  isSastScanPlanValid,
  type SastSandboxCleanupObservation,
  type SastSandboxRuntimeAttestation,
  type SastSandboxRuntimeAttestationClaims,
  type SastSandboxRuntimePolicy,
  type SastScanPlan,
  type SastSignedSandboxCleanupObservation
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import { ConfigService } from '../config/config.service';

const MAX_CLOCK_SKEW_MS = 5_000;

export interface SandboxRuntimeAttestationBinding {
  plan: Readonly<SastScanPlan>;
  attemptId: string;
  attemptNumber: number;
  sandboxId: string;
  workloadIdentityRef: string;
  policy: Readonly<SastSandboxRuntimePolicy>;
}

@Injectable()
export class SandboxRuntimeAttestationService {
  constructor(private readonly config: ConfigService) {}

  issue(
    binding: SandboxRuntimeAttestationBinding,
    now = new Date(),
    ttlSeconds = MAX_SAST_SANDBOX_ATTESTATION_TTL_SECONDS
  ): SastSandboxRuntimeAttestation {
    if (
      !Number.isSafeInteger(ttlSeconds) ||
      ttlSeconds < 1 ||
      ttlSeconds > MAX_SAST_SANDBOX_ATTESTATION_TTL_SECONDS ||
      !Number.isSafeInteger(binding.attemptNumber) ||
      binding.attemptNumber < 1 ||
      binding.attemptNumber > 2 ||
      !isSastScanPlanValid(binding.plan) ||
      !isSastSandboxRuntimePolicyValid(binding.policy, binding.plan)
    ) {
      throw new Error('Sandbox runtime attestation binding is invalid.');
    }

    const issuedAt = now.toISOString();
    const attemptDeadlineAt = new Date(
      now.getTime() +
        binding.plan.profile.limits.wallClockTimeoutSeconds * 1_000
    ).toISOString();
    const claims: SastSandboxRuntimeAttestationClaims = {
      version: SAST_SANDBOX_ATTESTATION_VERSION,
      issuer: SAST_SANDBOX_ATTESTATION_ISSUER,
      audience: SAST_SANDBOX_ATTESTATION_AUDIENCE,
      tenantId: binding.plan.tenantId,
      repositoryBindingId: binding.plan.repositoryState.repositoryBindingId,
      scanRequestId: binding.plan.scanRequestId,
      attemptId: binding.attemptId,
      attemptNumber: binding.attemptNumber,
      sandboxId: binding.sandboxId,
      workloadIdentityRef: binding.workloadIdentityRef,
      planDigest: this.planDigest(binding.plan),
      canonicalScanKey: binding.plan.canonicalScanKey,
      fixedCommitSha: binding.plan.repositoryState.fixedCommitSha,
      profileId: binding.plan.profile.id,
      profileDigest: binding.plan.profileDigest,
      scannerSetDigest: binding.plan.scannerSet.scannerSetDigest,
      preflightAttestationRef: binding.plan.repositoryState.attestationRef,
      preflightInventoryDigest: binding.plan.repositoryState.inventoryDigest,
      policy: binding.policy,
      nonce: randomBytes(16).toString('hex'),
      issuedAt,
      expiresAt: new Date(now.getTime() + ttlSeconds * 1_000).toISOString(),
      attemptDeadlineAt
    };

    return {
      claims,
      signature: this.sign('sandbox-runtime-attestation', this.canonicalClaims(claims))
    };
  }

  verify(
    attestation: SastSandboxRuntimeAttestation,
    expected: SandboxRuntimeAttestationBinding,
    now = new Date()
  ): boolean {
    try {
      const claims = attestation?.claims;
      if (
        !claims ||
        !isSastScanPlanValid(expected.plan) ||
        !this.hasOnlyKeys(attestation, ['claims', 'signature']) ||
        !this.hasOnlyKeys(claims, [
          'attemptId',
          'attemptNumber',
          'attemptDeadlineAt',
          'audience',
          'canonicalScanKey',
          'expiresAt',
          'fixedCommitSha',
          'issuedAt',
          'issuer',
          'nonce',
          'planDigest',
          'policy',
          'preflightAttestationRef',
          'preflightInventoryDigest',
          'profileDigest',
          'profileId',
          'repositoryBindingId',
          'sandboxId',
          'scannerSetDigest',
          'scanRequestId',
          'tenantId',
          'version',
          'workloadIdentityRef'
        ]) ||
        !this.safeEqual(
          attestation.signature,
          this.sign(
            'sandbox-runtime-attestation',
            this.canonicalClaims(claims)
          )
        ) ||
        !isSastSandboxRuntimePolicyValid(claims.policy, expected.plan)
      ) {
        return false;
      }

      const issuedAt = Date.parse(claims.issuedAt);
      const expiresAt = Date.parse(claims.expiresAt);
      const attemptDeadlineAt = Date.parse(claims.attemptDeadlineAt);
      const maximumExpiry =
        issuedAt + MAX_SAST_SANDBOX_ATTESTATION_TTL_SECONDS * 1_000;
      const expectedAttemptDeadline =
        issuedAt +
        expected.plan.profile.limits.wallClockTimeoutSeconds * 1_000;

      return (
        claims.version === SAST_SANDBOX_ATTESTATION_VERSION &&
        claims.issuer === SAST_SANDBOX_ATTESTATION_ISSUER &&
        claims.audience === SAST_SANDBOX_ATTESTATION_AUDIENCE &&
        claims.tenantId === expected.plan.tenantId &&
        claims.repositoryBindingId ===
          expected.plan.repositoryState.repositoryBindingId &&
        claims.scanRequestId === expected.plan.scanRequestId &&
        claims.attemptId === expected.attemptId &&
        claims.attemptNumber === expected.attemptNumber &&
        claims.sandboxId === expected.sandboxId &&
        claims.workloadIdentityRef === expected.workloadIdentityRef &&
        claims.planDigest === this.planDigest(expected.plan) &&
        claims.canonicalScanKey === expected.plan.canonicalScanKey &&
        claims.fixedCommitSha ===
          expected.plan.repositoryState.fixedCommitSha &&
        claims.profileId === expected.plan.profile.id &&
        claims.profileDigest === expected.plan.profileDigest &&
        claims.scannerSetDigest ===
          expected.plan.scannerSet.scannerSetDigest &&
        claims.preflightAttestationRef ===
          expected.plan.repositoryState.attestationRef &&
        claims.preflightInventoryDigest ===
          expected.plan.repositoryState.inventoryDigest &&
        this.canonicalPolicy(claims.policy) ===
          this.canonicalPolicy(expected.policy) &&
        /^[a-f0-9]{32}$/u.test(claims.nonce) &&
        Number.isFinite(issuedAt) &&
        Number.isFinite(expiresAt) &&
        Number.isFinite(attemptDeadlineAt) &&
        issuedAt <= now.getTime() + MAX_CLOCK_SKEW_MS &&
        expiresAt > now.getTime() &&
        expiresAt > issuedAt &&
        expiresAt <= maximumExpiry &&
        attemptDeadlineAt === expectedAttemptDeadline &&
        attemptDeadlineAt > now.getTime()
      );
    } catch {
      return false;
    }
  }

  issueCleanup(
    observation: SastSandboxCleanupObservation
  ): SastSignedSandboxCleanupObservation {
    this.assertCleanupShape(observation);
    if (
      !this.hasOnlyKeys(observation, [
        'attemptId',
        'completedAt',
        'credentialRevokedAndWiped',
        'microVmTerminated',
        'nonce',
        'repositoryBindingId',
        'resultIngressClosed',
        'sandboxId',
        'scannerProcessesTerminated',
        'scanRequestId',
        'tenantId',
        'workloadIdentityRef',
        'writableVolumesDestroyed'
      ])
    ) {
      throw new Error('Sandbox cleanup observation contains unknown fields.');
    }
    return {
      observation,
      signature: this.sign(
        'sandbox-cleanup-observation',
        this.canonicalCleanup(observation)
      )
    };
  }

  verifyCleanup(
    signed: SastSignedSandboxCleanupObservation,
    expected: Omit<
      SastSandboxCleanupObservation,
      | 'credentialRevokedAndWiped'
      | 'scannerProcessesTerminated'
      | 'writableVolumesDestroyed'
      | 'microVmTerminated'
      | 'resultIngressClosed'
      | 'completedAt'
      | 'nonce'
    >,
    now = new Date()
  ): boolean {
    try {
      const observation = signed?.observation;
      this.assertCleanupShape(observation);
      const completedAt = Date.parse(observation.completedAt);

      return (
        this.hasOnlyKeys(signed, ['observation', 'signature']) &&
        this.hasOnlyKeys(observation, [
          'attemptId',
          'completedAt',
          'credentialRevokedAndWiped',
          'microVmTerminated',
          'nonce',
          'repositoryBindingId',
          'resultIngressClosed',
          'sandboxId',
          'scannerProcessesTerminated',
          'scanRequestId',
          'tenantId',
          'workloadIdentityRef',
          'writableVolumesDestroyed'
        ]) &&
        this.safeEqual(
          signed.signature,
          this.sign(
            'sandbox-cleanup-observation',
            this.canonicalCleanup(observation)
          )
        ) &&
        observation.tenantId === expected.tenantId &&
        observation.repositoryBindingId === expected.repositoryBindingId &&
        observation.scanRequestId === expected.scanRequestId &&
        observation.attemptId === expected.attemptId &&
        observation.sandboxId === expected.sandboxId &&
        observation.workloadIdentityRef === expected.workloadIdentityRef &&
        observation.credentialRevokedAndWiped === true &&
        observation.scannerProcessesTerminated === true &&
        observation.writableVolumesDestroyed === true &&
        observation.microVmTerminated === true &&
        observation.resultIngressClosed === true &&
        completedAt <= now.getTime() + MAX_CLOCK_SKEW_MS &&
        completedAt >=
          now.getTime() -
            MAX_SAST_SANDBOX_ATTESTATION_TTL_SECONDS * 1_000
      );
    } catch {
      return false;
    }
  }

  private assertCleanupShape(
    observation: SastSandboxCleanupObservation
  ): void {
    if (
      !observation ||
      !this.isBoundedIdentifier(observation.tenantId, 255) ||
      !this.isBoundedIdentifier(observation.repositoryBindingId, 255) ||
      !this.isBoundedIdentifier(observation.scanRequestId, 255) ||
      !this.isBoundedIdentifier(observation.attemptId, 255) ||
      !this.isBoundedIdentifier(observation.sandboxId, 255) ||
      !this.isBoundedIdentifier(observation.workloadIdentityRef, 512) ||
      !Number.isFinite(Date.parse(observation.completedAt)) ||
      !/^[a-f0-9]{32}$/u.test(observation.nonce) ||
      typeof observation.credentialRevokedAndWiped !== 'boolean' ||
      typeof observation.scannerProcessesTerminated !== 'boolean' ||
      typeof observation.writableVolumesDestroyed !== 'boolean' ||
      typeof observation.microVmTerminated !== 'boolean' ||
      typeof observation.resultIngressClosed !== 'boolean'
    ) {
      throw new Error('Sandbox cleanup observation is invalid.');
    }
  }

  private hasOnlyKeys(value: unknown, allowedKeys: readonly string[]): boolean {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return false;
    }
    const allowed = new Set(allowedKeys);
    return Object.keys(value).every((key) => allowed.has(key));
  }

  private planDigest(plan: SastScanPlan): `sha256:${string}` {
    return `sha256:${createHash('sha256')
      .update(buildSastScanPlanDigestPreimage(plan), 'utf8')
      .digest('hex')}`;
  }

  private canonicalClaims(
    claims: SastSandboxRuntimeAttestationClaims
  ): string {
    return JSON.stringify({
      version: claims.version,
      issuer: claims.issuer,
      audience: claims.audience,
      tenantId: claims.tenantId,
      repositoryBindingId: claims.repositoryBindingId,
      scanRequestId: claims.scanRequestId,
      attemptId: claims.attemptId,
      attemptNumber: claims.attemptNumber,
      sandboxId: claims.sandboxId,
      workloadIdentityRef: claims.workloadIdentityRef,
      planDigest: claims.planDigest,
      canonicalScanKey: claims.canonicalScanKey,
      fixedCommitSha: claims.fixedCommitSha,
      profileId: claims.profileId,
      profileDigest: claims.profileDigest,
      scannerSetDigest: claims.scannerSetDigest,
      preflightAttestationRef: claims.preflightAttestationRef,
      preflightInventoryDigest: claims.preflightInventoryDigest,
      policy: JSON.parse(this.canonicalPolicy(claims.policy)) as unknown,
      nonce: claims.nonce,
      issuedAt: claims.issuedAt,
      expiresAt: claims.expiresAt,
      attemptDeadlineAt: claims.attemptDeadlineAt
    });
  }

  private canonicalPolicy(policy: SastSandboxRuntimePolicy): string {
    return JSON.stringify({
      sandboxProvider: policy.sandboxProvider,
      isolationClass: policy.isolationClass,
      runAsNonRoot: policy.runAsNonRoot,
      readOnlyRootFilesystem: policy.readOnlyRootFilesystem,
      readOnlyRepository: policy.readOnlyRepository,
      privateWritableOutput: policy.privateWritableOutput,
      shellInterpolationAllowed: policy.shellInterpolationAllowed,
      customerEnvironmentAllowed: policy.customerEnvironmentAllowed,
      customerExecutableConfigAllowed:
        policy.customerExecutableConfigAllowed,
      customerSuppressionConfigAllowed:
        policy.customerSuppressionConfigAllowed,
      repositoryToolConfigDiscoveryAllowed:
        policy.repositoryToolConfigDiscoveryAllowed,
      packageInstallAllowed: policy.packageInstallAllowed,
      repositoryBuildAllowed: policy.repositoryBuildAllowed,
      dynamicExecutionAllowed: policy.dynamicExecutionAllowed,
      runtimeAssetUpdateAllowed: policy.runtimeAssetUpdateAllowed,
      publicInternetEgressAllowed: policy.publicInternetEgressAllowed,
      cloudMetadataAccessAllowed: policy.cloudMetadataAccessAllowed,
      networkEgressPolicy: policy.networkEgressPolicy,
      resourceLimits: {
        cpuMillicores: policy.resourceLimits.cpuMillicores,
        memoryMiB: policy.resourceLimits.memoryMiB,
        ephemeralDiskMiB: policy.resourceLimits.ephemeralDiskMiB,
        processLimit: policy.resourceLimits.processLimit,
        fileDescriptorLimit: policy.resourceLimits.fileDescriptorLimit,
        maxFindings: policy.resourceLimits.maxFindings,
        maxArtifactBytes: policy.resourceLimits.maxArtifactBytes,
        maxArtifactRecords: policy.resourceLimits.maxArtifactRecords,
        maxStdoutStderrBytes:
          policy.resourceLimits.maxStdoutStderrBytes,
        wallClockTimeoutSeconds:
          policy.resourceLimits.wallClockTimeoutSeconds
      }
    });
  }

  private canonicalCleanup(
    observation: SastSandboxCleanupObservation
  ): string {
    return JSON.stringify({
      version: '1',
      tenantId: observation.tenantId,
      repositoryBindingId: observation.repositoryBindingId,
      scanRequestId: observation.scanRequestId,
      attemptId: observation.attemptId,
      sandboxId: observation.sandboxId,
      workloadIdentityRef: observation.workloadIdentityRef,
      credentialRevokedAndWiped:
        observation.credentialRevokedAndWiped,
      scannerProcessesTerminated:
        observation.scannerProcessesTerminated,
      writableVolumesDestroyed: observation.writableVolumesDestroyed,
      microVmTerminated: observation.microVmTerminated,
      resultIngressClosed: observation.resultIngressClosed,
      completedAt: observation.completedAt,
      nonce: observation.nonce
    });
  }

  private sign(
    domain: 'sandbox-runtime-attestation' | 'sandbox-cleanup-observation',
    payload: string
  ): `sha256:${string}` {
    const key = Buffer.from(
      this.config.get('SANDBOX_ATTESTATION_KEY'),
      'hex'
    );
    try {
      return `sha256:${createHmac('sha256', key)
        .update(`${domain}\0${payload}`, 'utf8')
        .digest('hex')}`;
    } finally {
      key.fill(0);
    }
  }

  private safeEqual(actual: string, expected: string): boolean {
    if (
      !/^sha256:[a-f0-9]{64}$/u.test(actual) ||
      !/^sha256:[a-f0-9]{64}$/u.test(expected)
    ) {
      return false;
    }
    const actualBuffer = Buffer.from(actual, 'utf8');
    const expectedBuffer = Buffer.from(expected, 'utf8');
    return (
      actualBuffer.length === expectedBuffer.length &&
      timingSafeEqual(actualBuffer, expectedBuffer)
    );
  }

  private isBoundedIdentifier(value: string, maximumBytes: number): boolean {
    return (
      typeof value === 'string' &&
      value.trim().length > 0 &&
      Buffer.byteLength(value, 'utf8') <= maximumBytes &&
      !Array.from(value).some((character) => {
        const codePoint = character.codePointAt(0) ?? 0;
        return codePoint <= 31 || codePoint === 127;
      })
    );
  }
}
