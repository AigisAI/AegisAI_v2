import {
  isSastScannerWrapperExecutionRequestValid,
  type SastRepositoryPreflightResult,
  type SastScannerInvocation,
  type SastScannerRepositoryManifest,
  type SastScannerWrapperExecutionRequest
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import { RepositoryPreflightAttestationService } from './repository-preflight-attestation.service';
import { RepositoryPreflightService } from './repository-preflight.service';
import { securityViolation } from './scanner-runtime.errors';

const MAX_MANIFEST_CLOCK_SKEW_MS = 5_000;
const MAX_MANIFEST_AGE_MS = 60_000;

@Injectable()
export class ScannerWorkspaceManifestService {
  constructor(
    private readonly preflight: RepositoryPreflightService,
    private readonly preflightAttestation: RepositoryPreflightAttestationService
  ) {}

  verify(
    request: SastScannerWrapperExecutionRequest,
    invocation: SastScannerInvocation,
    manifest: SastScannerRepositoryManifest,
    now = new Date()
  ): SastRepositoryPreflightResult {
    if (!isSastScannerWrapperExecutionRequestValid(request)) {
      throw securityViolation(
        'SCANNER_PLAN_BINDING_INVALID',
        'Scanner request is not bound to an immutable plan.'
      );
    }

    if (
      !this.preflightAttestation.verify(request.preflight.attestationRef, {
        attemptId: request.attemptId,
        fixedCommitSha: request.plan.repositoryState.fixedCommitSha,
        pathPolicyVersion: request.preflight.pathPolicyVersion,
        inventoryDigest: request.preflight.inventoryDigest,
        decision: request.preflight.decision
      })
    ) {
      throw securityViolation(
        'PREFLIGHT_ATTESTATION_INVALID',
        'Preflight attestation is missing, invalid, or stale for this attempt.'
      );
    }

    const observedAt =
      typeof manifest?.observedAt === 'string'
        ? Date.parse(manifest.observedAt)
        : Number.NaN;
    if (
      !manifest ||
      !this.hasOnlyKeys(manifest, [
        'entries',
        'observedAt',
        'scanner',
        'selection',
        'source'
      ]) ||
      manifest.scanner !== invocation.scanner ||
      manifest.source !== 'MICROVM_READ_ONLY_MOUNT' ||
      !Array.isArray(manifest.entries) ||
      !manifest.entries.every((entry) =>
        this.hasOnlyKeys(entry, [
          'byteSize',
          'executable',
          'gitObjectId',
          'kind',
          'lfsPointer',
          'path',
          'pathEncodingValid',
          'symlinkTarget',
          'symlinkTargetEncodingValid'
        ])
      ) ||
      !manifest.selection ||
      !this.hasOnlyKeys(manifest.selection, ['mode', 'paths']) ||
      !Number.isFinite(observedAt) ||
      observedAt > now.getTime() + MAX_MANIFEST_CLOCK_SKEW_MS ||
      observedAt < now.getTime() - MAX_MANIFEST_AGE_MS
    ) {
      throw securityViolation(
        'SCANNER_WORKSPACE_MANIFEST_INVALID',
        'Scanner-visible workspace manifest is malformed or out of scope.'
      );
    }

    let evaluated: SastRepositoryPreflightResult;
    try {
      evaluated = this.preflight.evaluate({
        attemptId: request.attemptId,
        fixedCommitSha: request.plan.repositoryState.fixedCommitSha,
        pathPolicyVersion: request.preflight.pathPolicyVersion,
        pathPolicy: request.plan.profile.pathPolicy,
        limits: request.plan.profile.limits,
        sourceExtensions: request.plan.profile.sourceExtensions,
        manifestNames: request.plan.profile.manifestNames,
        selection: manifest.selection,
        entries: manifest.entries
      });
    } catch {
      throw securityViolation(
        'SCANNER_WORKSPACE_REMANIFEST_FAILED',
        'Scanner-visible workspace could not be safely re-manifested.'
      );
    }

    if (
      evaluated.inventoryDigest !== request.preflight.inventoryDigest ||
      evaluated.inventoryDigest !== invocation.preflightInventoryDigest ||
      evaluated.decision !== request.preflight.decision
    ) {
      throw securityViolation(
        'SCANNER_WORKSPACE_DIGEST_MISMATCH',
        'Scanner-visible workspace differs from the attested preflight inventory.'
      );
    }

    return evaluated;
  }

  private hasOnlyKeys(value: unknown, allowedKeys: readonly string[]): boolean {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return false;
    }
    const allowed = new Set(allowedKeys);
    return Object.keys(value).every((key) => allowed.has(key));
  }
}
