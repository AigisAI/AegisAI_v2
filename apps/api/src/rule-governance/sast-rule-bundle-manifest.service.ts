import {
  buildSastRuleBundleCompatibilityReceipt,
  buildSastProfileDigestPreimage,
  findSastRuleBundleCompatibilityReasonCodes,
  isAttestationBoundToManifest,
  isSastRuleBundleCompatibilityContextShapeValid,
  isSastRuleBundleManifestShapeValid,
  isSastRuleBundleSupplyChainAttestationShapeValid,
  isSastScanProfileValid,
  isScannerSetDescriptorValid,
  type RuleBundleDescriptor,
  type SastRuleBundleCompatibilityContext,
  type SastRuleBundleManifest,
  type VerifiedRuleBundleDescriptor,
  type VerifiedScannerSetDescriptor
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import {
  SastRuleBundleCompatibilityGate,
  SastRuleBundleCompatibilityGateError,
  type SastRuleBundleCompatibilityGateInput
} from './sast-rule-bundle-compatibility.gate';
import {
  SastRuleBundleManifestPersistenceError,
  SastRuleBundleManifestStore,
  type PersistedVerifiedSastRuleBundle
} from './sast-rule-bundle-manifest.store';
import {
  SastRuleBundleSupplyChainAuthority,
  SastRuleBundleSupplyChainVerificationError
} from './sast-rule-bundle-supply-chain.authority';
import { digestSastRuleBundleCanonical } from './sast-rule-bundle-canonical';

@Injectable()
export class SastRuleBundleManifestService extends SastRuleBundleCompatibilityGate {
  constructor(
    private readonly store: SastRuleBundleManifestStore,
    private readonly supplyChainAuthority: SastRuleBundleSupplyChainAuthority
  ) {
    super();
  }

  async registerVerifiedManifest(
    manifest: Readonly<SastRuleBundleManifest>
  ): Promise<PersistedVerifiedSastRuleBundle> {
    if (
      !isSastRuleBundleManifestShapeValid(
        manifest,
        digestSastRuleBundleCanonical
      )
    ) {
      throw new SastRuleBundleSupplyChainVerificationError(
        'SUBJECT_MISMATCH'
      );
    }

    const attestation = await this.supplyChainAuthority.verify(manifest);
    if (
      !isSastRuleBundleSupplyChainAttestationShapeValid(
        attestation,
        digestSastRuleBundleCanonical
      ) ||
      !isAttestationBoundToManifest(attestation, manifest) ||
      Date.parse(attestation.verifiedAt) < Date.parse(manifest.builtAt)
    ) {
      throw new SastRuleBundleSupplyChainVerificationError(
        'SUBJECT_MISMATCH'
      );
    }

    return this.store.registerVerified({ manifest, attestation });
  }

  async verifyScannerSet(
    input: Readonly<SastRuleBundleCompatibilityGateInput>
  ): Promise<VerifiedScannerSetDescriptor> {
    if (
      !isScannerSetDescriptorValid(input.scannerSet) ||
      !isSastScanProfileValid(input.profile) ||
      digestSastRuleBundleCanonical(
        buildSastProfileDigestPreimage(input.profile)
      ) !== input.profileDigest ||
      !isIsoTimestamp(input.evaluatedAt)
    ) {
      throw new SastRuleBundleCompatibilityGateError(
        'MANIFEST_MISMATCH'
      );
    }

    const verifiedBundles: VerifiedRuleBundleDescriptor[] = [];
    for (const descriptor of input.scannerSet.ruleBundles) {
      const verified = await this.loadVerified(descriptor.manifestId);
      if (!manifestProjectionMatches(descriptor, verified)) {
        throw new SastRuleBundleCompatibilityGateError(
          'MANIFEST_MISMATCH'
        );
      }
      if (
        Date.parse(input.evaluatedAt) <
        Date.parse(verified.attestation.verifiedAt)
      ) {
        throw new SastRuleBundleCompatibilityGateError(
          'MANIFEST_UNVERIFIED'
        );
      }

      const scanner = input.scannerSet.scanners[descriptor.scanner];
      const context: SastRuleBundleCompatibilityContext = {
        scannerSetDigest: input.scannerSet.scannerSetDigest,
        profileId: input.profile.id,
        profileDigest: input.profileDigest,
        scanner: descriptor.scanner,
        scannerVersion: scanner.version,
        scannerImageDigest: scanner.digest,
        wrapperDigest: scanner.wrapper.digest,
        schemaBundleDigest: input.scannerSet.schemaBundle.digest,
        normalizerBundleDigest: input.scannerSet.normalizerBundle.digest
      };
      if (!isSastRuleBundleCompatibilityContextShapeValid(context)) {
        throw new SastRuleBundleCompatibilityGateError(
          'MANIFEST_MISMATCH'
        );
      }
      if (
        findSastRuleBundleCompatibilityReasonCodes(
          verified.manifest,
          context
        ).length > 0
      ) {
        throw new SastRuleBundleCompatibilityGateError(
          'COMPATIBILITY_UNSUPPORTED'
        );
      }

      const receipt = buildSastRuleBundleCompatibilityReceipt({
        manifest: verified.manifest,
        attestation: verified.attestation,
        context,
        evaluatedAt: input.evaluatedAt,
        digestCanonical: digestSastRuleBundleCanonical
      });
      if (!receipt) {
        throw new SastRuleBundleCompatibilityGateError(
          'COMPATIBILITY_UNSUPPORTED'
        );
      }

      let persistedReceipt;
      try {
        persistedReceipt = await this.store.recordCompatibilityReceipt(
          receipt
        );
      } catch (error) {
        if (error instanceof SastRuleBundleManifestPersistenceError) {
          throw new SastRuleBundleCompatibilityGateError(
            'VERIFICATION_UNAVAILABLE'
          );
        }
        throw error;
      }
      verifiedBundles.push({
        ...descriptor,
        compatibilityReceiptId: persistedReceipt.receipt.receiptId,
        compatibilityReceiptDigest:
          persistedReceipt.receipt.receiptDigest
      });
    }

    return {
      ...input.scannerSet,
      scanners: {
        OPENGREP: { ...input.scannerSet.scanners.OPENGREP, wrapper: { ...input.scannerSet.scanners.OPENGREP.wrapper } },
        TRIVY: { ...input.scannerSet.scanners.TRIVY, wrapper: { ...input.scannerSet.scanners.TRIVY.wrapper } },
        SYFT: { ...input.scannerSet.scanners.SYFT, wrapper: { ...input.scannerSet.scanners.SYFT.wrapper } }
      },
      ruleBundles: verifiedBundles,
      vulnerabilityDatabase: { ...input.scannerSet.vulnerabilityDatabase },
      schemaBundle: { ...input.scannerSet.schemaBundle },
      normalizerBundle: { ...input.scannerSet.normalizerBundle }
    };
  }

  private async loadVerified(
    manifestId: string
  ): Promise<PersistedVerifiedSastRuleBundle> {
    try {
      const verified = await this.store.findVerified(manifestId);
      if (!verified) {
        throw new SastRuleBundleCompatibilityGateError(
          'MANIFEST_UNVERIFIED'
        );
      }
      return verified;
    } catch (error) {
      if (error instanceof SastRuleBundleCompatibilityGateError) {
        throw error;
      }
      if (error instanceof SastRuleBundleManifestPersistenceError) {
        throw new SastRuleBundleCompatibilityGateError(
          'VERIFICATION_UNAVAILABLE'
        );
      }
      throw error;
    }
  }
}

function manifestProjectionMatches(
  descriptor: Readonly<RuleBundleDescriptor>,
  verified: Readonly<PersistedVerifiedSastRuleBundle>
): boolean {
  const { manifest, attestation } = verified;
  return (
    descriptor.bundleId === manifest.bundleId &&
    descriptor.version === manifest.bundleVersion &&
    descriptor.state === manifest.lifecycleState &&
    descriptor.digest === manifest.bundleDigest &&
    descriptor.manifestId === manifest.manifestId &&
    descriptor.manifestDigest === manifest.manifestDigest &&
    descriptor.verificationId === attestation.verificationId &&
    descriptor.verificationDigest === attestation.attestationDigest &&
    descriptor.signatureRef === manifest.signatureRef &&
    descriptor.provenanceRef === manifest.provenanceRef &&
    descriptor.compatibilityRef === manifest.compatibilityRef &&
    descriptor.rolloutPolicyRef === manifest.rolloutPolicyRef &&
    descriptor.killSwitchRef === manifest.killSwitchRef &&
    descriptor.rollbackTargetDigest === manifest.rollbackTargetDigest &&
    descriptor.scanner === manifest.scanner &&
    descriptor.source === manifest.source &&
    descriptor.immutable === manifest.immutable &&
    descriptor.customerExecutableConfigAllowed ===
      manifest.customerExecutableConfigAllowed &&
    stableJson(descriptor.rules) === stableJson(manifest.rules)
  );
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableJson(entry)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
    .join(',')}}`;
}

function isIsoTimestamp(value: string): boolean {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}
