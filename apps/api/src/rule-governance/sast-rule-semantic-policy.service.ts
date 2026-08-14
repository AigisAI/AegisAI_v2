import {
  buildSastProfileDigestPreimage,
  buildSastTenantRulePolicyResolution,
  compareSastRuleSemanticVersions,
  isSastRuleDefinitionMetadataBindingShapeValid,
  isSastScanProfileValid,
  isSastTenantRulePolicyShapeValid,
  isVerifiedScannerSetDescriptorValid,
  toVerifiedSastTenantRulePolicyDescriptor,
  type SastRuleBundleManifest,
  type SastRuleDefinitionMetadataBinding,
  type SastTenantRulePolicy,
  type VerifiedSastTenantRulePolicyDescriptor
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import { digestSastRuleBundleCanonical } from './sast-rule-bundle-canonical';
import { SastRuleBundleManifestStore } from './sast-rule-bundle-manifest.store';
import {
  SastRuleSemanticPolicyPersistenceError,
  SastRuleSemanticPolicyStore,
  type PersistedSastRuleDefinitionMetadataBinding,
  type PersistedSastTenantRulePolicy
} from './sast-rule-semantic-policy.store';
import {
  SastTenantRulePolicyGate,
  SastTenantRulePolicyGateError,
  type SastTenantRulePolicyGateInput
} from './sast-tenant-rule-policy.gate';

@Injectable()
export class SastRuleSemanticPolicyService extends SastTenantRulePolicyGate {
  constructor(
    private readonly store: SastRuleSemanticPolicyStore,
    private readonly manifestStore: SastRuleBundleManifestStore
  ) {
    super();
  }

  async registerRuleMetadataBinding(
    binding: Readonly<SastRuleDefinitionMetadataBinding>
  ): Promise<PersistedSastRuleDefinitionMetadataBinding> {
    if (
      !isSastRuleDefinitionMetadataBindingShapeValid(
        binding,
        digestSastRuleBundleCanonical
      )
    ) {
      throw new SastRuleSemanticPolicyPersistenceError('INPUT_INVALID');
    }
    const verified = await this.manifestStore.findVerified(
      binding.manifestId
    );
    if (!verified) {
      throw new SastRuleSemanticPolicyPersistenceError(
        'MANIFEST_NOT_FOUND'
      );
    }
    const manifestRule = verified.manifest.rules.find(
      (rule) => rule.ruleId === binding.ruleId
    );
    if (
      binding.manifestDigest !== verified.manifest.manifestDigest ||
      binding.bundleId !== verified.manifest.bundleId ||
      binding.bundleDigest !== verified.manifest.bundleDigest ||
      binding.scanner !== verified.manifest.scanner ||
      !manifestRule ||
      manifestRule.ruleRevision !== binding.ruleRevision ||
      manifestRule.ruleSemanticId !== binding.ruleSemanticId ||
      manifestRule.metadataDigest !== binding.metadataDigest ||
      !metadataCompatibilityMatchesManifest(
        binding,
        verified.manifest
      )
    ) {
      throw new SastRuleSemanticPolicyPersistenceError(
        'REPLAY_CONFLICT'
      );
    }
    return this.store.registerRuleMetadataBinding(binding);
  }

  async registerTenantPolicy(
    policy: Readonly<SastTenantRulePolicy>
  ): Promise<PersistedSastTenantRulePolicy> {
    if (
      !isSastTenantRulePolicyShapeValid(
        policy,
        digestSastRuleBundleCanonical
      )
    ) {
      throw new SastRuleSemanticPolicyPersistenceError('INPUT_INVALID');
    }
    return this.store.registerTenantPolicy(policy);
  }

  async resolve(
    input: Readonly<SastTenantRulePolicyGateInput>
  ): Promise<VerifiedSastTenantRulePolicyDescriptor> {
    if (
      !isGateInputValid(input) ||
      digestSastRuleBundleCanonical(
        buildSastProfileDigestPreimage(input.profile)
      ) !== input.profileDigest
    ) {
      throw new SastTenantRulePolicyGateError(
        'RULE_METADATA_MISMATCH'
      );
    }

    try {
      const persistedPolicy = await this.store.findTenantPolicy(
        input.tenantId,
        input.policyVersion
      );
      if (!persistedPolicy) {
        throw new SastTenantRulePolicyGateError(
          'TENANT_POLICY_INVALID'
        );
      }
      const manifestIds = input.scannerSet.ruleBundles
        .map((bundle) => bundle.manifestId)
        .sort(compareStrings);
      const metadataBindings = (
        await this.store.findRuleMetadataBindingsForManifests(
          manifestIds
        )
      ).sort(compareMetadataBinding);
      if (!metadataMatchesScannerSet(metadataBindings, input.scannerSet)) {
        throw new SastTenantRulePolicyGateError(
          metadataBindings.length === 0
            ? 'RULE_METADATA_UNVERIFIED'
            : 'RULE_METADATA_MISMATCH'
        );
      }
      const approved = await this.store.findApprovedPolicyTargets();
      const receipt = buildSastTenantRulePolicyResolution({
        policy: persistedPolicy.policy,
        context: {
          tenantId: input.tenantId,
          repositoryBindingId: input.repositoryBindingId,
          scannerSetDigest: input.scannerSet.scannerSetDigest,
          profileId: input.profile.id,
          profileDigest: input.profileDigest,
          evaluatedAt: input.evaluatedAt
        },
        selectedMetadata: metadataBindings,
        approvedSemanticRuleIds: approved.semanticRuleIds,
        approvedCategories: approved.categories,
        digestCanonical: digestSastRuleBundleCanonical
      });
      if (!receipt) {
        throw new SastTenantRulePolicyGateError(
          'TENANT_POLICY_INVALID'
        );
      }
      const persisted = await this.store.recordPolicyResolution(receipt);
      return toVerifiedSastTenantRulePolicyDescriptor(
        persisted.receipt
      );
    } catch (error) {
      if (error instanceof SastTenantRulePolicyGateError) throw error;
      if (error instanceof SastRuleSemanticPolicyPersistenceError) {
        throw new SastTenantRulePolicyGateError(
          error.reason === 'METADATA_NOT_FOUND'
            ? 'RULE_METADATA_UNVERIFIED'
            : error.reason === 'POLICY_NOT_FOUND' ||
                error.reason === 'TENANT_SCOPE_INVALID' ||
                error.reason === 'REFERENCE_INVALID'
              ? 'TENANT_POLICY_INVALID'
              : 'POLICY_STORE_UNAVAILABLE'
        );
      }
      throw new SastTenantRulePolicyGateError(
        'POLICY_STORE_UNAVAILABLE'
      );
    }
  }
}

function isGateInputValid(
  input: Readonly<SastTenantRulePolicyGateInput>
): boolean {
  return (
    typeof input.tenantId === 'string' &&
    input.tenantId.length > 0 &&
    typeof input.repositoryBindingId === 'string' &&
    input.repositoryBindingId.length > 0 &&
    typeof input.policyVersion === 'string' &&
    /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(input.policyVersion) &&
    isVerifiedScannerSetDescriptorValid(input.scannerSet) &&
    isSastScanProfileValid(input.profile) &&
    /^sha256:[a-f0-9]{64}$/u.test(input.profileDigest) &&
    isIsoTimestamp(input.evaluatedAt)
  );
}

function metadataCompatibilityMatchesManifest(
  binding: Readonly<SastRuleDefinitionMetadataBinding>,
  manifest: Readonly<SastRuleBundleManifest>
): boolean {
  const introduced = compareSastRuleSemanticVersions(
    manifest.bundleVersion,
    binding.metadata.introducedInBundleVersion
  );
  if (introduced === null || introduced < 0) return false;
  return manifest.compatibility.scannerVersions.every((version) => {
    const afterFirst = compareSastRuleSemanticVersions(
      version,
      binding.metadata.firstSupportedScannerVersion
    );
    const beforeLast = binding.metadata.lastSupportedScannerVersion
      ? compareSastRuleSemanticVersions(
          version,
          binding.metadata.lastSupportedScannerVersion
        )
      : 0;
    return (
      afterFirst !== null &&
      afterFirst >= 0 &&
      beforeLast !== null &&
      beforeLast <= 0
    );
  });
}

function metadataMatchesScannerSet(
  bindings: readonly Readonly<SastRuleDefinitionMetadataBinding>[],
  scannerSet: Readonly<SastTenantRulePolicyGateInput['scannerSet']>
): boolean {
  const expected = scannerSet.ruleBundles
    .flatMap((bundle) =>
      bundle.rules.map((rule) => ({
        manifestId: bundle.manifestId,
        manifestDigest: bundle.manifestDigest,
        bundleId: bundle.bundleId,
        bundleDigest: bundle.digest,
        scanner: bundle.scanner,
        ruleId: rule.ruleId,
        ruleRevision: rule.ruleRevision,
        ruleSemanticId: rule.ruleSemanticId,
        metadataDigest: rule.metadataDigest
      }))
    )
    .sort((left, right) =>
      compareStrings(
        `${left.manifestId}\u0000${left.ruleId}`,
        `${right.manifestId}\u0000${right.ruleId}`
      )
    );
  return (
    expected.length === bindings.length &&
    expected.every((rule, index) => {
      const actual = bindings[index];
      return (
        actual !== undefined &&
        actual.manifestId === rule.manifestId &&
        actual.manifestDigest === rule.manifestDigest &&
        actual.bundleId === rule.bundleId &&
        actual.bundleDigest === rule.bundleDigest &&
        actual.scanner === rule.scanner &&
        actual.ruleId === rule.ruleId &&
        actual.ruleRevision === rule.ruleRevision &&
        actual.ruleSemanticId === rule.ruleSemanticId &&
        actual.metadataDigest === rule.metadataDigest
      );
    })
  );
}

function compareMetadataBinding(
  left: Readonly<SastRuleDefinitionMetadataBinding>,
  right: Readonly<SastRuleDefinitionMetadataBinding>
): number {
  return compareStrings(
    `${left.manifestId}\u0000${left.ruleId}`,
    `${right.manifestId}\u0000${right.ruleId}`
  );
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isIsoTimestamp(value: string): boolean {
  if (
    typeof value !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
  ) {
    return false;
  }
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value;
}
