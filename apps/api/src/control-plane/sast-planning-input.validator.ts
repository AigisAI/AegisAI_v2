import {
  registerDecorator,
  type ValidationArguments,
  type ValidationOptions
} from 'class-validator';
import {
  isSastProfileSelectionPolicyValid,
  isSastQueuePolicySetValid,
  isSastQueueUsageSnapshotValid,
  isScannerSetDescriptorValid,
  isTrustedSastRepositoryMetadataValid,
  type SastProfileSelectionPolicy,
  type SastQueuePolicySet,
  type SastQueueUsageSnapshot,
  type ScannerSetDescriptor,
  type TrustedSastRepositoryMetadata
} from '@aegisai/shared';

export type SastPlanningInputKind =
  | 'REPOSITORY_METADATA'
  | 'PROFILE_POLICY'
  | 'SCANNER_SET'
  | 'QUEUE_POLICY_SET'
  | 'QUEUE_USAGE';

export function IsValidSastPlanningInput(
  kind: SastPlanningInputKind,
  validationOptions?: ValidationOptions
): PropertyDecorator {
  return (target: object, propertyName: string | symbol) => {
    registerDecorator({
      name: 'isValidSastPlanningInput',
      target: target.constructor,
      propertyName: propertyName.toString(),
      constraints: [kind],
      options: validationOptions,
      validator: {
        validate(value: unknown, args: ValidationArguments): boolean {
          return validatePlanningInput(args.constraints[0] as SastPlanningInputKind, value);
        },
        defaultMessage(args: ValidationArguments): string {
          return `${args.property} contains an invalid or unsupported SAST planning payload`;
        }
      }
    });
  };
}

function validatePlanningInput(kind: SastPlanningInputKind, value: unknown): boolean {
  try {
    switch (kind) {
      case 'REPOSITORY_METADATA':
        return (
          hasRepositoryMetadataShape(value) &&
          isTrustedSastRepositoryMetadataValid(value as TrustedSastRepositoryMetadata)
        );
      case 'PROFILE_POLICY':
        return (
          hasOnlyKeys(value, [
            'policyVersion',
            'allowedProfileIds',
            'requireLanguageSpecificSast'
          ]) &&
          isSastProfileSelectionPolicyValid(value as SastProfileSelectionPolicy)
        );
      case 'SCANNER_SET':
        return (
          hasScannerSetShape(value) &&
          isScannerSetDescriptorValid(value as ScannerSetDescriptor)
        );
      case 'QUEUE_POLICY_SET':
        return (
          hasQueuePolicySetShape(value) &&
          isSastQueuePolicySetValid(value as SastQueuePolicySet)
        );
      case 'QUEUE_USAGE':
        return (
          hasOnlyKeys(value, [
            'snapshotVersion',
            'tenantId',
            'repositoryBindingId',
            'lane',
            'dailyWindowStartedAt',
            'activeForTenant',
            'queuedForTenant',
            'admittedTodayForTenant',
            'activeForRepository',
            'queuedInLane',
            'lastRepositoryAdmissionAt'
          ]) &&
          isSastQueueUsageSnapshotValid(value as SastQueueUsageSnapshot)
        );
    }
  } catch {
    return false;
  }
}

function hasRepositoryMetadataShape(value: unknown): boolean {
  if (
    !hasOnlyKeys(value, [
      'repositoryBindingId',
      'fixedCommitSha',
      'inventoryDigest',
      'attestationRef',
      'collectedAt',
      'sourceLanguages',
      'manifestNames',
      'repositoryBytes',
      'selectedBytes',
      'fileCount',
      'maxSingleFileBytes',
      'maxPathDepth'
    ])
  ) {
    return false;
  }
  const metadata = value as Record<string, unknown>;
  return (
    Array.isArray(metadata.sourceLanguages) &&
    metadata.sourceLanguages.every((signal) =>
      hasOnlyKeys(signal, ['language', 'sourceFileCount', 'sourceBytes'])
    )
  );
}

function hasScannerSetShape(value: unknown): boolean {
  if (
    !hasOnlyKeys(value, [
      'scannerSetVersion',
      'scannerSetDigest',
      'signatureRef',
      'provenanceRef',
      'scanners',
      'ruleBundles',
      'vulnerabilityDatabase',
      'schemaBundle',
      'normalizerBundle',
      'sbomSchema',
      'rollbackRef'
    ])
  ) {
    return false;
  }
  const scannerSet = value as Record<string, unknown>;
  if (
    !hasOnlyKeys(scannerSet.scanners, ['OPENGREP', 'TRIVY', 'SYFT']) ||
    !Array.isArray(scannerSet.ruleBundles)
  ) {
    return false;
  }
  const scanners = scannerSet.scanners as Record<string, unknown>;
  const scannerKeys = ['OPENGREP', 'TRIVY', 'SYFT'];
  if (
    !scannerKeys.every((scanner) => {
      const descriptor = scanners[scanner];
      return (
        hasOnlyKeys(descriptor, [
          'digest',
          'signatureRef',
          'provenanceRef',
          'scanner',
          'version',
          'sbomRef',
          'wrapper'
        ]) &&
        hasOnlyKeys((descriptor as Record<string, unknown>).wrapper, [
          'digest',
          'signatureRef',
          'provenanceRef'
        ])
      );
    })
  ) {
    return false;
  }

  return (
    scannerSet.ruleBundles.every((bundle) => {
      if (
        !hasOnlyKeys(bundle, [
          'bundleId',
          'version',
          'state',
          'digest',
          'signatureRef',
          'provenanceRef',
          'compatibilityRef',
          'rolloutPolicyRef',
          'killSwitchRef',
          'scanner',
          'source',
          'immutable',
          'customerExecutableConfigAllowed',
          'rules'
        ])
      ) {
        return false;
      }
      const rules = (bundle as Record<string, unknown>).rules;
      return (
        Array.isArray(rules) &&
        rules.every((rule) =>
          hasOnlyKeys(rule, [
            'ruleId',
            'ruleRevision',
            'ruleSemanticId',
            'metadataDigest'
          ])
        )
      );
    }) &&
    hasOnlyKeys(scannerSet.vulnerabilityDatabase, [
      'digest',
      'signatureRef',
      'provenanceRef',
      'databaseVersion',
      'publishedAt'
    ]) &&
    hasOnlyKeys(scannerSet.schemaBundle, ['digest', 'signatureRef', 'provenanceRef']) &&
    hasOnlyKeys(scannerSet.normalizerBundle, ['digest', 'signatureRef', 'provenanceRef'])
  );
}

function hasQueuePolicySetShape(value: unknown): boolean {
  if (
    !hasOnlyKeys(value, [
      'policyVersion',
      'digest',
      'signatureRef',
      'provenanceRef',
      'fairnessStrategy',
      'lanes'
    ])
  ) {
    return false;
  }
  const policySet = value as Record<string, unknown>;
  if (!hasOnlyKeys(policySet.lanes, ['FAST', 'DEEP'])) {
    return false;
  }
  const lanes = policySet.lanes as Record<string, unknown>;
  return ['FAST', 'DEEP'].every((lane) =>
    hasOnlyKeys(lanes[lane], [
      'lane',
      'queueName',
      'maxActivePerTenant',
      'maxQueuedPerTenant',
      'maxDailyAdmissionsPerTenant',
      'maxActivePerRepository',
      'minimumRepositoryIntervalSeconds',
      'maxQueuedInLane',
      'capacityRetrySeconds'
    ])
  );
}

function hasOnlyKeys(value: unknown, allowedKeys: readonly string[]): boolean {
  if (!isPlainObject(value)) {
    return false;
  }
  const allowed = new Set(allowedKeys);
  return Object.keys(value).every((key) => allowed.has(key));
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
