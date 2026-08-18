import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_FORBIDDEN_CAPABILITIES,
  SAST_SCAN_PROFILES,
  type SastProfileId,
  type SastScanPlan,
  type VerifiedSastRuleBundleLifecycleDescriptor,
  type VerifiedSastTenantRulePolicyDescriptor
} from '@aegisai/shared';

import { fixtureDigest } from './sast-finding-lineage-fixtures';

export function durableSastScanPlan(
  options: {
    tenantId?: string;
    repositoryBindingId?: string;
    scanRequestId?: string;
    canonicalScanKey?: `sha256:${string}`;
    profileId?: SastProfileId;
    fixedCommitSha?: string;
    targetRef?: string;
  } = {}
): SastScanPlan {
  const profile = SAST_SCAN_PROFILES[
    options.profileId ?? 'JAVA_FAST_V1'
  ];
  return {
    tenantId: options.tenantId ?? 'tenant-1',
    scanRequestId: options.scanRequestId ?? 'scan-1',
    canonicalScanKey:
      options.canonicalScanKey ?? fixtureDigest('fixture'),
    profile,
    profileDigest: SAST_APPROVED_PROFILE_DIGESTS[profile.id],
    policyVersion: 'policy-v1',
    tenantRulePolicy: verifiedTenantRulePolicy('policy-v1'),
    repositoryState: {
      repositoryBindingId:
        options.repositoryBindingId ?? 'repository-1',
      fixedCommitSha: options.fixedCommitSha ?? 'a'.repeat(40),
      targetRef: options.targetRef ?? 'refs/heads/main',
      inventoryDigest: fixtureDigest('inventory'),
      attestationRef: 'preflight://attempt-1',
      shallowFetchPreferred: true,
      submodulesEnabled: false,
      lfsObjectsFetched: false
    },
    scannerSet: {
      scannerSetVersion: 'scanner-set-v1',
      scannerSetDigest: fixtureDigest('scanner-set'),
      signatureRef: 'signature://scanner-set-v1',
      provenanceRef: 'provenance://scanner-set-v1',
      scanners: {
        OPENGREP: scannerDescriptor(
          'OPENGREP',
          '1.22.0',
          'opengrep'
        ),
        TRIVY: scannerDescriptor('TRIVY', '0.66.0', 'trivy'),
        SYFT: scannerDescriptor('SYFT', '1.44.0', 'syft')
      },
      ruleBundles: [
        ruleBundle('OPENGREP', 'opengrep'),
        ruleBundle('TRIVY', 'trivy')
      ],
      vulnerabilityDatabase: {
        databaseVersion: '2026-07-30',
        publishedAt: '2026-07-30T00:00:00.000Z',
        digest: fixtureDigest('trivy-db'),
        signatureRef: 'signature://trivy-db',
        provenanceRef: 'provenance://trivy-db'
      },
      schemaBundle: {
        digest: fixtureDigest('schema'),
        signatureRef: 'signature://schema',
        provenanceRef: 'provenance://schema'
      },
      normalizerBundle: {
        digest: fixtureDigest('normalizer'),
        signatureRef: 'signature://normalizer',
        provenanceRef: 'provenance://normalizer'
      },
      sbomSchema: 'CYCLONEDX_JSON',
      rollbackRef: 'rollback://scanner-set-v1'
    },
    isolationClass: 'HARDENED',
    resultIngressRef: 'result-ingress://tenant-1/scan-1',
    evidenceOutputRef: 'evidence-output://tenant-1/scan-1',
    auditSinkRef: 'audit-sink://tenant-1/scan-1',
    forbiddenCapabilities: [...SAST_FORBIDDEN_CAPABILITIES],
    createdAt: '2026-07-29T23:00:00.000Z'
  };
}

export function verifiedTenantRulePolicy(
  policyVersion = 'policy-v1'
): VerifiedSastTenantRulePolicyDescriptor {
  const policyDigest = fixtureDigest(`policy:${policyVersion}`);
  const policySuffix = policyDigest.slice('sha256:'.length);
  const resolutionDigest = fixtureDigest(
    `policy-resolution:${policyVersion}`
  );
  const resolutionSuffix = resolutionDigest.slice('sha256:'.length);
  return {
    policyId: `sast-tenant-rule-policy://${policySuffix}`,
    policyVersion,
    policyDigest,
    resolutionReceiptId:
      `sast-tenant-rule-policy-resolution://${resolutionSuffix}`,
    resolutionIdentityDigest: resolutionDigest,
    resolutionReceiptDigest: resolutionDigest,
    semanticMetadataSetDigest: fixtureDigest(
      `semantic-metadata-set:${policyVersion}`
    ),
    ruleResolutionDigest: fixtureDigest(
      `rule-resolution:${policyVersion}`
    ),
    enabledRuleSetDigest: fixtureDigest(
      `enabled-rules:${policyVersion}`
    ),
    disabledRuleSetDigest: fixtureDigest(
      `disabled-rules:${policyVersion}`
    ),
    pathExclusionDigest: fixtureDigest(
      `path-exclusions:${policyVersion}`
    ),
    severityFloors: {
      dashboard: 'INFO',
      publication: 'MEDIUM'
    }
  };
}

export function verifiedRuleBundleLifecycle(
  seed: string,
  lifecycleState: 'CANARY' | 'ACTIVE' = 'ACTIVE'
): VerifiedSastRuleBundleLifecycleDescriptor {
  const transitionDigest = fixtureDigest(`${seed}-lifecycle-transition`);
  const evidenceDigest = fixtureDigest(`${seed}-promotion-evidence`);
  const selectionDigest = fixtureDigest(`${seed}-lifecycle-selection`);
  return {
    lifecycleState,
    lifecycleSequence: lifecycleState === 'CANARY' ? 2 : 3,
    lifecycleTransitionId:
      `sast-rule-bundle-lifecycle-transition://${transitionDigest.slice('sha256:'.length)}`,
    lifecycleTransitionDigest: transitionDigest,
    promotionEvidenceId:
      `sast-rule-bundle-promotion-evidence://${evidenceDigest.slice('sha256:'.length)}`,
    promotionEvidenceDigest: evidenceDigest,
    approvalSetDigest: fixtureDigest(`${seed}-approval-set`),
    selectionReceiptId:
      `sast-rule-bundle-lifecycle-selection://${selectionDigest.slice('sha256:'.length)}`,
    selectionReceiptDigest: selectionDigest
  };
}

function scannerDescriptor(
  scanner: 'OPENGREP' | 'TRIVY' | 'SYFT',
  version: string,
  seed: string
) {
  return {
    scanner,
    version,
    digest: fixtureDigest(`${seed}-image`),
    signatureRef: `signature://${seed}-image`,
    provenanceRef: `provenance://${seed}-image`,
    sbomRef: `sbom://${seed}-image`,
    wrapper: {
      digest: fixtureDigest(`${seed}-wrapper`),
      signatureRef: `signature://${seed}-wrapper`,
      provenanceRef: `provenance://${seed}-wrapper`
    }
  };
}

function ruleBundle(
  scanner: 'OPENGREP' | 'TRIVY',
  seed: string
) {
  return {
    bundleId: `${seed}-bundle-v1`,
    version: '1',
    state: 'ACTIVE' as const,
    digest: fixtureDigest(`${seed}-bundle`),
    manifestId: `sast-rule-bundle-manifest://${fixtureDigest(`${seed}-manifest`).slice('sha256:'.length)}`,
    manifestDigest: fixtureDigest(`${seed}-manifest`),
    verificationId: `sast-rule-bundle-verification://${fixtureDigest(`${seed}-manifest`).slice('sha256:'.length)}`,
    verificationDigest: fixtureDigest(`${seed}-verification`),
    signatureRef: `signature://${seed}-bundle`,
    provenanceRef: `provenance://${seed}-bundle`,
    compatibilityRef: `compatibility://${seed}-bundle`,
    rolloutPolicyRef: `rollout://${seed}-bundle`,
    killSwitchRef: `kill-switch://${seed}-bundle`,
    rollbackTargetDigest: fixtureDigest(`${seed}-rollback`),
    compatibilityReceiptId: `sast-rule-bundle-compatibility://${fixtureDigest(`${seed}-receipt`).slice('sha256:'.length)}`,
    compatibilityReceiptDigest: fixtureDigest(`${seed}-receipt`),
    lifecycle: verifiedRuleBundleLifecycle(seed),
    canaryAssignment: null,
    scanner,
    source: 'PLATFORM_MANAGED' as const,
    immutable: true as const,
    customerExecutableConfigAllowed: false as const,
    rules: [
      {
        ruleId: `${seed}.fixture`,
        ruleRevision: '1',
        ruleSemanticId: `${seed}.fixture`,
        metadataDigest: fixtureDigest(`${seed}-metadata`)
      }
    ]
  };
}
