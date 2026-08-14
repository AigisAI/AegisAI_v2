import { createHash } from 'node:crypto';

import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_SCAN_PROFILES,
  buildSastRuleBundleManifest,
  buildSastRuleBundleSupplyChainAttestation,
  buildSastRuleDefinitionMetadata,
  buildSastRuleDefinitionMetadataBinding,
  buildSastTenantRulePolicy,
  type SastRuleBundleCompatibilityReceipt,
  type SastRuleBundleManifest,
  type SastRuleBundleSupplyChainAttestation,
  type SastRuleDefinitionMetadata,
  type SastRuleDefinitionMetadataBinding,
  type SastTenantRulePolicy,
  type SastTenantRulePolicyResolutionReceipt,
  type VerifiedRuleBundleDescriptor,
  type VerifiedScannerSetDescriptor
} from '@aegisai/shared';

import {
  SastRuleBundleManifestStore,
  type PersistedSastRuleBundleCompatibilityReceipt,
  type PersistedVerifiedSastRuleBundle
} from '../../src/rule-governance/sast-rule-bundle-manifest.store';
import { SastRuleSemanticPolicyService } from '../../src/rule-governance/sast-rule-semantic-policy.service';
import {
  SastRuleSemanticPolicyPersistenceError,
  SastRuleSemanticPolicyStore,
  type PersistedSastRuleDefinitionMetadataBinding,
  type PersistedSastTenantRulePolicy,
  type PersistedSastTenantRulePolicyResolution,
  type SastApprovedRulePolicyTargets
} from '../../src/rule-governance/sast-rule-semantic-policy.store';
import { durableSastScanPlan } from '../support/sast-scan-plan-fixtures';

describe('SastRuleSemanticPolicyService', () => {
  it('binds reusable metadata to both signed manifests and resolves one exact tenant receipt', async () => {
    const fixtures = governanceFixtures();
    const manifestStore = new MemoryManifestStore(fixtures.verifiedBundles);
    const policyStore = new MemorySemanticPolicyStore();
    const service = new SastRuleSemanticPolicyService(
      policyStore,
      manifestStore
    );

    await expect(
      service.registerRuleMetadataBinding(fixtures.bindings[0])
    ).resolves.toMatchObject({ replayed: false });
    await expect(
      service.registerRuleMetadataBinding(fixtures.bindings[1])
    ).resolves.toMatchObject({ replayed: false });
    await expect(service.registerTenantPolicy(fixtures.policy)).resolves.toMatchObject({
      replayed: false
    });

    const descriptor = await service.resolve({
      tenantId: 'tenant-1',
      repositoryBindingId: 'repository-1',
      policyVersion: 'policy-v1',
      scannerSet: fixtures.scannerSet,
      profile: SAST_SCAN_PROFILES.JAVA_FAST_V1,
      profileDigest: SAST_APPROVED_PROFILE_DIGESTS.JAVA_FAST_V1,
      evaluatedAt: '2026-08-13T13:00:00.000Z'
    });

    expect(descriptor).toMatchObject({
      policyId: fixtures.policy.policyId,
      policyVersion: 'policy-v1',
      policyDigest: fixtures.policy.policyDigest
    });
    expect(policyStore.receipts).toHaveLength(1);
    expect(policyStore.receipts[0].rules).toHaveLength(2);
    expect(
      policyStore.receipts[0].rules.map((rule) => rule.bindingId).sort()
    ).toEqual(fixtures.bindings.map((binding) => binding.bindingId).sort());
    expect(JSON.stringify(policyStore.receipts[0])).not.toContain('ruleContent');
  });

  it('rejects a byte-valid binding that does not match the verified manifest projection', async () => {
    const fixtures = governanceFixtures();
    const service = new SastRuleSemanticPolicyService(
      new MemorySemanticPolicyStore(),
      new MemoryManifestStore(fixtures.verifiedBundles)
    );
    const mismatched = bindMetadata(
      fixtures.metadata[0],
      fixtures.manifests[0],
      digest('wrong-manifest')
    );

    await expect(service.registerRuleMetadataBinding(mismatched)).rejects.toMatchObject({
      reason: 'REPLAY_CONFLICT'
    });
  });

  it.each([
    ['pre-introduction bundle', { introducedInBundleVersion: '2.0.0' }],
    ['unsupported scanner', { firstSupportedScannerVersion: '99.0.0' }]
  ] as const)('rejects metadata for a %s', async (_label, metadataOptions) => {
    const metadata = ruleMetadata(
      'OPENGREP',
      'java.sql-injection',
      'SAST',
      'INJECTION',
      metadataOptions
    );
    const manifest = ruleManifest('OPENGREP', metadata, '5');
    const attestation = buildSastRuleBundleSupplyChainAttestation({
      manifest,
      verifiedAt: '2026-08-13T11:00:00.000Z',
      digestCanonical: digest
    });
    if (!attestation) throw new Error('fixture attestation invalid');
    const service = new SastRuleSemanticPolicyService(
      new MemorySemanticPolicyStore(),
      new MemoryManifestStore([{ manifest, attestation, replayed: false }])
    );

    await expect(
      service.registerRuleMetadataBinding(bindMetadata(metadata, manifest))
    ).rejects.toMatchObject({ reason: 'REPLAY_CONFLICT' });
  });

  it.each([
    ['empty', 'RULE_METADATA_UNVERIFIED'],
    ['partial', 'RULE_METADATA_MISMATCH']
  ] as const)(
    'fails closed when the resolved scanner set has %s metadata',
    async (mode, expectedReason) => {
      const fixtures = governanceFixtures();
      const store = new MemorySemanticPolicyStore();
      store.policy = fixtures.policy;
      store.bindings =
        mode === 'empty' ? [] : [fixtures.bindings[0]];
      const service = new SastRuleSemanticPolicyService(
        store,
        new MemoryManifestStore(fixtures.verifiedBundles)
      );

      await expect(
        service.resolve({
          tenantId: 'tenant-1',
          repositoryBindingId: 'repository-1',
          policyVersion: 'policy-v1',
          scannerSet: fixtures.scannerSet,
          profile: SAST_SCAN_PROFILES.JAVA_FAST_V1,
          profileDigest: SAST_APPROVED_PROFILE_DIGESTS.JAVA_FAST_V1,
          evaluatedAt: '2026-08-13T13:00:00.000Z'
        })
      ).rejects.toMatchObject({ reason: expectedReason });
      expect(store.receipts).toHaveLength(0);
    }
  );

  it('maps ledger outages to one bounded fail-closed gate reason', async () => {
    const fixtures = governanceFixtures();
    const store = new MemorySemanticPolicyStore();
    store.findPolicyError = new Error('database unavailable');
    const service = new SastRuleSemanticPolicyService(
      store,
      new MemoryManifestStore(fixtures.verifiedBundles)
    );

    await expect(
      service.resolve({
        tenantId: 'tenant-1',
        repositoryBindingId: 'repository-1',
        policyVersion: 'policy-v1',
        scannerSet: fixtures.scannerSet,
        profile: SAST_SCAN_PROFILES.JAVA_FAST_V1,
        profileDigest: SAST_APPROVED_PROFILE_DIGESTS.JAVA_FAST_V1,
        evaluatedAt: '2026-08-13T13:00:00.000Z'
      })
    ).rejects.toMatchObject({ reason: 'POLICY_STORE_UNAVAILABLE' });
  });

  it.each([
    ['MANIFEST_NOT_FOUND', 'RULE_METADATA_UNVERIFIED'],
    ['METADATA_NOT_FOUND', 'RULE_METADATA_UNVERIFIED'],
    ['INPUT_INVALID', 'TENANT_POLICY_INVALID'],
    ['LEDGER_CORRUPT', 'TENANT_POLICY_INVALID'],
    ['POLICY_NOT_FOUND', 'TENANT_POLICY_INVALID'],
    ['TENANT_SCOPE_INVALID', 'TENANT_POLICY_INVALID'],
    ['REFERENCE_INVALID', 'TENANT_POLICY_INVALID'],
    ['REPLAY_CONFLICT', 'TENANT_POLICY_INVALID']
  ] as const)(
    'maps deterministic persistence failure %s to %s',
    async (persistenceReason, gateReason) => {
      const fixtures = governanceFixtures();
      const store = new MemorySemanticPolicyStore();
      store.findPolicyError =
        new SastRuleSemanticPolicyPersistenceError(persistenceReason);
      const service = new SastRuleSemanticPolicyService(
        store,
        new MemoryManifestStore(fixtures.verifiedBundles)
      );

      await expect(
        service.resolve({
          tenantId: 'tenant-1',
          repositoryBindingId: 'repository-1',
          policyVersion: 'policy-v1',
          scannerSet: fixtures.scannerSet,
          profile: SAST_SCAN_PROFILES.JAVA_FAST_V1,
          profileDigest: SAST_APPROVED_PROFILE_DIGESTS.JAVA_FAST_V1,
          evaluatedAt: '2026-08-13T13:00:00.000Z'
        })
      ).rejects.toMatchObject({ reason: gateReason });
      expect(store.receipts).toHaveLength(0);
    }
  );
});

class MemorySemanticPolicyStore extends SastRuleSemanticPolicyStore {
  bindings: SastRuleDefinitionMetadataBinding[] = [];
  policy: SastTenantRulePolicy | null = null;
  receipts: SastTenantRulePolicyResolutionReceipt[] = [];
  findPolicyError: Error | null = null;

  async registerRuleMetadataBinding(
    binding: Readonly<SastRuleDefinitionMetadataBinding>
  ): Promise<PersistedSastRuleDefinitionMetadataBinding> {
    const replayed = this.bindings.some(
      (candidate) => candidate.bindingId === binding.bindingId
    );
    if (!replayed) this.bindings.push(structuredClone(binding));
    return { binding: structuredClone(binding), replayed };
  }

  async findRuleMetadataBindingsForManifests(
    manifestIds: readonly string[]
  ): Promise<SastRuleDefinitionMetadataBinding[]> {
    return this.bindings
      .filter((binding) => manifestIds.includes(binding.manifestId))
      .map((binding) => structuredClone(binding));
  }

  async findApprovedPolicyTargets(): Promise<SastApprovedRulePolicyTargets> {
    return {
      semanticRuleIds: [...new Set(this.bindings.map((binding) => binding.ruleSemanticId))].sort(),
      categories: [
        ...new Set(
          this.bindings.map(
            (binding) => binding.metadata.semanticIdentity.category
          )
        )
      ].sort()
    };
  }

  async registerTenantPolicy(
    policy: Readonly<SastTenantRulePolicy>
  ): Promise<PersistedSastTenantRulePolicy> {
    const replayed = this.policy?.policyId === policy.policyId;
    this.policy ??= structuredClone(policy);
    return { policy: structuredClone(this.policy), replayed };
  }

  async findTenantPolicy(
    tenantId: string,
    policyVersion: string
  ): Promise<PersistedSastTenantRulePolicy | null> {
    if (this.findPolicyError) throw this.findPolicyError;
    if (
      !this.policy ||
      this.policy.tenantId !== tenantId ||
      this.policy.policyVersion !== policyVersion
    ) {
      return null;
    }
    return { policy: structuredClone(this.policy), replayed: true };
  }

  async recordPolicyResolution(
    receipt: Readonly<SastTenantRulePolicyResolutionReceipt>
  ): Promise<PersistedSastTenantRulePolicyResolution> {
    this.receipts.push(structuredClone(receipt));
    return { receipt: structuredClone(receipt), replayed: false };
  }
}

class MemoryManifestStore extends SastRuleBundleManifestStore {
  private readonly bundles = new Map<string, PersistedVerifiedSastRuleBundle>();

  constructor(bundles: readonly PersistedVerifiedSastRuleBundle[]) {
    super();
    for (const bundle of bundles) {
      this.bundles.set(bundle.manifest.manifestId, bundle);
    }
  }

  async registerVerified(input: {
    manifest: Readonly<SastRuleBundleManifest>;
    attestation: Readonly<SastRuleBundleSupplyChainAttestation>;
  }): Promise<PersistedVerifiedSastRuleBundle> {
    const result = {
      manifest: structuredClone(input.manifest),
      attestation: structuredClone(input.attestation),
      replayed: false
    };
    this.bundles.set(input.manifest.manifestId, result);
    return result;
  }

  async findVerified(
    manifestId: string
  ): Promise<PersistedVerifiedSastRuleBundle | null> {
    return this.bundles.get(manifestId) ?? null;
  }

  async recordCompatibilityReceipt(
    receipt: Readonly<SastRuleBundleCompatibilityReceipt>
  ): Promise<PersistedSastRuleBundleCompatibilityReceipt> {
    return { receipt: structuredClone(receipt), replayed: false };
  }
}

function governanceFixtures() {
  const metadata = [
    ruleMetadata('OPENGREP', 'java.sql-injection', 'SAST', 'INJECTION'),
    ruleMetadata(
      'TRIVY',
      'iac.public-s3-bucket',
      'IAC_MISCONFIGURATION',
      'CLOUD_MISCONFIGURATION'
    )
  ];
  const manifests = [
    ruleManifest('OPENGREP', metadata[0], '1'),
    ruleManifest('TRIVY', metadata[1], '2')
  ];
  const bindings = manifests
    .map((manifest, index) => bindMetadata(metadata[index], manifest))
    .sort((left, right) =>
      `${left.manifestId}\u0000${left.ruleId}`.localeCompare(
        `${right.manifestId}\u0000${right.ruleId}`
      )
    );
  const verifiedBundles = manifests.map((manifest) => {
    const attestation = buildSastRuleBundleSupplyChainAttestation({
      manifest,
      verifiedAt: '2026-08-13T11:00:00.000Z',
      digestCanonical: digest
    });
    if (!attestation) throw new Error('fixture attestation invalid');
    return { manifest, attestation, replayed: false };
  });
  const policy = buildSastTenantRulePolicy(
    {
      tenantId: 'tenant-1',
      policyVersion: 'policy-v1',
      effectiveAt: '2026-08-13T12:00:00.000Z',
      expiresAt: '2027-08-13T12:00:00.000Z',
      categoryDecisions: [],
      ruleDecisions: [],
      pathExclusions: ['generated'],
      severityFloors: { dashboard: 'INFO', publication: 'MEDIUM' },
      repositoryOverrides: [],
      approvedWaiverRefs: [],
      approvedSuppressionRefs: [],
      actorRef: 'user://tenant-admin-1',
      auditRef: immutableRef('audit', 'policy-v1')
    },
    digest
  );
  if (!policy) throw new Error('fixture policy invalid');
  return {
    metadata,
    manifests,
    bindings,
    verifiedBundles,
    policy,
    scannerSet: verifiedScannerSet(manifests, verifiedBundles)
  };
}

function ruleMetadata(
  scanner: 'OPENGREP' | 'TRIVY',
  ruleSemanticId: string,
  capability: 'SAST' | 'IAC_MISCONFIGURATION',
  category: string,
  options: {
    introducedInBundleVersion?: string;
    firstSupportedScannerVersion?: string;
  } = {}
): SastRuleDefinitionMetadata {
  const metadata = buildSastRuleDefinitionMetadata(
    {
      scanner,
      ruleId: ruleSemanticId,
      ruleRevision: '1.0.0',
      ruleSemanticId,
      semanticIdentity: {
        ruleSemanticId,
        capability,
        category,
        languages: capability === 'SAST' ? ['JAVA'] : [],
        formats: capability === 'SAST' ? [] : ['TERRAFORM'],
        vulnerabilityPredicateRef: immutableRef('predicates', ruleSemanticId),
        sourceKinds: capability === 'SAST' ? ['HTTP_PARAMETER'] : [],
        sinkKinds: capability === 'SAST' ? ['SQL_QUERY'] : [],
        defaultSeverity: 'HIGH',
        defaultConfidence: 'HIGH',
        findingIdentityRef: immutableRef('identity', ruleSemanticId),
        tenantControl: 'OPTIONAL'
      },
      ownerRef: immutableRef('owners', 'appsec'),
      cweIds: capability === 'SAST' ? ['CWE-89'] : [],
      owaspMappings: ['OWASP-A03_2021'],
      documentationRef: immutableRef('docs', ruleSemanticId),
      fixtureRefs: [immutableRef('fixtures', ruleSemanticId)],
      introducedInBundleVersion:
        options.introducedInBundleVersion ?? '1.0.0',
      firstSupportedScannerVersion:
        options.firstSupportedScannerVersion ?? '0.1.0',
      lastSupportedScannerVersion: null,
      deprecationState: 'ACTIVE',
      replacementSemanticRuleId: null
    },
    digest
  );
  if (!metadata) throw new Error('fixture metadata invalid');
  return metadata;
}

function ruleManifest(
  scanner: 'OPENGREP' | 'TRIVY',
  metadata: SastRuleDefinitionMetadata,
  seed: string
): SastRuleBundleManifest {
  const plan = durableSastScanPlan();
  const scannerDescriptor = plan.scannerSet.scanners[scanner];
  const manifest = buildSastRuleBundleManifest(
    {
      bundleId: `sast-rule-bundle://${scanner.toLowerCase()}/default`,
      bundleVersion: '1.0.0',
      lifecycleState: 'ACTIVE',
      scanner,
      builtAt: '2026-08-13T10:00:00.000Z',
      sourceRevision: seed.repeat(40),
      bundleDigest: digest(`${scanner}-bundle`),
      members: [
        {
          memberId: `rules/${scanner.toLowerCase()}.yml`,
          digest: digest(`${scanner}-member`)
        }
      ],
      rules: [
        {
          ruleId: metadata.ruleId,
          ruleRevision: metadata.ruleRevision,
          ruleSemanticId: metadata.ruleSemanticId,
          metadataDigest: metadata.metadataDigest
        }
      ],
      compatibility: {
        scannerVersions: [scannerDescriptor.version],
        scannerImageDigests: [scannerDescriptor.digest],
        wrapperDigests: [scannerDescriptor.wrapper.digest],
        schemaBundleDigests: [plan.scannerSet.schemaBundle.digest],
        normalizerBundleDigests: [plan.scannerSet.normalizerBundle.digest],
        profileIds: ['JAVA_FAST_V1']
      },
      qualityEvidence: {
        goldenCorpusResultRef: immutableRef('quality', `${scanner}-golden`),
        regressionCorpusResultRef: immutableRef('quality', `${scanner}-regression`),
        maliciousCorpusResultRef: immutableRef('quality', `${scanner}-malicious`),
        performanceCorpusResultRef: immutableRef('quality', `${scanner}-performance`)
      },
      signerIdentity: 'spiffe://aegis/security/rule-signer',
      signatureRef: immutableRef('signature', scanner),
      provenanceRef: immutableRef('provenance', scanner),
      compatibilityRef: immutableRef('compatibility', scanner),
      rolloutPolicyRef: immutableRef('rollout', scanner),
      killSwitchNamespace: `sast-kill-switch://rule-bundles/${scanner.toLowerCase()}`,
      killSwitchRef: immutableRef('kill-switch', scanner),
      rollbackTargetDigest: digest(`${scanner}-rollback`)
    },
    digest
  );
  if (!manifest) throw new Error('fixture manifest invalid');
  return manifest;
}

function bindMetadata(
  metadata: SastRuleDefinitionMetadata,
  manifest: SastRuleBundleManifest,
  manifestDigest = manifest.manifestDigest
): SastRuleDefinitionMetadataBinding {
  const binding = buildSastRuleDefinitionMetadataBinding(
    {
      manifestId: manifest.manifestId,
      manifestDigest,
      bundleId: manifest.bundleId,
      bundleDigest: manifest.bundleDigest,
      metadata
    },
    digest
  );
  if (!binding) throw new Error('fixture binding invalid');
  return binding;
}

function verifiedScannerSet(
  manifests: readonly SastRuleBundleManifest[],
  verifiedBundles: readonly PersistedVerifiedSastRuleBundle[]
): VerifiedScannerSetDescriptor {
  const base = durableSastScanPlan().scannerSet;
  return {
    ...base,
    scannerSetDigest: digest('semantic-policy-scanner-set'),
    ruleBundles: manifests.map((manifest, index) => {
      const attestation = verifiedBundles[index].attestation;
      return {
        bundleId: manifest.bundleId,
        version: manifest.bundleVersion,
        state: manifest.lifecycleState,
        digest: manifest.bundleDigest,
        manifestId: manifest.manifestId,
        manifestDigest: manifest.manifestDigest,
        verificationId: attestation.verificationId,
        verificationDigest: attestation.attestationDigest,
        signatureRef: manifest.signatureRef,
        provenanceRef: manifest.provenanceRef,
        compatibilityRef: manifest.compatibilityRef,
        rolloutPolicyRef: manifest.rolloutPolicyRef,
        killSwitchRef: manifest.killSwitchRef,
        rollbackTargetDigest: manifest.rollbackTargetDigest,
        compatibilityReceiptId:
          `sast-rule-bundle-compatibility://${String(index + 7).repeat(64)}`,
        compatibilityReceiptDigest: digest(`receipt-${index}`),
        scanner: manifest.scanner,
        source: 'PLATFORM_MANAGED',
        immutable: true,
        customerExecutableConfigAllowed: false,
        rules: manifest.rules.map((rule) => ({ ...rule }))
      } satisfies VerifiedRuleBundleDescriptor;
    })
  };
}

function immutableRef(namespace: string, seed: string): string {
  return `catalog://${namespace}/${seed}/${digest(seed)}`;
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
