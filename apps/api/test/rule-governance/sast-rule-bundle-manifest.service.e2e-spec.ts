import { createHash } from 'node:crypto';
import { verifiedTenantRulePolicy } from '../support/sast-scan-plan-fixtures';

import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_FORBIDDEN_CAPABILITIES,
  SAST_SCAN_PROFILES,
  buildSastRuleBundleManifest,
  buildSastRuleBundleSupplyChainAttestation,
  isSastScanPlanValid,
  type SastRuleBundleCompatibilityReceipt,
  type SastRuleBundleManifest,
  type SastRuleBundleSupplyChainAttestation,
  type ScannerSetDescriptor
} from '@aegisai/shared';

import {
  SastRuleBundleCompatibilityGateError
} from '../../src/rule-governance/sast-rule-bundle-compatibility.gate';
import {
  SastRuleBundleManifestService
} from '../../src/rule-governance/sast-rule-bundle-manifest.service';
import {
  SastRuleBundleManifestStore,
  type PersistedSastRuleBundleCompatibilityReceipt,
  type PersistedVerifiedSastRuleBundle
} from '../../src/rule-governance/sast-rule-bundle-manifest.store';
import {
  SastRuleBundleSupplyChainAuthority,
  UnavailableSastRuleBundleSupplyChainAuthority
} from '../../src/rule-governance/sast-rule-bundle-supply-chain.authority';

describe('SastRuleBundleManifestService T045 gate', () => {
  it('registers trusted immutable manifests while lifecycle verification remains mandatory for plans', async () => {
    const store = new InMemoryManifestStore();
    const service = new SastRuleBundleManifestService(
      store,
      new AcceptingSupplyChainAuthority()
    );
    const manifests = [manifest('OPENGREP'), manifest('TRIVY')];

    const first = await service.registerVerifiedManifest(manifests[0]);
    const replay = await service.registerVerifiedManifest(manifests[0]);
    await service.registerVerifiedManifest(manifests[1]);

    expect(first.replayed).toBe(false);
    expect(replay).toMatchObject({ replayed: true });
    expect(replay.manifest).toEqual(first.manifest);

    const scannerSet = scannerSetFor(manifests);
    const verifiedScannerSet = await service.verifyScannerSet({
      scannerSet,
      profile: SAST_SCAN_PROFILES.JAVA_FAST_V1,
      profileDigest: SAST_APPROVED_PROFILE_DIGESTS.JAVA_FAST_V1,
      evaluatedAt: '2026-08-13T11:05:00.000Z'
    });
    const replayedScannerSet = await service.verifyScannerSet({
      scannerSet,
      profile: SAST_SCAN_PROFILES.JAVA_FAST_V1,
      profileDigest: SAST_APPROVED_PROFILE_DIGESTS.JAVA_FAST_V1,
      evaluatedAt: '2026-08-13T11:10:00.000Z'
    });

    expect(verifiedScannerSet.ruleBundles).toHaveLength(2);
    expect(verifiedScannerSet.ruleBundles).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          scanner: 'OPENGREP',
          compatibilityReceiptId: expect.stringMatching(
            /^sast-rule-bundle-compatibility:\/\/[a-f0-9]{64}$/
          ),
          compatibilityReceiptDigest: expect.stringMatching(
            /^sha256:[a-f0-9]{64}$/
          )
        })
      ])
    );
    expect(store.receipts).toHaveLength(2);
    expect(replayedScannerSet).toEqual(verifiedScannerSet);
    expect(
      JSON.stringify({ manifests: store.verified, receipts: store.receipts })
    ).not.toMatch(/"sourceContent"|"ruleContent"|"secretValue"/u);

    expect(
      isSastScanPlanValid({
        tenantId: 'tenant-1',
        scanRequestId: 'scan-1',
        canonicalScanKey: digest('canonical'),
        profile: SAST_SCAN_PROFILES.JAVA_FAST_V1,
        profileDigest: SAST_APPROVED_PROFILE_DIGESTS.JAVA_FAST_V1,
        policyVersion: 'policy-1',
        tenantRulePolicy: verifiedTenantRulePolicy('policy-1'),
        repositoryState: {
          repositoryBindingId: 'repository-1',
          fixedCommitSha: 'a'.repeat(40),
          targetRef: 'refs/heads/dev',
          inventoryDigest: digest('inventory'),
          attestationRef: 'attestation://inventory',
          shallowFetchPreferred: true,
          submodulesEnabled: false,
          lfsObjectsFetched: false
        },
        scannerSet: verifiedScannerSet as never,
        isolationClass: 'HARDENED',
        resultIngressRef: 'result-ingress://tenant-1/scan-1',
        evidenceOutputRef: 'evidence-output://tenant-1/scan-1',
        auditSinkRef: 'audit-sink://tenant-1/scan-1',
        forbiddenCapabilities: [...SAST_FORBIDDEN_CAPABILITIES],
        createdAt: '2026-08-13T11:05:00.000Z'
      })
    ).toBe(false);
  });

  it('fails closed without creating a receipt for projection drift or unsupported compatibility', async () => {
    const store = new InMemoryManifestStore();
    const service = new SastRuleBundleManifestService(
      store,
      new AcceptingSupplyChainAuthority()
    );
    const manifests = [manifest('OPENGREP'), manifest('TRIVY')];
    for (const item of manifests) {
      await service.registerVerifiedManifest(item);
    }
    const scannerSet = scannerSetFor(manifests);

    await expect(
      service.verifyScannerSet({
        scannerSet: {
          ...scannerSet,
          ruleBundles: scannerSet.ruleBundles.map((bundle) =>
            bundle.scanner === 'OPENGREP'
              ? { ...bundle, manifestDigest: digest('tampered') }
              : bundle
          )
        },
        profile: SAST_SCAN_PROFILES.JAVA_FAST_V1,
        profileDigest: SAST_APPROVED_PROFILE_DIGESTS.JAVA_FAST_V1,
        evaluatedAt: '2026-08-13T11:05:00.000Z'
      })
    ).rejects.toMatchObject<Partial<SastRuleBundleCompatibilityGateError>>({
      reason: 'MANIFEST_MISMATCH'
    });
    expect(store.receipts).toHaveLength(0);

    await expect(
      service.verifyScannerSet({
        scannerSet: {
          ...scannerSet,
          scanners: {
            ...scannerSet.scanners,
            OPENGREP: {
              ...scannerSet.scanners.OPENGREP,
              version: '9.9.9'
            }
          }
        },
        profile: SAST_SCAN_PROFILES.JAVA_FAST_V1,
        profileDigest: SAST_APPROVED_PROFILE_DIGESTS.JAVA_FAST_V1,
        evaluatedAt: '2026-08-13T11:05:00.000Z'
      })
    ).rejects.toMatchObject<Partial<SastRuleBundleCompatibilityGateError>>({
      reason: 'COMPATIBILITY_UNSUPPORTED'
    });
    expect(store.receipts).toHaveLength(0);
  });

  it('defaults to an unavailable verifier and never self-attests a manifest', async () => {
    const service = new SastRuleBundleManifestService(
      new InMemoryManifestStore(),
      new UnavailableSastRuleBundleSupplyChainAuthority()
    );

    await expect(
      service.registerVerifiedManifest(manifest('OPENGREP'))
    ).rejects.toMatchObject({ reason: 'AUTHORITY_UNAVAILABLE' });
  });
});

class AcceptingSupplyChainAuthority extends SastRuleBundleSupplyChainAuthority {
  async verify(
    input: Readonly<SastRuleBundleManifest>
  ): Promise<SastRuleBundleSupplyChainAttestation> {
    const attestation = buildSastRuleBundleSupplyChainAttestation({
      manifest: input,
      verifiedAt: '2026-08-13T11:00:00.000Z',
      digestCanonical: digest
    });
    if (!attestation) throw new Error('fixture attestation invalid');
    return attestation;
  }
}

class InMemoryManifestStore extends SastRuleBundleManifestStore {
  readonly verified: PersistedVerifiedSastRuleBundle[] = [];
  readonly receipts: SastRuleBundleCompatibilityReceipt[] = [];

  async registerVerified(input: {
    manifest: Readonly<SastRuleBundleManifest>;
    attestation: Readonly<SastRuleBundleSupplyChainAttestation>;
  }): Promise<PersistedVerifiedSastRuleBundle> {
    const existing = this.verified.find(
      (item) => item.manifest.manifestId === input.manifest.manifestId
    );
    if (existing) return { ...structuredClone(existing), replayed: true };
    const created = {
      manifest: structuredClone(input.manifest),
      attestation: structuredClone(input.attestation),
      replayed: false
    };
    this.verified.push(created);
    return structuredClone(created);
  }

  async findVerified(
    manifestId: string
  ): Promise<PersistedVerifiedSastRuleBundle | null> {
    const existing = this.verified.find(
      (item) => item.manifest.manifestId === manifestId
    );
    return existing ? structuredClone(existing) : null;
  }

  async recordCompatibilityReceipt(
    receipt: Readonly<SastRuleBundleCompatibilityReceipt>
  ): Promise<PersistedSastRuleBundleCompatibilityReceipt> {
    const existing = this.receipts.find(
      (item) => item.receiptId === receipt.receiptId
    );
    if (existing) {
      return { receipt: structuredClone(existing), replayed: true };
    }
    const created = structuredClone(receipt);
    this.receipts.push(created);
    return { receipt: created, replayed: false };
  }
}

function manifest(scanner: 'OPENGREP' | 'TRIVY'): SastRuleBundleManifest {
  const slug = scanner.toLowerCase();
  const built = buildSastRuleBundleManifest(
    {
      bundleId: `sast-rule-bundle://${slug}/default`,
      bundleVersion: '1.2.3',
      lifecycleState: 'ACTIVE',
      scanner,
      builtAt: '2026-08-13T10:00:00.000Z',
      sourceRevision: scanner === 'OPENGREP' ? 'a'.repeat(40) : 'b'.repeat(40),
      bundleDigest: digest(`${slug}-bundle`),
      members: [
        {
          memberId: `rules/${slug}/default.yml`,
          digest: digest(`${slug}-member`)
        }
      ],
      rules: [
        {
          ruleId: `${slug}.fixture`,
          ruleRevision: '1',
          ruleSemanticId: `aegis.${slug}.fixture`,
          metadataDigest: digest(`${slug}-metadata`)
        }
      ],
      compatibility: {
        scannerVersions: ['1.22.0'],
        scannerImageDigests: [digest(`${slug}-image`)],
        wrapperDigests: [digest(`${slug}-wrapper`)],
        schemaBundleDigests: [digest('schema')],
        normalizerBundleDigests: [digest('normalizer')],
        profileIds: ['JAVA_DEEP_V1', 'JAVA_FAST_V1']
      },
      qualityEvidence: {
        goldenCorpusResultRef: reference(`${slug}-golden`),
        regressionCorpusResultRef: reference(`${slug}-regression`),
        maliciousCorpusResultRef: reference(`${slug}-malicious`),
        performanceCorpusResultRef: reference(`${slug}-performance`)
      },
      signerIdentity: 'spiffe://aegis/security/rule-signer',
      signatureRef: reference(`${slug}-signature`),
      provenanceRef: reference(`${slug}-provenance`),
      compatibilityRef: reference(`${slug}-compatibility`),
      rolloutPolicyRef: reference(`${slug}-rollout`),
      killSwitchNamespace: `sast-kill-switch://rule-bundles/${slug}`,
      killSwitchRef: reference(`${slug}-kill-switch`),
      rollbackTargetDigest: digest(`${slug}-last-known-good`)
    },
    digest
  );
  if (!built) throw new Error('fixture manifest invalid');
  return built;
}

function scannerSetFor(
  manifests: readonly SastRuleBundleManifest[]
): ScannerSetDescriptor {
  const byScanner = new Map(manifests.map((item) => [item.scanner, item]));
  const descriptor = (scanner: 'OPENGREP' | 'TRIVY') => {
    const item = byScanner.get(scanner);
    if (!item) throw new Error('fixture manifest missing');
    const verification = buildSastRuleBundleSupplyChainAttestation({
      manifest: item,
      verifiedAt: '2026-08-13T11:00:00.000Z',
      digestCanonical: digest
    });
    if (!verification) throw new Error('fixture attestation invalid');
    return {
      bundleId: item.bundleId,
      version: item.bundleVersion,
      state: item.lifecycleState,
      digest: item.bundleDigest,
      manifestId: item.manifestId,
      manifestDigest: item.manifestDigest,
      verificationId: verification.verificationId,
      verificationDigest: verification.attestationDigest,
      signatureRef: item.signatureRef,
      provenanceRef: item.provenanceRef,
      compatibilityRef: item.compatibilityRef,
      rolloutPolicyRef: item.rolloutPolicyRef,
      killSwitchRef: item.killSwitchRef,
      rollbackTargetDigest: item.rollbackTargetDigest,
      scanner,
      source: item.source,
      immutable: item.immutable,
      customerExecutableConfigAllowed:
        item.customerExecutableConfigAllowed,
      rules: item.rules.map((rule) => ({ ...rule }))
    };
  };
  const runtime = (scanner: 'OPENGREP' | 'TRIVY' | 'SYFT') => {
    const slug = scanner.toLowerCase();
    return {
      scanner,
      version: scanner === 'SYFT' ? '1.33.0' : '1.22.0',
      digest: digest(`${slug}-image`),
      signatureRef: `signature://${slug}`,
      provenanceRef: `provenance://${slug}`,
      sbomRef: `sbom://${slug}`,
      wrapper: {
        digest: digest(`${slug}-wrapper`),
        signatureRef: `signature://${slug}-wrapper`,
        provenanceRef: `provenance://${slug}-wrapper`
      }
    };
  };
  return {
    scannerSetVersion: 'scanner-set-v1',
    scannerSetDigest: digest('scanner-set'),
    signatureRef: 'signature://scanner-set',
    provenanceRef: 'provenance://scanner-set',
    scanners: {
      OPENGREP: runtime('OPENGREP'),
      TRIVY: runtime('TRIVY'),
      SYFT: runtime('SYFT')
    },
    ruleBundles: [descriptor('OPENGREP'), descriptor('TRIVY')],
    vulnerabilityDatabase: {
      digest: digest('vulnerability-database'),
      signatureRef: 'signature://vulnerability-database',
      provenanceRef: 'provenance://vulnerability-database',
      databaseVersion: '2026-08-13',
      publishedAt: '2026-08-13T00:00:00.000Z'
    },
    schemaBundle: {
      digest: digest('schema'),
      signatureRef: 'signature://schema',
      provenanceRef: 'provenance://schema'
    },
    normalizerBundle: {
      digest: digest('normalizer'),
      signatureRef: 'signature://normalizer',
      provenanceRef: 'provenance://normalizer'
    },
    sbomSchema: 'CYCLONEDX_JSON',
    rollbackRef: 'rollback://scanner-set-v0'
  };
}

function reference(label: string): string {
  return `sast-${label}://registry/${label}/${digest(label)}`;
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
