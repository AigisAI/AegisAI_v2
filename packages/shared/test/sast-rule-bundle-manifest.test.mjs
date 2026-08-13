import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  buildSastRuleBundleCompatibilityReceipt,
  buildSastRuleBundleManifest,
  buildSastRuleBundleSupplyChainAttestation,
  findSastRuleBundleCompatibilityReasonCodes,
  isSastRuleBundleCompatibilityReceiptShapeValid,
  isSastRuleBundleManifestShapeValid,
  isSastRuleBundleSupplyChainAttestationShapeValid
} from '../dist/index.js';

test('T045 builds one canonical content-free immutable rule bundle manifest', () => {
  const manifest = ruleBundleManifest();

  assert.equal(isSastRuleBundleManifestShapeValid(manifest, digest), true);
  assert.equal(manifest.source, 'PLATFORM_MANAGED');
  assert.equal(manifest.immutable, true);
  assert.equal(manifest.customerExecutableConfigAllowed, false);
  assert.equal(manifest.members.length, 2);
  assert.equal(manifest.rules.length, 2);
  assert.equal(JSON.stringify(manifest).includes('ruleContent'), false);
  assert.equal(JSON.stringify(manifest).includes('tenantId'), false);
  assert.equal(JSON.stringify(manifest).includes('repository'), false);
});

test('T045 binds trusted supply-chain verification and exact compatibility', () => {
  const manifest = ruleBundleManifest();
  const attestation = buildSastRuleBundleSupplyChainAttestation({
    manifest,
    verifiedAt: '2026-08-13T11:00:00.000Z',
    digestCanonical: digest
  });
  assert.ok(attestation);
  assert.equal(
    isSastRuleBundleSupplyChainAttestationShapeValid(
      attestation,
      digest
    ),
    true
  );
  assert.equal(attestation.signatureBytesStored, false);
  assert.equal(attestation.provenancePayloadStored, false);

  const context = compatibilityContext();
  assert.deepEqual(
    findSastRuleBundleCompatibilityReasonCodes(manifest, context),
    []
  );
  const receipt = buildSastRuleBundleCompatibilityReceipt({
    manifest,
    attestation,
    context,
    evaluatedAt: '2026-08-13T11:05:00.000Z',
    digestCanonical: digest
  });
  assert.ok(receipt);
  assert.equal(
    isSastRuleBundleCompatibilityReceiptShapeValid(receipt, digest),
    true
  );
  assert.equal(receipt.compatible, true);
  assert.deepEqual(receipt.reasonCodes, []);
  assert.equal(receipt.customerInputAccepted, false);
  assert.equal(
    buildSastRuleBundleCompatibilityReceipt({
      manifest,
      attestation,
      context,
      evaluatedAt: '2026-08-13T10:59:59.999Z',
      digestCanonical: digest
    }),
    null
  );
});

test('T045 rejects manifest tampering, unknown fields, mutable refs, and noncanonical sets', () => {
  const manifest = ruleBundleManifest();

  assert.equal(
    isSastRuleBundleManifestShapeValid(
      { ...manifest, bundleDigest: digest('tampered') },
      digest
    ),
    false
  );
  assert.equal(
    isSastRuleBundleManifestShapeValid(
      { ...manifest, executableRuleContent: 'allow all' },
      digest
    ),
    false
  );
  assert.equal(
    buildSastRuleBundleManifest(
      {
        ...manifestInput(),
        signatureRef: 'https://registry.example/rules:latest'
      },
      digest
    ),
    null
  );
  assert.equal(
    buildSastRuleBundleManifest(
      { ...manifestInput(), unexpected: true },
      digest
    ),
    null
  );
  assert.equal(
    buildSastRuleBundleManifest(
      { ...manifestInput(), members: undefined },
      digest
    ),
    null
  );
  assert.equal(
    buildSastRuleBundleManifest(
      {
        ...manifestInput(),
        members: [...manifestInput().members].reverse()
      },
      digest
    ),
    null
  );
  assert.equal(
    buildSastRuleBundleManifest(
      {
        ...manifestInput(),
        rules: [
          manifestInput().rules[0],
          { ...manifestInput().rules[0] }
        ]
      },
      digest
    ),
    null
  );
});

test('T045 reports every incompatible supply-chain dimension and persists no denial receipt', () => {
  const manifest = ruleBundleManifest();
  const attestation = buildSastRuleBundleSupplyChainAttestation({
    manifest,
    verifiedAt: '2026-08-13T11:00:00.000Z',
    digestCanonical: digest
  });
  assert.ok(attestation);
  const incompatible = {
    ...compatibilityContext(),
    scanner: 'TRIVY',
    scannerVersion: '9.9.9',
    scannerImageDigest: digest('foreign-image'),
    wrapperDigest: digest('foreign-wrapper'),
    schemaBundleDigest: digest('foreign-schema'),
    normalizerBundleDigest: digest('foreign-normalizer'),
    profileId: 'COMMON_DEEP_V1'
  };
  assert.deepEqual(
    findSastRuleBundleCompatibilityReasonCodes(manifest, incompatible),
    [
      'SCANNER_KIND_MISMATCH',
      'SCANNER_VERSION_UNSUPPORTED',
      'SCANNER_IMAGE_UNSUPPORTED',
      'WRAPPER_UNSUPPORTED',
      'SCHEMA_BUNDLE_UNSUPPORTED',
      'NORMALIZER_BUNDLE_UNSUPPORTED',
      'PROFILE_UNSUPPORTED'
    ]
  );
  assert.equal(
    buildSastRuleBundleCompatibilityReceipt({
      manifest,
      attestation,
      context: incompatible,
      evaluatedAt: '2026-08-13T11:05:00.000Z',
      digestCanonical: digest
    }),
    null
  );
});

function ruleBundleManifest() {
  const manifest = buildSastRuleBundleManifest(manifestInput(), digest);
  assert.ok(manifest);
  return manifest;
}

function manifestInput() {
  const scannerImageDigest = digest('opengrep-image');
  const wrapperDigest = digest('opengrep-wrapper');
  const schemaBundleDigest = digest('schema-bundle');
  const normalizerBundleDigest = digest('normalizer-bundle');
  return {
    bundleId: 'sast-rule-bundle://opengrep/java-default',
    bundleVersion: '1.2.3',
    lifecycleState: 'ACTIVE',
    scanner: 'OPENGREP',
    builtAt: '2026-08-13T10:00:00.000Z',
    sourceRevision: 'a'.repeat(40),
    bundleDigest: digest('opengrep-bundle'),
    members: [
      { memberId: 'rules/java/security.yml', digest: digest('member-a') },
      { memberId: 'rules/java/web.yml', digest: digest('member-b') }
    ],
    rules: [
      {
        ruleId: 'java.security.injection',
        ruleRevision: '1',
        ruleSemanticId: 'aegis.java.injection',
        metadataDigest: digest('rule-a')
      },
      {
        ruleId: 'java.web.xss',
        ruleRevision: '3',
        ruleSemanticId: 'aegis.java.xss',
        metadataDigest: digest('rule-b')
      }
    ],
    compatibility: {
      scannerVersions: ['1.22.0'],
      scannerImageDigests: [scannerImageDigest],
      wrapperDigests: [wrapperDigest],
      schemaBundleDigests: [schemaBundleDigest],
      normalizerBundleDigests: [normalizerBundleDigest],
      profileIds: ['JAVA_DEEP_V1', 'JAVA_FAST_V1']
    },
    qualityEvidence: {
      goldenCorpusResultRef: reference('golden'),
      regressionCorpusResultRef: reference('regression'),
      maliciousCorpusResultRef: reference('malicious'),
      performanceCorpusResultRef: reference('performance')
    },
    signerIdentity: 'spiffe://aegis/security/rule-signer',
    signatureRef: reference('signature'),
    provenanceRef: reference('provenance'),
    compatibilityRef: reference('compatibility'),
    rolloutPolicyRef: reference('rollout'),
    killSwitchNamespace: 'sast-kill-switch://rule-bundles/opengrep',
    killSwitchRef: reference('kill-switch'),
    rollbackTargetDigest: digest('last-known-good')
  };
}

function compatibilityContext() {
  const input = manifestInput();
  return {
    scannerSetDigest: digest('scanner-set'),
    profileId: 'JAVA_FAST_V1',
    profileDigest: digest('profile'),
    scanner: 'OPENGREP',
    scannerVersion: input.compatibility.scannerVersions[0],
    scannerImageDigest: input.compatibility.scannerImageDigests[0],
    wrapperDigest: input.compatibility.wrapperDigests[0],
    schemaBundleDigest: input.compatibility.schemaBundleDigests[0],
    normalizerBundleDigest:
      input.compatibility.normalizerBundleDigests[0]
  };
}

function reference(label) {
  return `sast-${label}://registry/${label}/sha256:${createHash('sha256')
    .update(label, 'utf8')
    .digest('hex')}`;
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
