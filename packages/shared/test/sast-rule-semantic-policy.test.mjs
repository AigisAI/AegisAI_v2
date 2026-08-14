import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  buildSastRuleDefinitionMetadata,
  buildSastRuleDefinitionMetadataBinding,
  buildSastTenantRulePolicy,
  buildSastTenantRulePolicyResolution,
  findSastTenantRulePolicyResolutionReasonCodes,
  isSastRuleDefinitionMetadataBindingShapeValid,
  isSastRuleDefinitionMetadataShapeValid,
  isSastTenantRulePolicyResolutionReceiptShapeValid,
  isSastTenantRulePolicyShapeValid,
  toVerifiedSastTenantRulePolicyDescriptor
} from '../dist/index.js';

test('T046 separates reusable rule metadata from immutable signed-manifest bindings', () => {
  const metadata = ruleMetadata();
  const first = metadataBinding(metadata, '1', '2');
  const second = metadataBinding(metadata, '3', '4');

  assert.equal(isSastRuleDefinitionMetadataShapeValid(metadata, digest), true);
  assert.equal(
    isSastRuleDefinitionMetadataBindingShapeValid(first, digest),
    true
  );
  assert.equal(
    isSastRuleDefinitionMetadataBindingShapeValid(second, digest),
    true
  );
  assert.equal(first.metadataDigest, second.metadataDigest);
  assert.equal(first.metadataId, second.metadataId);
  assert.notEqual(first.bindingDigest, second.bindingDigest);
  assert.notEqual(first.bindingId, second.bindingId);
  assert.equal(JSON.stringify(metadata).includes('manifestId'), false);
  assert.equal(JSON.stringify(first).includes('ruleContent'), false);
  assert.equal(first.executableRuleContentStored, false);
  assert.equal(first.customerExecutableConfigAllowed, false);
});

test('T046 rejects metadata and binding drift, mutable references, and unknown fields', () => {
  const metadata = ruleMetadata();
  const binding = metadataBinding(metadata, '1', '2');

  assert.equal(
    isSastRuleDefinitionMetadataShapeValid(
      { ...metadata, ownerRef: 'https://example.test/team/latest' },
      digest
    ),
    false
  );
  assert.equal(
    isSastRuleDefinitionMetadataShapeValid(
      { ...metadata, executableRuleContent: 'rules: []' },
      digest
    ),
    false
  );
  assert.equal(
    isSastRuleDefinitionMetadataBindingShapeValid(
      { ...binding, manifestDigest: digest('tampered') },
      digest
    ),
    false
  );
  assert.equal(
    isSastRuleDefinitionMetadataBindingShapeValid(
      {
        ...binding,
        metadata: { ...metadata, ruleRevision: '1.0.1' }
      },
      digest
    ),
    false
  );
});

test('T046 accepts only bounded declarative tenant policy metadata', () => {
  const policy = tenantPolicy();

  assert.equal(isSastTenantRulePolicyShapeValid(policy, digest), true);
  assert.equal(policy.executableRulesAccepted, false);
  assert.equal(policy.cliFlagsAccepted, false);
  assert.equal(policy.pluginsAccepted, false);
  assert.equal(policy.arbitraryConfigurationAccepted, false);
  assert.equal(JSON.stringify(policy).includes('sourceCode'), false);
  assert.equal(
    buildSastTenantRulePolicy(
      { ...tenantPolicyInput(), pathExclusions: ['src/**'] },
      digest
    ),
    null
  );
  assert.equal(
    buildSastTenantRulePolicy(
      { ...tenantPolicyInput(), regex: '.*' },
      digest
    ),
    null
  );
  assert.equal(
    buildSastTenantRulePolicy(
      {
        ...tenantPolicyInput(),
        severityFloors: { dashboard: 'INFO', publication: 'LOW' }
      },
      digest
    ),
    null
  );
  assert.equal(
    buildSastTenantRulePolicy(
      {
        ...tenantPolicyInput(),
        severityFloors: { dashboard: 'MEDIUM', publication: 'HIGH' },
        repositoryOverrides: [
          {
            repositoryBindingId: 'repository-1',
            categoryDecisions: [],
            ruleDecisions: [],
            pathExclusions: [],
            severityFloors: { dashboard: 'INFO', publication: 'MEDIUM' }
          }
        ]
      },
      digest
    ),
    null
  );
  assert.equal(
    buildSastTenantRulePolicy(
      {
        ...tenantPolicyInput(),
        expiresAt: '2028-08-13T12:00:00.000Z'
      },
      digest
    ),
    null
  );
  assert.equal(
    buildSastTenantRulePolicy(
      {
        ...tenantPolicyInput(),
        effectiveAt: '2026-08-13T12:00:00Z'
      },
      digest
    ),
    null
  );
  assert.equal(
    buildSastTenantRulePolicy(
      {
        ...tenantPolicyInput(),
        effectiveAt: '2026-02-30T12:00:00.000Z'
      },
      digest
    ),
    null
  );
  assert.equal(
    buildSastTenantRulePolicy(
      {
        ...tenantPolicyInput(),
        actorRef: `user://${'a'.repeat(2_049)}`
      },
      digest
    ),
    null
  );
});

test('T046 produces a content-free exact resolution receipt and frozen plan descriptor', () => {
  const metadata = ruleMetadata();
  const binding = metadataBinding(metadata, '1', '2');
  const policy = tenantPolicy();
  const receipt = buildSastTenantRulePolicyResolution({
    policy,
    context: resolutionContext(),
    selectedMetadata: [binding],
    approvedSemanticRuleIds: ['java.sql-injection'],
    approvedCategories: ['INJECTION'],
    digestCanonical: digest
  });

  assert.ok(receipt);
  assert.equal(
    isSastTenantRulePolicyResolutionReceiptShapeValid(receipt, digest),
    true
  );
  assert.equal(receipt.rules[0].bindingId, binding.bindingId);
  assert.equal(receipt.rules[0].state, 'ENABLED');
  assert.equal(receipt.policyMatched, true);
  assert.equal(receipt.mandatoryRulesPreserved, true);
  assert.equal(receipt.executableConfigurationAccepted, false);
  assert.equal(receipt.customerInputStored, false);
  assert.deepEqual(toVerifiedSastTenantRulePolicyDescriptor(receipt), {
    policyId: receipt.policyId,
    policyVersion: receipt.policyVersion,
    policyDigest: receipt.policyDigest,
    resolutionReceiptId: receipt.receiptId,
    resolutionIdentityDigest: receipt.receiptIdentityDigest,
    resolutionReceiptDigest: receipt.receiptDigest,
    semanticMetadataSetDigest: receipt.semanticMetadataSetDigest,
    ruleResolutionDigest: receipt.ruleResolutionDigest,
    enabledRuleSetDigest: receipt.enabledRuleSetDigest,
    disabledRuleSetDigest: receipt.disabledRuleSetDigest,
    pathExclusionDigest: receipt.pathExclusionDigest,
    severityFloors: receipt.severityFloors
  });
  assert.equal(
    isSastTenantRulePolicyResolutionReceiptShapeValid(
      { ...receipt, semanticMetadataSetDigest: digest('tampered') },
      digest
    ),
    false
  );
  assert.equal(
    isSastTenantRulePolicyResolutionReceiptShapeValid(
      {
        ...receipt,
        receiptId:
          'sast-tenant-rule-policy-resolution://' + 'f'.repeat(64)
      },
      digest
    ),
    false
  );
  assert.equal(
    buildSastTenantRulePolicyResolution({
      policy,
      context: {
        ...resolutionContext(),
        evaluatedAt: '2026-08-13T13:00:00Z'
      },
      selectedMetadata: [binding],
      approvedSemanticRuleIds: ['java.sql-injection'],
      approvedCategories: ['INJECTION'],
      digestCanonical: digest
    }),
    null
  );
});

test('T046 fails closed for unknown selectors, mandatory disables, and semantic-ID reuse', () => {
  const mandatory = ruleMetadata({ tenantControl: 'MANDATORY' });
  const binding = metadataBinding(mandatory, '1', '2');
  const disabledPolicy = tenantPolicy({
    ruleDecisions: [
      { ruleSemanticId: 'java.sql-injection', state: 'DISABLED' }
    ]
  });
  const base = {
    policy: disabledPolicy,
    context: resolutionContext(),
    selectedMetadata: [binding],
    approvedSemanticRuleIds: ['java.sql-injection'],
    approvedCategories: ['INJECTION'],
    digestCanonical: digest
  };

  assert.deepEqual(findSastTenantRulePolicyResolutionReasonCodes(base), [
    'POLICY_MANDATORY_RULE_DISABLED'
  ]);
  assert.equal(buildSastTenantRulePolicyResolution(base), null);

  const unknown = tenantPolicy({
    ruleDecisions: [
      { ruleSemanticId: 'java.unknown-rule', state: 'DISABLED' }
    ]
  });
  assert.deepEqual(
    findSastTenantRulePolicyResolutionReasonCodes({
      ...base,
      policy: unknown
    }),
    ['POLICY_SELECTOR_UNKNOWN']
  );

  const changedMeaning = ruleMetadata({
    predicateSeed: 'different-predicate'
  });
  const conflictBindings = [
    metadataBinding(mandatory, '1', '2'),
    metadataBinding(changedMeaning, '3', '4')
  ];
  assert.deepEqual(
    findSastTenantRulePolicyResolutionReasonCodes({
      ...base,
      policy: tenantPolicy(),
      selectedMetadata: conflictBindings
    }),
    ['POLICY_SEMANTIC_IDENTITY_CONFLICT']
  );
});

test('T046 repository overrides can narrow but cannot re-enable a tenant-disabled rule', () => {
  const metadata = ruleMetadata();
  const binding = metadataBinding(metadata, '1', '2');
  const policy = tenantPolicy({
    categoryDecisions: [{ category: 'INJECTION', state: 'DISABLED' }],
    repositoryOverrides: [
      {
        repositoryBindingId: 'repository-1',
        categoryDecisions: [{ category: 'INJECTION', state: 'ENABLED' }],
        ruleDecisions: [
          { ruleSemanticId: 'java.sql-injection', state: 'ENABLED' }
        ],
        pathExclusions: [],
        severityFloors: { dashboard: 'INFO', publication: 'MEDIUM' }
      }
    ]
  });
  const receipt = buildSastTenantRulePolicyResolution({
    policy,
    context: resolutionContext(),
    selectedMetadata: [binding],
    approvedSemanticRuleIds: ['java.sql-injection'],
    approvedCategories: ['INJECTION'],
    digestCanonical: digest
  });

  assert.ok(receipt);
  assert.equal(receipt.rules[0].state, 'DISABLED');
});

function ruleMetadata(options = {}) {
  const input = {
    scanner: 'OPENGREP',
    ruleId: 'java.sql-injection',
    ruleRevision: '1.0.0',
    ruleSemanticId: 'java.sql-injection',
    semanticIdentity: {
      ruleSemanticId: 'java.sql-injection',
      capability: 'SAST',
      category: 'INJECTION',
      languages: ['JAVA'],
      formats: [],
      vulnerabilityPredicateRef: immutableRef(
        'predicates',
        options.predicateSeed ?? 'sql-injection'
      ),
      sourceKinds: ['HTTP_PARAMETER'],
      sinkKinds: ['SQL_QUERY'],
      defaultSeverity: 'HIGH',
      defaultConfidence: 'HIGH',
      findingIdentityRef: immutableRef('identity', 'java-v1'),
      tenantControl: options.tenantControl ?? 'OPTIONAL'
    },
    ownerRef: immutableRef('owners', 'appsec'),
    cweIds: ['CWE-89'],
    owaspMappings: ['OWASP-A03_2021'],
    documentationRef: immutableRef('docs', 'sql-injection'),
    fixtureRefs: [immutableRef('fixtures', 'sql-injection-positive')],
    introducedInBundleVersion: '1.0.0',
    firstSupportedScannerVersion: '1.22.0',
    lastSupportedScannerVersion: null,
    deprecationState: 'ACTIVE',
    replacementSemanticRuleId: null
  };
  const metadata = buildSastRuleDefinitionMetadata(input, digest);
  assert.ok(metadata);
  return metadata;
}

function metadataBinding(metadata, manifestSeed, bundleSeed) {
  const binding = buildSastRuleDefinitionMetadataBinding(
    {
      manifestId: `sast-rule-bundle-manifest://${manifestSeed.repeat(64)}`,
      manifestDigest: digest(manifestSeed),
      bundleId: 'sast-rule-bundle://opengrep/core-java',
      bundleDigest: digest(bundleSeed),
      metadata
    },
    digest
  );
  assert.ok(binding);
  return binding;
}

function tenantPolicy(overrides = {}) {
  const policy = buildSastTenantRulePolicy(
    { ...tenantPolicyInput(), ...overrides },
    digest
  );
  assert.ok(policy);
  return policy;
}

function tenantPolicyInput() {
  return {
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
  };
}

function resolutionContext() {
  return {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scannerSetDigest: digest('scanner-set'),
    profileId: 'JAVA_FAST_V1',
    profileDigest: digest('profile'),
    evaluatedAt: '2026-08-13T13:00:00.000Z'
  };
}

function immutableRef(namespace, seed) {
  return `catalog://${namespace}/${seed}/${digest(seed)}`;
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}
