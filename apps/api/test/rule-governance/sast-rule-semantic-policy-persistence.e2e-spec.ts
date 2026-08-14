import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('SAST semantic metadata and tenant policy T046 persistence contract', () => {
  const schema = read('prisma/schema.prisma');
  const migration = read(
    'prisma/migrations/20260813130000_sast_rule_semantic_policy/migration.sql'
  );
  const store = read(
    'src/rule-governance/prisma-sast-rule-semantic-policy.store.ts'
  );
  const moduleSource = read(
    'src/rule-governance/rule-governance.module.ts'
  );
  const planner = read(
    'src/control-plane/sast-scan-planner.service.ts'
  );

  it('normalizes every reusable metadata, manifest binding, policy, and resolution ledger', () => {
    for (const model of [
      'SastRuleSemanticIdentity',
      'SastRuleSemanticIdentityValue',
      'SastRuleDefinitionMetadata',
      'SastRuleDefinitionMetadataValue',
      'SastRuleDefinitionMetadataBinding',
      'SastTenantRulePolicy',
      'SastTenantRulePolicyDecision',
      'SastTenantRulePolicyPathExclusion',
      'SastTenantRulePolicyRepositoryOverride',
      'SastTenantRulePolicyRepositoryDecision',
      'SastTenantRulePolicyRepositoryPathExclusion',
      'SastTenantRulePolicyWaiverReference',
      'SastTenantRulePolicySuppressionReference',
      'SastTenantRulePolicyResolution',
      'SastTenantRulePolicyResolutionRule',
      'SastTenantRulePolicyResolutionPathExclusion'
    ]) {
      expect(schema).toContain(`model ${model} {`);
      expect(migration).toContain(`CREATE TABLE "${model}"`);
      expect(migration).toContain(`${model}_immutable_update`);
      expect(migration).toContain(`${model}_immutable_delete`);
    }
    expect(migration).not.toMatch(/JSONB/u);
    expect(migration).not.toMatch(
      /"(?:ruleContent|sourceContent|repositoryContent|secretValue|policyPayload|waiverReason)"/u
    );
  });

  it('breaks the digest cycle by separating reusable metadata content from signed-manifest binding', () => {
    const metadataModel = modelBody(
      schema,
      'SastRuleDefinitionMetadata'
    );
    const bindingModel = modelBody(
      schema,
      'SastRuleDefinitionMetadataBinding'
    );
    expect(metadataModel).not.toContain('manifestId');
    expect(metadataModel).not.toContain('manifestDigest');
    expect(metadataModel).not.toContain('bundleDigest');
    expect(bindingModel).toContain('manifestId');
    expect(bindingModel).toContain('metadataId');
    expect(bindingModel).toContain('bindingDigest');
    expect(migration).toContain(
      'SastRuleDefinitionMetadataBinding_manifest_rule_fkey'
    );
    expect(migration).toContain(
      'SastRuleDefinitionMetadataBinding_manifest_fkey'
    );
    expect(migration).toContain(
      'SastRuleDefinitionMetadataBinding_metadata_fkey'
    );
    expect(migration).toContain(
      'SastRuleDefinitionMetadata_content_binding_key'
    );
  });

  it('pins non-executable, content-free, immutable and mandatory-rule safety facts', () => {
    for (const invariant of [
      '"source" = \'PLATFORM_MANAGED\'',
      '"immutable" IS TRUE',
      '"executableRuleContentStored" IS FALSE',
      '"customerExecutableConfigAllowed" IS FALSE',
      '"customerSourceStored" IS FALSE',
      '"secretValueStored" IS FALSE',
      '"executableRulesAccepted" IS FALSE',
      '"cliFlagsAccepted" IS FALSE',
      '"pluginsAccepted" IS FALSE',
      '"arbitraryConfigurationAccepted" IS FALSE',
      '"mandatoryRulesPreserved" IS TRUE',
      '"executableConfigurationAccepted" IS FALSE',
      '"customerInputStored" IS FALSE'
    ]) {
      expect(migration).toContain(invariant);
    }
    expect(migration).toContain(
      'NOT ("tenantControl" = \'MANDATORY\' AND "state" = \'DISABLED\')'
    );
    expect(migration).toContain('"pathPrefix" !~ \'[\\\\*?\\[\\]{}()|]\'');
    expect(migration).toContain('"ownerRef" !~ \'^https?://\'');
    expect(migration).toContain(
      '"publicationSeverityFloor" <= \'MEDIUM\'::"Severity"'
    );
    expect(migration).toContain(
      '"id" = \'sast-tenant-rule-policy-resolution://\' || substring("receiptIdentityDigest" FROM 8)'
    );
    expect(migration).toContain(
      'SastTenantRulePolicyResolutionRule_semantic_identity_fkey'
    );
    expect(migration).toContain(
      'SastTenantRulePolicy_resolution_binding_key'
    );
  });

  it('uses serializable exact replay, verifies references, and reconstructs normalized children', () => {
    expect(store).toContain(
      'Prisma.TransactionIsolationLevel.Serializable'
    );
    expect(store).toContain(
      'canonicalizeSastRuleDefinitionMetadataBinding'
    );
    expect(store).toContain('canonicalizeSastTenantRulePolicy');
    expect(store).toContain(
      'canonicalizeSastTenantRulePolicyResolutionReceipt'
    );
    expect(store).toContain('assertReplacementSafe');
    expect(store).toContain('assertPolicyReferences');
    expect(store).toContain('assertResolutionBindings');
    expect(store).toContain("'REPLAY_CONFLICT'");
    for (const kind of [
      'LANGUAGE',
      'FORMAT',
      'SOURCE_KIND',
      'SINK_KIND',
      'CWE',
      'OWASP',
      'FIXTURE',
      'CATEGORY',
      'RULE'
    ]) {
      expect(store).toContain(`'${kind}'`);
    }
  });

  it('gates the canonical plan and queue admission on one exact immutable policy receipt', () => {
    expect(moduleSource).toContain('provide: SastTenantRulePolicyGate');
    expect(moduleSource).toContain('SastRuleSemanticPolicyService');
    const compatibilityGate = planner.indexOf(
      'ruleBundleCompatibilityGate.verifyScannerSet'
    );
    const policyGate = planner.indexOf('tenantRulePolicyGate.resolve');
    const canonicalKey = planner.indexOf(
      'buildSastCanonicalScanKeyPreimage',
      policyGate
    );
    const queueReservation = planner.indexOf(
      'assertSastQueueReservationAllowed'
    );
    expect(compatibilityGate).toBeGreaterThan(-1);
    expect(policyGate).toBeGreaterThan(-1);
    expect(canonicalKey).toBeGreaterThan(-1);
    expect(queueReservation).toBeGreaterThan(-1);
    expect(policyGate).toBeGreaterThan(compatibilityGate);
    expect(canonicalKey).toBeGreaterThan(policyGate);
    expect(queueReservation).toBeGreaterThan(canonicalKey);
    expect(planner).toContain('tenantRulePolicy,');
    expect(planner).toContain('RULE_METADATA_UNVERIFIED');
    expect(planner).toContain('RULE_METADATA_MISMATCH');
    expect(planner).toContain('TENANT_RULE_POLICY_INVALID');
    expect(planner).toContain('TENANT_RULE_POLICY_UNAVAILABLE');
  });
});

function read(path: string): string {
  return readFileSync(resolve(__dirname, '../../', path), 'utf8');
}

function modelBody(source: string, model: string): string {
  const start = source.indexOf(`model ${model} {`);
  const end = source.indexOf('\nmodel ', start + 1);
  if (start < 0) throw new Error(`missing model ${model}`);
  return source.slice(start, end < 0 ? source.length : end);
}
