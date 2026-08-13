import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('SAST rule-bundle T045 persistence contract', () => {
  const schema = read('prisma/schema.prisma');
  const migration = read(
    'prisma/migrations/20260813120000_sast_rule_bundle_manifest/migration.sql'
  );
  const store = read(
    'src/rule-governance/prisma-sast-rule-bundle-manifest.store.ts'
  );
  const moduleSource = read(
    'src/rule-governance/rule-governance.module.ts'
  );
  const planner = read(
    'src/control-plane/sast-scan-planner.service.ts'
  );

  it('normalizes an immutable manifest, member, rule, compatibility, attestation, and receipt ledger', () => {
    for (const model of [
      'SastRuleBundleManifest',
      'SastRuleBundleManifestMember',
      'SastRuleBundleManifestRule',
      'SastRuleBundleCompatibilityEntry',
      'SastRuleBundleSupplyChainAttestation',
      'SastRuleBundleCompatibilityReceipt'
    ]) {
      expect(schema).toContain(`model ${model} {`);
      expect(migration).toContain(`CREATE TABLE "${model}"`);
      expect(migration).toContain(`${model}_immutable_update`);
      expect(migration).toContain(`${model}_immutable_delete`);
    }
    expect(migration).not.toMatch(/JSONB/u);
    expect(migration).not.toMatch(
      /"(?:ruleContent|sourceContent|repositoryContent|signatureBytes|provenancePayload|secretValue)"/u
    );
  });

  it('pins supply-chain truth and zero-content safety facts in database checks', () => {
    for (const invariant of [
      '"source" = \'PLATFORM_MANAGED\'',
      '"immutable" IS TRUE',
      '"customerExecutableConfigAllowed" IS FALSE',
      '"executableRuleContentStored" IS FALSE',
      '"customerSourceStored" IS FALSE',
      '"secretValueStored" IS FALSE',
      '"signatureVerified" IS TRUE',
      '"provenanceVerified" IS TRUE',
      '"trustedSigner" IS TRUE',
      '"subjectDigestsVerified" IS TRUE',
      '"signatureBytesStored" IS FALSE',
      '"provenancePayloadStored" IS FALSE',
      '"customerInputAccepted" IS FALSE',
      '"manifestProjectionMatched" IS TRUE'
    ]) {
      expect(migration).toContain(invariant);
    }
    expect(migration).toContain(
      '"rollbackTargetDigest" <> "bundleDigest"'
    );
    expect(migration).toContain(
      '"id" = \'sast-rule-bundle-manifest://\' || substring("manifestDigest" FROM 8)'
    );
    expect(migration).toContain(
      '"id" = \'sast-rule-bundle-verification://\' || substring("manifestDigest" FROM 8)'
    );
    expect(migration).toContain('"signatureRef" !~ \'^https?://\'');
    expect(migration).toContain('"provenanceRef" !~ \'^https?://\'');
    for (const state of [
      'DRAFT',
      'VALIDATED',
      'CANARY',
      'ACTIVE',
      'SUSPENDED',
      'ROLLED_BACK',
      'RETIRED'
    ]) {
      expect(migration).toContain(`'${state}'`);
    }
  });

  it('uses serializable exact replay and reconstructs every canonical set', () => {
    expect(store).toContain(
      'Prisma.TransactionIsolationLevel.Serializable'
    );
    expect(store).toContain('canonicalizeSastRuleBundleManifest');
    expect(store).toContain(
      'canonicalizeSastRuleBundleSupplyChainAttestation'
    );
    expect(store).toContain(
      'canonicalizeSastRuleBundleCompatibilityReceipt'
    );
    expect(store).toContain(
      'Date.parse(expected.evaluatedAt) < Date.parse(receipt.evaluatedAt)'
    );
    expect(store).toContain("'REPLAY_CONFLICT'");
    for (const kind of [
      'SCANNER_VERSION',
      'SCANNER_IMAGE_DIGEST',
      'WRAPPER_DIGEST',
      'SCHEMA_BUNDLE_DIGEST',
      'NORMALIZER_BUNDLE_DIGEST',
      'PROFILE_ID'
    ]) {
      expect(store).toContain(`'${kind}'`);
    }
  });

  it('defaults verification to unavailable and gates planning before queue reservation', () => {
    expect(moduleSource).toContain(
      'UnavailableSastRuleBundleSupplyChainAuthority'
    );
    expect(moduleSource).toContain(
      'provide: SastRuleBundleSupplyChainAuthority'
    );
    expect(moduleSource).toContain(
      'provide: SastRuleBundleCompatibilityGate'
    );
    const compatibilityGate = planner.indexOf(
      'ruleBundleCompatibilityGate.verifyScannerSet'
    );
    const queueReservation = planner.indexOf(
      'assertSastQueueReservationAllowed'
    );
    expect(compatibilityGate).toBeGreaterThan(-1);
    expect(queueReservation).toBeGreaterThan(compatibilityGate);
    expect(planner).toContain('RULE_BUNDLE_MANIFEST_UNVERIFIED');
    expect(planner).toContain('RULE_BUNDLE_MANIFEST_MISMATCH');
    expect(planner).toContain(
      'RULE_BUNDLE_COMPATIBILITY_UNSUPPORTED'
    );
    expect(planner).toContain(
      'RULE_BUNDLE_VERIFICATION_UNAVAILABLE'
    );
  });
});

function read(path: string): string {
  return readFileSync(resolve(__dirname, '../../', path), 'utf8');
}
