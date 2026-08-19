import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const apiRoot = resolve(__dirname, '../..');
const repositoryRoot = resolve(apiRoot, '../..');
const read = (path: string) =>
  readFileSync(resolve(repositoryRoot, path), 'utf8');

describe('T050 SAST last-known-good rollback persistence contracts', () => {
  const schema = read('apps/api/prisma/schema.prisma');
  const migration = read(
    'apps/api/prisma/migrations/20260819220000_sast_rule_bundle_rollback/migration.sql'
  );
  const store = read(
    'apps/api/src/rule-governance/prisma-sast-rule-bundle-rollback.store.ts'
  );
  const service = read(
    'apps/api/src/rule-governance/sast-rule-bundle-rollback.service.ts'
  );
  const router = read(
    'apps/api/src/rule-governance/sast-rule-bundle-lifecycle-authority.router.ts'
  );
  const moduleSource = read(
    'apps/api/src/rule-governance/rule-governance.module.ts'
  );

  const immutableModels = [
    'SastRuleBundleRollbackCommand',
    'SastRuleBundleRollbackVerification',
    'SastRuleBundleRollbackApproval',
    'SastRuleBundleRollbackReceipt',
    'SastRuleBundleRollbackReceiptApproval'
  ];

  it('keeps every rollback ledger normalized, content-free, and append-only', () => {
    for (const model of immutableModels) {
      expect(schema).toContain(`model ${model}`);
      expect(migration).toContain(`CREATE TABLE "${model}"`);
      expect(migration).toContain(`"${model}_immutable_update"`);
      expect(migration).toContain(`"${model}_immutable_delete"`);
      expect(prismaModel(schema, model)).not.toMatch(/\b(?:Json|Bytes)\b/u);
      expect(sqlColumns(migration, model)).toEqual(
        prismaScalarColumns(schema, model)
      );
    }
    expect(migration).not.toContain('ON DELETE CASCADE');
    expect(migration).not.toMatch(
      /"(?:sourceContent|findingContent|ruleContent|secretValue|credential|signatureBytes|provenancePayload|arbitraryPayload)"/iu
    );
  });

  it('derives the target from original promotion evidence and locks both heads canonically', () => {
    expect(service).not.toContain('request.baselineManifestId');
    expect(service).not.toContain('request.baselineBundleDigest');
    expect(service).toContain('evidence.baselineManifestId');
    expect(service).toContain('evidence.rollbackTargetDigest');
    expect(service).toContain('rollbackBaselineIsCurrent');
    expect(store).toContain('lockLifecycleHeads');
    expect(store).toContain(".sort(compareText)");
    expect(store).toContain('runSastKillSwitchSerializable');
    expect(migration).toContain('ORDER BY "manifestId" COLLATE "C"');
    expect(migration).toContain(
      'SAST rollback target was not derived from the original promotion evidence'
    );
    expect(migration).toContain(
      'candidate_manifest."rollbackTargetDigest" IS DISTINCT FROM NEW."baselineBundleDigest"'
    );
    expect(migration).toContain(
      'baseline_head."lifecycleState" IS DISTINCT FROM \'ACTIVE\''
    );
    expect(migration).toContain(
      'CONSTRAINT "SastRuleBundleRollbackCommand_evidence_id_fkey"'
    );
    expect(migration).toContain(
      'CONSTRAINT "SastRuleBundleRollbackCommand_evidence_digest_fkey"'
    );
    expect(migration).not.toMatch(
      /CREATE (?:UNIQUE )?INDEX(?: CONCURRENTLY)? "SastRuleBundlePromotionEvidence/iu
    );
  });

  it('requires exact signed command verification and fresh independent dual approval', () => {
    expect(moduleSource).toContain(
      'UnavailableSastRuleBundleRollbackSignatureAuthority'
    );
    expect(moduleSource).toContain(
      'provide: SastRuleBundleRollbackSignatureAuthority'
    );
    expect(migration).toContain(
      'CREATE CONSTRAINT TRIGGER "SastRuleBundleRollbackCommand_verification"'
    );
    expect(migration).toContain(
      'NEW."approvedAt" > command_record."commandedAt" + INTERVAL \'15 minutes\''
    );
    expect(migration).toContain(
      'NEW."approverRef" = command_record."actorRef"'
    );
    expect(migration).toContain(
      'security_count <> 1 OR platform_count <> 1'
    );
    expect(migration).toContain(
      'CREATE CONSTRAINT TRIGGER "SastRuleBundleRollbackReceipt_approvals"'
    );
    expect(service).toContain('approvalSetCanAccept');
  });

  it('installs only the ROLLBACK lifecycle seam and revalidates both heads at commit', () => {
    expect(router).toContain("input.authority === 'ROLLBACK'");
    expect(router).toContain('this.rollback.authorizeLifecycleTransition(input)');
    expect(moduleSource).toContain('PrismaSastRuleBundleRollbackStore');
    expect(moduleSource).toContain('SastRuleBundleRollbackService');
    expect(migration).toContain(
      'CREATE TRIGGER "SastRuleBundleLifecycleTransition_rollback_authority"'
    );
    expect(migration).toContain(
      'NEW."fromState" <> \'SUSPENDED\' OR NEW."toState" <> \'ROLLED_BACK\''
    );
    expect(migration).toContain(
      'SAST rollback candidate changed before lifecycle commit'
    );
    expect(migration).toContain(
      'SAST rollback baseline changed before lifecycle commit'
    );
    expect(migration).not.toContain('UPDATE "SastRuleBundleLifecycleTransition"');
    expect(migration).not.toContain('UPDATE "SastRuleBundleLifecycleHead"');
    expect(migration).not.toContain('UPDATE "SastRuleBundleManifest"');
  });

  it('keeps rollback receipt authority narrow and content-free', () => {
    for (const field of [
      'baselineMutationAuthorized',
      'historicalMutationAuthorized',
      'scannerSetMutationAuthorized',
      'findingAuthority',
      'policyAuthority',
      'publicationAuthority',
      'scmWriteAuthority'
    ]) {
      expect(prismaModel(schema, 'SastRuleBundleRollbackReceipt')).toContain(
        `${field}`
      );
      expect(migration).toContain(`"${field}" IS FALSE`);
    }
    expect(service).not.toMatch(/Finding|Waiver|Publication|Scm/u);
  });
});

function prismaModel(source: string, name: string): string {
  const start = source.indexOf(`model ${name} {`);
  const end = source.indexOf('\n}', start);
  if (start < 0 || end < 0) throw new Error(`missing Prisma model ${name}`);
  return source.slice(start, end + 2);
}

function prismaScalarColumns(source: string, name: string): string[] {
  return prismaModel(source, name)
    .split('\n')
    .map((line) =>
      /^\s{2}([A-Za-z][A-Za-z0-9]*)\s+(?:String|Int|BigInt|Boolean|DateTime)(?:\?|\s|$)/u.exec(
        line
      )?.[1]
    )
    .filter((value): value is string => value !== undefined)
    .sort();
}

function sqlColumns(source: string, name: string): string[] {
  const start = source.indexOf(`CREATE TABLE "${name}" (`);
  const end = source.indexOf('\n);', start);
  if (start < 0 || end < 0) throw new Error(`missing SQL table ${name}`);
  return source
    .slice(start, end)
    .split('\n')
    .map((line) => /^\s{2}"([^"]+)"\s+/u.exec(line)?.[1])
    .filter((value): value is string => value !== undefined)
    .sort();
}
