import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const apiRoot = resolve(__dirname, '../..');
const repositoryRoot = resolve(apiRoot, '../..');
const read = (path: string) =>
  readFileSync(resolve(repositoryRoot, path), 'utf8');

describe('T047 rule-bundle lifecycle persistence contracts', () => {
  const schema = read('apps/api/prisma/schema.prisma');
  const migration = read(
    'apps/api/prisma/migrations/20260814120000_sast_rule_bundle_lifecycle/migration.sql'
  );
  const store = read(
    'apps/api/src/rule-governance/prisma-sast-rule-bundle-lifecycle.store.ts'
  );
  const service = read(
    'apps/api/src/rule-governance/sast-rule-bundle-lifecycle.service.ts'
  );
  const authorityRouter = read(
    'apps/api/src/rule-governance/sast-rule-bundle-lifecycle-authority.router.ts'
  );
  const moduleSource = read(
    'apps/api/src/rule-governance/rule-governance.module.ts'
  );
  const planner = read(
    'apps/api/src/control-plane/sast-scan-planner.service.ts'
  );
  const queueStore = read(
    'apps/api/src/control-plane/prisma-sast-queue-admission.store.ts'
  );
  const sharedRuntime = read('packages/shared/src/types/sast-runtime.ts');
  const sharedPlanning = read('packages/shared/src/types/sast-planning.ts');

  it('uses normalized immutable tables without JSON or executable payload columns', () => {
    for (const model of [
      'SastRuleBundlePromotionEvidence',
      'SastRuleBundlePromotionApproval',
      'SastRuleBundleLifecycleTransition',
      'SastRuleBundleLifecycleTransitionApproval',
      'SastRuleBundleLifecycleSelectionReceipt'
    ]) {
      expect(schema).toContain(`model ${model}`);
      expect(migration).toContain(`CREATE TABLE "${model}"`);
      expect(migration).toContain(`"${model}_immutable_update"`);
      expect(migration).toContain(`"${model}_immutable_delete"`);
      expect(prismaModel(schema, model)).not.toMatch(/\bJson\b/u);
    }
    expect(migration).not.toMatch(
      /"(?:sourceContent|ruleContent|repositoryContent|secretValue|credential|customerConfig)"/iu
    );
    expect(migration).not.toContain('ON DELETE CASCADE');
    expect(schema).toContain('model SastRuleBundleLifecycleHead');
    expect(migration).toContain(
      'CREATE TABLE "SastRuleBundleLifecycleHead"'
    );
    expect(prismaModel(schema, 'SastRuleBundleLifecycleHead')).not.toMatch(
      /\bJson\b/u
    );
    expect(migration).toContain('SastRuleBundleLifecycleHead_protect_update');
  });

  it('enforces quantitative gates, separation of duties, and the exact state graph in PostgreSQL', () => {
    expect(migration).toContain('"positiveCases" BETWEEN 200');
    expect(migration).toContain('"negativeCases" BETWEEN 200');
    expect(migration).toContain('"performanceRuns" BETWEEN 30');
    expect(migration).toContain('* 10000 >= "mustDetectExpectedCases"::BIGINT * 9500');
    expect(migration).toContain('* 10000 >= "criticalHighReportedCases"::BIGINT * 9000');
    expect(migration).toContain('"falsePositiveIncreaseBasisPoints" BETWEEN -10000 AND 200');
    expect(migration).toContain('"scannerFailureRateBasisPoints" BETWEEN 0 AND 200');
    expect(migration).toContain('"p95LatencyIncreaseBasisPoints" BETWEEN -10000 AND 2000');
    expect(migration).toContain(
      '"goldenTotalCases" = "positiveCases" + "negativeCases"'
    );
    expect(migration).toContain(
      '"candidateP95LatencyMilliseconds" BETWEEN 1 AND 600000'
    );
    expect(migration).toContain(
      '"candidateP95LatencyMilliseconds" BETWEEN 1 AND 2700000'
    );
    expect(migration).toContain('"crossTenantEvents" = 0');
    expect(migration).toContain('"approverRef" <> "candidateAuthorRef"');
    expect(migration).toContain("'DRAFT' AND \"toState\" = 'VALIDATED'");
    expect(migration).toContain("'VALIDATED' AND \"toState\" = 'CANARY'");
    expect(migration).toContain("'CANARY' AND \"toState\" = 'ACTIVE'");
    expect(migration).toContain("'ACTIVE' AND \"toState\" = 'RETIRED'");
    expect(migration).toContain("\"toState\" = 'SUSPENDED'");
    expect(migration).toContain("'SUSPENDED' AND \"toState\" = 'ROLLED_BACK'");
    expect(migration).toContain('SastRuleBundleLifecycleTransition_approval_evidence_key');
    expect(migration).toContain('SastRuleBundleLifecycleTransition_approval_set');
  });

  it('serializes append and latest-selection races with bounded retries', () => {
    expect(store).toContain('recordLifecycleSelections');
    expect(store).toContain('Prisma.TransactionIsolationLevel.Serializable');
    expect(store).toContain('SERIALIZABLE_RETRIES = 3');
    expect(store).toContain('SERIALIZABLE_MAX_WAIT_MILLISECONDS = 5_000');
    expect(store).toContain('SERIALIZABLE_TIMEOUT_MILLISECONDS = 120_000');
    expect(migration).toContain('pg_advisory_xact_lock');
    expect(migration).toContain(
      '"kind" = \'PROFILE_ID\' AND "value" = NEW."profileId"'
    );
    expect(store).toContain('FOR UPDATE');
    expect(store).toContain('lockLifecycleManifest');
    expect(migration).toContain('enforce_sast_rule_bundle_lifecycle_append');
    expect(migration).toContain('enforce_sast_rule_bundle_lifecycle_selection');
    expect(migration).toContain('ORDER BY "sequence" DESC LIMIT 1');
    expect(store).toContain("'STALE_TRANSITION'");
    expect(store).toContain("'REPLAY_CONFLICT'");
    expect(store).toMatch(
      /recordLifecycleSelections[\s\S]*?sastRuleBundleLifecycleTransition\.findFirst[\s\S]*?sastRuleBundleLifecycleSelectionReceipt\.findUnique/u
    );
    const selectionWrite = store
      .split('async recordLifecycleSelections')[1]
      .split('private async replayEvidenceAfterConflict')[0];
    expect(selectionWrite).not.toContain(
      'attempt <= SERIALIZABLE_RETRIES'
    );
    expect(selectionWrite).toContain('replaySelectionsAfterConflict');
    expect(migration).not.toContain('INTO STRICT');
  });

  it('fences queue admission against a concurrent lifecycle transition', () => {
    const headLock = queueStore.indexOf(
      'assertCurrentRuleBundleLifecycleHeads(transaction, input.plan)'
    );
    const existingReservation = queueStore.indexOf(
      'transaction.sastQueueReservation.findUnique'
    );
    const scanRequestRead = queueStore.indexOf(
      'transaction.scanRequest.findUnique'
    );
    expect(headLock).toBeGreaterThan(-1);
    expect(headLock).toBeGreaterThan(existingReservation);
    expect(scanRequestRead).toBeGreaterThan(headLock);
    expect(queueStore).toContain('FROM "SastRuleBundleLifecycleHead" head');
    expect(queueStore).toContain('FOR UPDATE OF head');
    expect(queueStore).toContain('selectionReceiptExists');
    expect(migration).toContain(
      'SastRuleBundleLifecycleTransition_refresh_head'
    );
    expect(migration).toContain('SastQueueReservation_lifecycle_head');
    expect(migration).toContain(
      'enforce_sast_queue_rule_bundle_lifecycle_head'
    );
    expect(migration).toContain('FOR UPDATE');
  });

  it('installs the T048 canary authority while keeping T049 and T050 unavailable', () => {
    expect(service).toContain("'CANARY_OBSERVATION'");
    expect(service).toContain("'EMERGENCY_SUSPENSION'");
    expect(service).toContain("'ROLLBACK'");
    expect(moduleSource).toContain(
      'UnavailableSastRuleBundleLifecycleAuthority'
    );
    expect(moduleSource).toContain('SastRuleBundleLifecycleAuthorityRouter');
    expect(moduleSource).toContain('provide: SastRuleBundleLifecycleAuthority');
    expect(moduleSource).toContain(
      'useExisting: SastRuleBundleLifecycleAuthorityRouter'
    );
    expect(authorityRouter).toContain("input.authority !== 'CANARY_OBSERVATION'");
    expect(authorityRouter).toContain('this.canary.authorizeLifecycleTransition');
    expect(authorityRouter).toContain('this.unavailable.authorize()');
    expect(moduleSource).toContain('provide: SastRuleBundleLifecycleGate');
    expect(moduleSource).toContain('useExisting: SastRuleBundleLifecycleService');
  });

  it('orders compatibility, lifecycle, canary, and tenant policy before queue reservation', () => {
    const compatibility = planner.indexOf(
      'ruleBundleCompatibilityGate.verifyScannerSet'
    );
    const lifecycle = planner.indexOf(
      'ruleBundleLifecycleGate.verifyScannerSet'
    );
    const canary = planner.indexOf('ruleBundleCanaryGate.verifyScannerSet');
    const tenantPolicy = planner.indexOf('tenantRulePolicyGate.resolve');
    const queue = planner.indexOf('queueAdmissionService.reserveWithContext');
    expect(compatibility).toBeGreaterThan(-1);
    expect(lifecycle).toBeGreaterThan(compatibility);
    expect(canary).toBeGreaterThan(lifecycle);
    expect(tenantPolicy).toBeGreaterThan(canary);
    expect(queue).toBeGreaterThan(tenantPolicy);
    expect(sharedRuntime).toContain(
      'isCanaryQualifiedScannerSetDescriptorValid(plan.scannerSet)'
    );
    expect(sharedPlanning).toContain("'sast-canonical-scan-key-v4'");
    expect(sharedPlanning).toContain(
      'lifecycleTransitionDigest:'
    );
    expect(sharedPlanning).toContain('approvalSetDigest:');
    const canonicalPreimage = sharedPlanning
      .split('export function buildSastCanonicalScanKeyPreimage')[1]
      .split('function rejectedProfileSelection')[0];
    expect(canonicalPreimage).not.toContain('selectionReceiptId');
    expect(canonicalPreimage).not.toContain('selectionReceiptDigest');
    expect(migration).toContain('T047 canonical scan-key v3 cutover');
    expect(migration).toContain('"terminalStatus" IS NULL');
    expect(migration).toContain(
      '"status" IN (\'QUEUED\', \'PLANNING\', \'RUNNING\')'
    );
  });
});

function prismaModel(source: string, name: string): string {
  const start = source.indexOf(`model ${name} {`);
  const end = source.indexOf('\n}', start);
  if (start < 0 || end < 0) throw new Error(`missing Prisma model ${name}`);
  return source.slice(start, end + 2);
}
