import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const apiRoot = resolve(__dirname, '../..');
const repositoryRoot = resolve(apiRoot, '../..');
const read = (path: string) =>
  readFileSync(resolve(repositoryRoot, path), 'utf8');

describe('T049 SAST kill-switch persistence and propagation contracts', () => {
  const schema = read('apps/api/prisma/schema.prisma');
  const migration = read(
    'apps/api/prisma/migrations/20260819180000_sast_kill_switch_authority/migration.sql'
  );
  const store = read(
    'apps/api/src/rule-governance/prisma-sast-kill-switch.store.ts'
  );
  const service = read(
    'apps/api/src/rule-governance/sast-kill-switch.service.ts'
  );
  const moduleSource = read(
    'apps/api/src/rule-governance/rule-governance.module.ts'
  );
  const router = read(
    'apps/api/src/rule-governance/sast-rule-bundle-lifecycle-authority.router.ts'
  );
  const planner = read(
    'apps/api/src/control-plane/sast-scan-planner.service.ts'
  );
  const queueStore = read(
    'apps/api/src/control-plane/prisma-sast-queue-admission.store.ts'
  );
  const runtime = read(
    'apps/api/src/scan-plane/sast-scanner-runtime.service.ts'
  );
  const artifact = read(
    'apps/api/src/scan-plane/sast-kill-switch-artifact-acceptance.gate.ts'
  );
  const retry = read(
    'apps/api/src/scan-plane/sast-kill-switch-retry-runtime.authority.ts'
  );
  const coverage = read(
    'apps/api/src/scan-plane/sast-kill-switch-finding-lifecycle-coverage.gate.ts'
  );
  const scanModule = read('apps/api/src/scan-plane/scan-plane.module.ts');
  const controlPlane = read(
    'apps/api/src/control-plane/control-plane.service.ts'
  );
  const ai = read('apps/api/src/ai-plane/ai-advisory.service.ts');
  const canarySuspension = read(
    'apps/api/src/rule-governance/sast-kill-switch-canary-suspension.service.ts'
  );
  const sharedPlanning = read('packages/shared/src/types/sast-planning.ts');

  const immutableModels = [
    'SastKillSwitchDecision',
    'SastKillSwitchVerification',
    'SastKillSwitchEvaluation',
    'SastKillSwitchEvaluationHead',
    'SastKillSwitchEvaluationMatch',
    'SastKillSwitchEmergencySuspensionReceipt'
  ];

  it('keeps normalized append-only ledgers aligned between Prisma and deployable SQL', () => {
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
    expect(schema).toContain('model SastKillSwitchHead');
    expect(prismaModel(schema, 'SastKillSwitchHead')).not.toMatch(
      /\b(?:Json|Bytes)\b/u
    );
    expect(sqlColumns(migration, 'SastKillSwitchHead')).toEqual(
      prismaScalarColumns(schema, 'SastKillSwitchHead')
    );
    expect(migration).not.toContain('ON DELETE CASCADE');
    expect(migration).not.toMatch(
      /"(?:sourceContent|findingContent|ruleContent|secretValue|credential|signatureBytes|provenancePayload|arbitraryPayload)"/iu
    );
  });

  it('serializes selector chains, protects heads, and binds exact trusted verification', () => {
    expect(store).toContain('Prisma.TransactionIsolationLevel.Serializable');
    expect(store).toContain('SERIALIZABLE_RETRIES = 3');
    expect(store).toContain('ensureHeadPlaceholders');
    expect(store).toContain('lockHeads');
    expect(store).toContain('FOR UPDATE');
    expect(migration).toContain('pg_advisory_xact_lock');
    expect(migration).toContain('decision is stale or forks its selector chain');
    expect(migration).toContain(
      'deactivation requires one active current head'
    );
    expect(migration).toContain(
      'decision lacks exact trusted signature verification'
    );
    expect(migration).toContain('SastKillSwitchHead_protect_insert');
    expect(migration).toContain('SastKillSwitchHead_protect_update');
    expect(migration).toContain('SastKillSwitchHead_protect_delete');
    expect(service).toContain('MAX_BOUNDARY_CLOCK_SKEW_MILLISECONDS');
    expect(service).toContain('assertTrustedBoundaryTime');
    expect(schema).toContain(
      '@@unique([id, decisionDigest], map: "SastKillSwitchDecision_id_digest_key")'
    );
    expect(schema).toContain(
      '@@unique([id, decisionDigest, selectorKey], map: "SastKillSwitchDecision_identity_key")'
    );
  });

  it('locks the complete selector head set and rejects stale, expired, or partial receipts', () => {
    expect(store).toContain('buildApplicableSastKillSwitchSelectors');
    expect(store).toContain("'ACTIVE_DECISION_EXPIRED'");
    expect(migration).toContain('evaluation head is stale');
    expect(migration).toContain(
      'active authority expired without explicit deactivation'
    );
    expect(migration).toContain(
      'evaluation child set is incomplete or inconsistent'
    );
    expect(migration).toContain(
      'CREATE CONSTRAINT TRIGGER "SastKillSwitchEvaluation_complete"'
    );
    expect(migration).toContain(
      'CREATE TRIGGER "SastQueueReservation_zz_kill_switch_head"'
    );
    expect(migration).toContain(
      'SAST queue admission kill-switch selector set does not match the immutable plan'
    );
    expect(migration).toContain(
      `jsonb_each(NEW."immutablePlan"->'scannerSet'->'scanners')`
    );
    expect(queueStore).toContain('assertCurrentSastKillSwitchEvaluation');
    expect(queueStore).toContain('buildApplicableSastKillSwitchSelectors');
    expect(queueStore).toContain(
      'context.contextDigest !== projection.contextDigest'
    );
    expect(queueStore).toContain('FOR UPDATE OF head');
    expect(queueStore).toContain(
      'SAST kill-switch state changed before queue admission.'
    );
  });

  it('installs one authority across planning, runtime, artifact, retry, publication, AI, and suspension boundaries', () => {
    expect(moduleSource).toContain('PrismaSastKillSwitchStore');
    expect(moduleSource).toContain('useExisting: SastKillSwitchService');
    expect(router).toContain("input.authority === 'EMERGENCY_SUSPENSION'");
    expect(router).toContain('authorizeEmergencySuspension(input)');
    expect(migration).toContain(
      'SastKillSwitchEmergencySuspensionReceipt_binding'
    );
    expect(migration).toContain(
      "NEW.\"externalAuthority\" = 'EMERGENCY_SUSPENSION'"
    );

    const canary = planner.indexOf('ruleBundleCanaryGate.verifyScannerSet');
    const killSwitch = planner.indexOf('killSwitchGate.evaluateContext');
    const tenantPolicy = planner.indexOf('tenantRulePolicyGate.resolve');
    const queue = planner.indexOf('queueAdmissionService.reserveWithContext');
    expect(killSwitch).toBeGreaterThan(canary);
    expect(tenantPolicy).toBeGreaterThan(killSwitch);
    expect(queue).toBeGreaterThan(tenantPolicy);
    expect(runtime).toContain("gate: 'SCANNER_START'");
    expect(runtime.indexOf("gate: 'SCANNER_START'")).toBeLessThan(
      runtime.indexOf('this.provider.readRepositoryManifest(operation)')
    );
    expect(artifact).toContain("gate: 'ARTIFACT_ACCEPTANCE'");
    expect(artifact).toContain('acceptanceAuthority.evaluate(input)');
    expect(retry).toContain("gate: 'RETRY_ADMISSION'");
    expect(coverage).toContain("gate: 'COVERAGE'");
    expect(coverage).toContain('coverageAuthority.verify(decision)');
    expect(scanModule).toContain(
      'useExisting: SastKillSwitchFindingLifecycleCoverageGate'
    );
    expect(controlPlane).toContain("gate: 'EXTERNAL_PUBLICATION'");
    expect(controlPlane).toContain(
      'assertExternalPublicationKillSwitchClear'
    );
    expect(ai).toContain("gate: 'AI_ADVISORY'");
    expect(canarySuspension).toContain(
      'isSastKillSwitchCanarySuspensionRequestValid'
    );
    expect(canarySuspension).toContain(
      'SastRuleBundleCanaryRolloutHead'
    );
    expect(canarySuspension).toContain(
      "lifecycle.lifecycleState !== 'CANARY'"
    );
    expect(canarySuspension).not.toContain('request.candidateManifest');
    expect(canarySuspension).not.toContain('request.candidateBundle');
    expect(store).toContain('gate');
    expect(sharedPlanning).toContain("'sast-canonical-scan-key-v4'");
    const canonicalPreimage = sharedPlanning
      .split('export function buildSastCanonicalScanKeyPreimage')[1]
      .split('function rejectedProfileSelection')[0];
    expect(canonicalPreimage).not.toContain('killSwitchEvaluation');
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
