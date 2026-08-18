import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const apiRoot = resolve(__dirname, '../..');
const repositoryRoot = resolve(apiRoot, '../..');
const read = (path: string) =>
  readFileSync(resolve(repositoryRoot, path), 'utf8');

describe('T048 rule-bundle canary persistence contracts', () => {
  const schema = read('apps/api/prisma/schema.prisma');
  const migration = read(
    'apps/api/prisma/migrations/20260819120000_sast_rule_bundle_canary/migration.sql'
  );
  const store = read(
    'apps/api/src/rule-governance/prisma-sast-rule-bundle-canary.store.ts'
  );
  const service = read(
    'apps/api/src/rule-governance/sast-rule-bundle-canary.service.ts'
  );
  const keyProvider = read(
    'apps/api/src/rule-governance/sast-rule-bundle-canary-key.provider.ts'
  );
  const moduleSource = read(
    'apps/api/src/rule-governance/rule-governance.module.ts'
  );
  const authorityRouter = read(
    'apps/api/src/rule-governance/sast-rule-bundle-lifecycle-authority.router.ts'
  );
  const planner = read(
    'apps/api/src/control-plane/sast-scan-planner.service.ts'
  );
  const queueStore = read(
    'apps/api/src/control-plane/prisma-sast-queue-admission.store.ts'
  );
  const sharedCanary = read(
    'packages/shared/src/types/sast-rule-bundle-canary.ts'
  );
  const sharedPlanning = read('packages/shared/src/types/sast-planning.ts');

  const immutableModels = [
    'SastRuleBundleCanaryRollout',
    'SastRuleBundleCanaryRolloutStep',
    'SastRuleBundleCanaryEligibilityDecision',
    'SastRuleBundleCanaryMembership',
    'SastRuleBundleCanaryAssignmentReceipt',
    'SastRuleBundleCanaryScanObservation',
    'SastRuleBundleCanaryStepDecision',
    'SastRuleBundleCanaryStepDecisionReason',
    'SastRuleBundleCanaryStepDecisionObservation',
    'SastRuleBundleCanaryObservationReceipt',
    'SastRuleBundleCanaryReceiptPassedStep'
  ];

  it('uses normalized append-only ledgers without content, JSON, or HMAC key material', () => {
    for (const model of immutableModels) {
      expect(schema).toContain(`model ${model}`);
      expect(migration).toContain(`CREATE TABLE "${model}"`);
      expect(migration).toContain(`"${model}_immutable_update"`);
      expect(migration).toContain(`"${model}_immutable_delete"`);
      expect(prismaModel(schema, model)).not.toMatch(/\bJson\b/u);
    }
    expect(schema).toContain('model SastRuleBundleCanaryRolloutHead');
    expect(prismaModel(schema, 'SastRuleBundleCanaryRolloutHead')).not.toMatch(
      /\bJson\b/u
    );
    expect(migration).toContain('SastRuleBundleCanaryRolloutHead_protect_update');
    expect(migration).toContain('SastRuleBundleCanaryRolloutHead_protect_delete');
    expect(migration).not.toContain('ON DELETE CASCADE');
    expect(migration).not.toMatch(/\bJSONB\s+(?:NOT\s+)?NULL\b/iu);
    expect(migration).not.toMatch(
      /"(?:sourceContent|findingContent|ruleContent|secretValue|credential|keyMaterial|hmacKey)"/iu
    );
    expect(prismaModel(schema, 'SastRuleBundleCanaryMembership')).toContain(
      'assignmentHmacDigest'
    );
    expect(prismaModel(schema, 'SastRuleBundleCanaryMembership')).not.toMatch(
      /\b(?:Bytes|Json)\b/u
    );
    expect(keyProvider).toContain('MINIMUM_HMAC_KEY_BYTES = 32');
    expect(service).toContain('keyMaterial?.fill(0)');
    expect(
      prismaModel(schema, 'SastRuleBundleCanaryScanObservation')
    ).toContain('observationSourceDigest');
  });

  it('keeps every Prisma scalar column aligned with the deployable SQL tables', () => {
    for (const model of [
      ...immutableModels,
      'SastRuleBundleCanaryRolloutHead'
    ]) {
      expect(sqlColumns(migration, model)).toEqual(
        prismaScalarColumns(schema, model)
      );
    }
  });

  it('fixes one deterministic six-step rollout and immutable eligibility/membership bindings', () => {
    expect(schema).toContain(
      '@@unique([candidateManifestId, profileId], map: "SastRuleBundleCanaryRollout_candidate_profile_key")'
    );
    expect(migration).toContain(
      'CREATE UNIQUE INDEX "SastRuleBundleCanaryRollout_candidate_profile_key"'
    );
    for (const [position, step] of [
      [0, 'INTERNAL_CORPUS'],
      [1, 'INTERNAL_REPOSITORIES'],
      [2, 'PERCENT_1'],
      [3, 'PERCENT_5'],
      [4, 'PERCENT_25'],
      [5, 'PERCENT_100']
    ] as const) {
      expect(migration).toContain(
        `("position" = ${position} AND "step" = '${step}')`
      );
    }
    expect(migration).toContain(
      'CREATE CONSTRAINT TRIGGER "SastRuleBundleCanaryRollout_progression"'
    );
    expect(migration).toContain(
      'enforce_sast_rule_bundle_canary_eligibility'
    );
    expect(migration).toContain(
      'enforce_sast_rule_bundle_canary_membership'
    );
    expect(migration).toContain(
      'enforce_sast_rule_bundle_canary_assignment'
    );
    expect(migration).toContain('"bucketBasisPoints" < 100');
    expect(migration).toContain('"bucketBasisPoints" < 500');
    expect(migration).toContain('"bucketBasisPoints" < 2500');
    expect(migration).toContain('"bucketBasisPoints" < 10000');
    expect(migration).toContain(
      'derive_sast_rule_bundle_canary_bucket'
    );
    expect(migration).toContain(
      '"bucketBasisPoints" = public."derive_sast_rule_bundle_canary_bucket"("assignmentHmacDigest")'
    );
    expect(service).toContain("createHmac('sha256'");
    expect(sharedCanary).toContain('frame(input.tenantId)');
    expect(sharedCanary).toContain('frame(input.repositoryBindingId)');
    expect(sharedCanary).toContain('frame(input.profileId)');
    expect(sharedCanary).toContain('frame(input.rolloutId)');
    expect(sharedCanary).toContain('immutableForRollout: true');
    expect(service).toContain('evaluatedAt: eligibility.evaluatedAt');
    expect(service).toContain(
      'Date.parse(input.evaluatedAt) < Date.parse(eligibility.evaluatedAt)'
    );
    expect(migration).toContain(
      'NEW."evaluatedAt" < membership_record."evaluatedAt"'
    );
    expect(service).not.toContain('repositoryContentUsed: true');
    expect(service).not.toContain('findingOrSeverityUsed: true');
  });

  it('recomputes every observation aggregate and exact gate outcome in PostgreSQL', () => {
    expect(migration).toContain('percentile_disc(0.50)');
    expect(migration).toContain('percentile_disc(0.95)');
    expect(migration).toContain('bool_and(o."telemetryComplete")');
    expect(migration).toContain('bucket_count = 6');
    for (const measurement of [
      'candidateWaiverCount',
      'baselineWaiverCount',
      'candidateSuppressionCount',
      'baselineSuppressionCount',
      'candidateScannerTimeoutCount',
      'baselineScannerTimeoutCount',
      'candidateEgressDenialCount',
      'baselineEgressDenialCount'
    ]) {
      expect(migration).toContain(`"${measurement}"`);
      expect(sharedCanary).toContain(`${measurement}: number`);
    }
    expect(migration).toContain("minimum_scans := 200");
    expect(migration).toContain("minimum_interval := INTERVAL '24 hours'");
    expect(migration).toContain("minimum_scans := 1000");
    expect(migration).toContain("minimum_interval := INTERVAL '48 hours'");
    expect(migration).toContain('"windowEndedAt" = "evaluatedAt"');
    expect(migration).toContain(
      'NEW."candidateScannerFailureCount"::NUMERIC * 10000'
    );
    expect(migration).toContain(
      'NEW."candidateP95LatencyMilliseconds"::NUMERIC * 10000'
    );
    expect(migration).toMatch(
      /NEW\."candidateCriticalHighFindingCount"::NUMERIC\s+\* NEW\."baselineCompletedScans"::NUMERIC \* 10000/u
    );
    expect(sharedCanary).toContain('relativeRateIncreaseAtMost(');
    for (const reason of [
      'OBSERVATION_WINDOW_INSUFFICIENT',
      'CANDIDATE_SAMPLE_INSUFFICIENT',
      'BASELINE_SAMPLE_INSUFFICIENT',
      'TELEMETRY_MISSING',
      'COVERAGE_INCOMPLETE',
      'PROFILE_SIZE_COMPARISON_INCOMPLETE',
      'FALSE_POSITIVE_GATE_FAILED',
      'SCANNER_FAILURE_GATE_FAILED',
      'LATENCY_GATE_FAILED',
      'CRITICAL_HIGH_VOLUME_GATE_FAILED',
      'ZERO_TOLERANCE_EVENT_RECORDED'
    ]) {
      expect(migration).toContain(`'${reason}'`);
    }
    expect(migration).toContain(
      '(NEW."outcome" = \'PAUSED\') IS DISTINCT FROM hard_failed'
    );
    expect(migration).toContain(
      'head_record."latestOutcome" IS NOT DISTINCT FROM \'PAUSED\''
    );
    expect(migration).toContain(
      'CREATE CONSTRAINT TRIGGER "SastRuleBundleCanaryObservationReceipt_complete"'
    );
    expect(migration).toContain('actual_count <> 6');
    expect(migration).toContain(
      'head_record."currentStep" IS DISTINCT FROM \'PERCENT_100\''
    );
    expect(migration).toContain(
      'actual_reasons IS DISTINCT FROM expected_reasons'
    );
    expect(migration).toContain(
      'ordered_observations.previous_id >= ordered_observations."observationId"'
    );
    expect(migration).toMatch(
      /FROM public\."SastRuleBundleCanaryScanObservation" o\s+WHERE o\."rolloutId" = NEW\."rolloutId"/u
    );
    expect(migration).toMatch(
      /AND NOT EXISTS \(\s+SELECT 1\s+FROM public\."SastRuleBundleCanaryStepDecisionObservation" b/u
    );
    expect(migration).toContain(
      'coverage_failed := NEW."candidateIncompleteCoverageCount" <> 0'
    );
  });

  it('serializes rollout, assignment, observation, and decision writes with replay-only conflicts', () => {
    expect(store).toContain('Prisma.TransactionIsolationLevel.Serializable');
    expect(store).toContain('SERIALIZABLE_RETRIES = 3');
    expect(store).toContain('SERIALIZABLE_MAX_WAIT_MILLISECONDS = 5_000');
    expect(store).toContain('SERIALIZABLE_TIMEOUT_MILLISECONDS = 120_000');
    expect(store).toContain('lockRolloutHead');
    expect(store).toContain('FOR UPDATE');
    expect(store).toContain('async recordAssignments');
    expect(store).toContain('async appendStepDecision');
    expect(store).toContain("'REPLAY_CONFLICT'");
    expect(store).toContain("'STEP_STALE'");
    expect(store).toContain("'ROLLOUT_PAUSED'");
    expect(migration).toContain(
      'CREATE CONSTRAINT TRIGGER "SastRuleBundleCanaryStepDecision_evidence"'
    );
    expect(migration).toContain(
      'CREATE CONSTRAINT TRIGGER "SastRuleBundleCanaryStepDecisionObservation_count"'
    );
    expect(migration).toContain(
      'CREATE CONSTRAINT TRIGGER "SastRuleBundleCanaryStepDecisionReason_count"'
    );
  });

  it('installs the canary planning and lifecycle authority gates while retaining fail-closed adapters', () => {
    expect(moduleSource).toContain('PrismaSastRuleBundleCanaryStore');
    expect(moduleSource).toContain('SastRuleBundleCanaryService');
    expect(moduleSource).toContain('EnvironmentSastRuleBundleCanaryCohortKeyProvider');
    expect(moduleSource).toContain('UnavailableSastRuleBundleCanaryObservationSource');
    expect(moduleSource).toContain('useExisting: SastRuleBundleCanaryService');
    expect(moduleSource).toContain(
      'useExisting: SastRuleBundleLifecycleAuthorityRouter'
    );
    expect(authorityRouter).toContain(
      "input.authority !== 'CANARY_OBSERVATION'"
    );
    expect(authorityRouter).toContain(
      'this.canary.authorizeLifecycleTransition(input)'
    );
    expect(service).toContain('isRolloutLifecycleCurrent');
    expect(migration).toContain(
      'baseline_lifecycle_head."lifecycleState" IS DISTINCT FROM \'ACTIVE\''
    );
    const compatibility = planner.indexOf(
      'ruleBundleCompatibilityGate.verifyScannerSet'
    );
    const lifecycle = planner.indexOf(
      'ruleBundleLifecycleGate.verifyScannerSet'
    );
    const canary = planner.indexOf('ruleBundleCanaryGate.verifyScannerSet');
    const tenantPolicy = planner.indexOf('tenantRulePolicyGate.resolve');
    const queue = planner.indexOf('queueAdmissionService.reserveWithContext');
    expect(lifecycle).toBeGreaterThan(compatibility);
    expect(canary).toBeGreaterThan(lifecycle);
    expect(tenantPolicy).toBeGreaterThan(canary);
    expect(queue).toBeGreaterThan(tenantPolicy);
  });

  it('fences queue admission against lifecycle and canary races in application and database paths', () => {
    const lifecycleFence = queueStore.indexOf(
      'assertCurrentRuleBundleLifecycleHeads(transaction, input.plan)'
    );
    const canaryFence = queueStore.indexOf(
      'assertCurrentRuleBundleCanaryAssignments('
    );
    const scanRead = queueStore.indexOf('transaction.scanRequest.findUnique');
    expect(lifecycleFence).toBeGreaterThan(-1);
    expect(canaryFence).toBeGreaterThan(lifecycleFence);
    expect(scanRead).toBeGreaterThan(canaryFence);
    expect(queueStore).toContain(
      'FROM "SastRuleBundleCanaryRolloutHead" head'
    );
    expect(queueStore).toContain('FOR UPDATE OF head');
    expect(queueStore).toContain("receipt.\"selection\" = 'CANDIDATE'");
    expect(queueStore).toContain("head.latestOutcome === 'PAUSED'");
    expect(migration).toContain(
      'CREATE TRIGGER "SastQueueReservation_canary_head"'
    );
    expect(migration).toContain(
      'enforce_sast_queue_rule_bundle_canary_head'
    );
    expect(migration).toContain(
      'Active SAST bundles cannot carry canary assignments'
    );
    expect(migration).toContain(
      'SAST queue admission canary assignment is stale or unauthorized'
    );
    expect(store).toContain('observationMatchesReservationPlan');
    expect(store).toContain('isSastScanPlanValid(plan)');
    expect(migration).toContain(
      'plan_bundle->\'lifecycle\'->>\'lifecycleState\' = \'CANARY\''
    );
    expect(migration).toContain(
      'plan_bundle->\'lifecycle\'->>\'lifecycleState\' = \'ACTIVE\''
    );
    expect(migration).toContain(
      'rollout_record."observationSourceDigest" IS DISTINCT FROM NEW."observationSourceDigest"'
    );
    expect(migration).toContain(
      'NEW."incompleteCoverageCount" IS DISTINCT FROM'
    );
    expect(migration).toContain(
      'NEW."publicationDenialCount" IS DISTINCT FROM'
    );
  });

  it('uses canonical v4 stable cohort identity and drains every non-terminal v3 plan', () => {
    expect(sharedPlanning).toContain("'sast-canonical-scan-key-v4'");
    const canonicalPreimage = sharedPlanning
      .split('export function buildSastCanonicalScanKeyPreimage')[1]
      .split('function rejectedProfileSelection')[0];
    expect(canonicalPreimage).toContain('rolloutId:');
    expect(canonicalPreimage).toContain('rolloutDigest:');
    expect(canonicalPreimage).toContain('membershipId:');
    expect(canonicalPreimage).toContain('membershipDigest:');
    expect(canonicalPreimage).toContain('bucketBasisPoints:');
    expect(canonicalPreimage).toContain('candidateAssigned: true');
    expect(canonicalPreimage).not.toContain('assignmentReceiptId');
    expect(canonicalPreimage).not.toContain('assignmentReceiptDigest');
    expect(canonicalPreimage).not.toContain('stepHeadDecisionId');
    expect(canonicalPreimage).not.toContain('stepHeadDecisionDigest');
    expect(migration).toContain('T048 canonical scan-key v4 cutover');
    expect(migration).toContain(
      'all existing v3 SAST plans and reservations to be completed, failed, or canceled'
    );
    expect(migration).toContain(
      '"status" IN (\'QUEUED\', \'PLANNING\', \'RUNNING\')'
    );
    expect(migration).toContain('"terminalStatus" IS NULL');
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
      /^\s{2}([A-Za-z][A-Za-z0-9]*)\s+(?:String|Int|BigInt|Boolean|DateTime|ScanLane)(?:\?|\s|$)/u.exec(
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
