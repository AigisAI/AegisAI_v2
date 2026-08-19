import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign as signBytes
} from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES,
  SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS,
  SAST_END_TO_END_QUALIFICATION_ENTRY_ATTESTATION_VERSION,
  SAST_END_TO_END_QUALIFICATION_PIPELINE_PHASES,
  SAST_END_TO_END_QUALIFICATION_RECEIPT_SIGNATURE_ROLES,
  SAST_END_TO_END_QUALIFICATION_SIGNATURE_ROLES,
  SAST_END_TO_END_QUALIFICATION_SIGNATURE_VERSION,
  SAST_ISOLATED_QUALIFICATION_CLEANUP_CONTROLS,
  SAST_ISOLATED_QUALIFICATION_RESULT_VERSION,
  buildSastEndToEndQualificationAttempt,
  buildSastEndToEndQualificationDependencySet,
  buildSastEndToEndQualificationEntryAttestation,
  buildSastEndToEndQualificationReceipt,
  serializeSastEndToEndQualificationSignaturePayload
} from '../../packages/shared/dist/index.js';
import { loadAndValidateEndToEndQualificationPackage } from '../../tools/sast-qualification/end-to-end-qualification-loader.mjs';

const repositoryRoot = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const planTool = join(
  repositoryRoot,
  'tools',
  'sast-qualification',
  'generate-end-to-end-qualification-plan.mjs'
);
const verifierTool = join(
  repositoryRoot,
  'tools',
  'sast-qualification',
  'verify-end-to-end-qualification-evidence.mjs'
);
const ZERO_COUNTS = Object.freeze({
  crossTenantLeakCount: 0,
  secretLeakCount: 0,
  sandboxEscapeCount: 0,
  staleExternalPublicationCount: 0,
  unauthorizedEgressCount: 0,
  missingDestructionEvidenceCount: 0,
  evidencePolicyViolationCount: 0,
  unsignedArtifactExecutionCount: 0
});

test('T054 verifier remains blocked with exit code 2 and rejects clock spoofing', async () => {
  const run = await runNode(verifierTool, []);
  assert.equal(run.code, 2, run.stderr);
  const result = JSON.parse(run.stdout);
  assert.equal(result.status, 'BLOCKED_T053_QUALIFICATION');
  assert.equal(result.observedReceiptCount, 0);
  assert.equal(result.t055EntryAuthorized, false);
  assert.equal(result.productionReadinessAuthority, false);

  const spoofedClock = await runNode(verifierTool, [
    '--evaluated-at',
    '2026-08-20T00:10:00.000Z'
  ]);
  assert.equal(spoofedClock.code, 1);
  assert.match(spoofedClock.stderr, /invalid or duplicate qualification tool argument/u);
});

test('T054 tools verify real Ed25519 entry, approvals, and receipt signatures', async (t) => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'aegis-t054-tools-'));
  t.after(() => rm(temporaryRoot, { recursive: true, force: true }));
  const qualificationPackage = await loadAndValidateEndToEndQualificationPackage();
  const clock = buildClock();
  const trust = buildTrustBundle(clock);
  const dependencySet = buildDependencySet(
    trust.text,
    qualificationPackage.manifest,
    clock
  );
  const t053Result = passedT053Result(qualificationPackage.manifest, clock);
  const entryAttestation = buildEntryAttestation(
    qualificationPackage.manifest,
    t053Result,
    trust,
    clock
  );

  const t053Path = await writeJson(temporaryRoot, 't053-result.json', t053Result);
  const entryPath = await writeJson(
    temporaryRoot,
    'entry-attestation.json',
    entryAttestation
  );
  const dependencyPath = await writeJson(
    temporaryRoot,
    'dependency-set.json',
    dependencySet
  );
  const trustPath = join(temporaryRoot, 'trust-bundle.json');
  await writeFile(trustPath, trust.text, 'utf8');
  const planRun = await runNode(planTool, [
    '--t053-result',
    t053Path,
    '--entry-attestation',
    entryPath,
    '--dependency-set',
    dependencyPath,
    '--trust-bundle',
    trustPath
  ]);
  assert.equal(planRun.code, 0, planRun.stderr);
  const plan = JSON.parse(planRun.stdout);
  assert.equal(plan.executionCellCount, 3462);
  assert.equal(plan.aggregateMetricsAcceptedFromCaller, false);
  const planPath = await writeJson(temporaryRoot, 'plan.json', plan);

  const evidenceClock = evidenceClockAfter(plan.plannedAt);
  const approvals = SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES.map((role) =>
    createSignature(role, plan.planDigest, evidenceClock.approvalSignedAt, trust)
  );
  const cell = qualificationPackage.manifest.cells[0];
  const receipt = buildReceipt(
    cell,
    qualificationPackage.manifest,
    plan,
    dependencySet,
    evidenceClock
  );
  const receipts = [
    {
      receipt,
      signatures: SAST_END_TO_END_QUALIFICATION_RECEIPT_SIGNATURE_ROLES.map(
        (role) =>
          createSignature(role, receipt.receiptDigest, evidenceClock.receiptSignedAt, trust)
      )
    }
  ];
  const approvalsPath = await writeJson(temporaryRoot, 'approvals.json', approvals);
  const receiptsPath = await writeJson(temporaryRoot, 'receipts.json', receipts);
  const verifierArgs = [
    '--t053-result',
    t053Path,
    '--entry-attestation',
    entryPath,
    '--dependency-set',
    dependencyPath,
    '--plan',
    planPath,
    '--approvals',
    approvalsPath,
    '--receipts',
    receiptsPath,
    '--trust-bundle',
    trustPath
  ];
  const pending = await runNode(verifierTool, verifierArgs);
  assert.equal(pending.code, 2, pending.stderr);
  const pendingResult = JSON.parse(pending.stdout);
  assert.equal(pendingResult.status, 'PENDING_PROVIDER_EXECUTION');
  assert.equal(pendingResult.validReceiptCount, 1);
  assert.deepEqual(pendingResult.failureReasons, []);
  assert.equal(pendingResult.t055EntryAuthorized, false);

  receipts[0].signatures[0].valueBase64 = Buffer.alloc(64).toString('base64');
  await writeJson(temporaryRoot, 'receipts.json', receipts);
  const tampered = await runNode(verifierTool, verifierArgs);
  assert.equal(tampered.code, 1, tampered.stderr);
  const tamperedResult = JSON.parse(tampered.stdout);
  assert.equal(tamperedResult.status, 'FAILED');
  assert.ok(tamperedResult.failureReasons.includes('RECEIPT_SIGNATURE_INVALID'));
  assert.equal(tamperedResult.t055EntryAuthorized, false);
});

function buildClock(base = Date.now()) {
  const instant = (offset) => new Date(base + offset * 1_000).toISOString();
  return Object.freeze({
    validFrom: instant(-3_600),
    t053EvaluatedAt: instant(-3_000),
    entryVerifiedAt: instant(-2_400),
    validUntil: instant(43_200)
  });
}

function evidenceClockAfter(plannedAt) {
  const base = Math.max(Date.now() - 4_000, Date.parse(plannedAt));
  const instant = (milliseconds) => new Date(base + milliseconds).toISOString();
  return Object.freeze({
    approvalSignedAt: instant(1),
    startedAt: instant(2),
    completedAt: instant(1_002),
    cleanupCompletedAt: instant(2_002),
    receiptSignedAt: instant(2_003)
  });
}

function buildTrustBundle(clock) {
  const privateKeys = new Map();
  const keys = SAST_END_TO_END_QUALIFICATION_SIGNATURE_ROLES.map((role) => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
    const keyDigest = digestBytes(publicKey.export({ type: 'spki', format: 'der' }));
    const keyId =
      `qualification-key://aegisai/t054/${role.toLowerCase().replaceAll('_', '-')}/${keyDigest}`;
    privateKeys.set(role, { keyId, privateKey });
    return {
      keyId,
      role,
      algorithm: 'ED25519',
      publicKeyPem,
      validFrom: clock.validFrom,
      validUntil: clock.validUntil
    };
  });
  const value = {
    version: 'sast-end-to-end-qualification-trust-bundle-v1',
    revision: '1.0.0',
    keys,
    immutable: true
  };
  return {
    value,
    text: `${JSON.stringify(value, null, 2)}\n`,
    privateKeys
  };
}

function buildDependencySet(trustText, manifest, clock) {
  const trustDigest = digest(trustText);
  const candidateScannerSetDigest = digest('candidate-scanner-set');
  const baselineScannerSetDigest = digest('baseline-scanner-set');
  const performance = manifest.cells.find((cell) =>
    cell.cellKind.startsWith('PERFORMANCE_')
  );
  assert.ok(performance?.hardwareClassRef);
  const artifacts = SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS.map(
    (artifactKey) => {
      const artifactDigest =
        artifactKey === 'TRUST_POLICY'
          ? trustDigest
          : artifactKey === 'CANDIDATE_SCANNER_SET'
            ? candidateScannerSetDigest
            : artifactKey === 'BASELINE_SCANNER_SET'
              ? baselineScannerSetDigest
              : digest(`artifact:${artifactKey}`);
      return {
        artifactKey,
        artifactRef:
          `qualification-artifact://aegisai/t054/${artifactKey.toLowerCase()}/${artifactDigest}`,
        artifactDigest,
        signatureRef: digestRef(
          `artifact-signature://aegisai/t054/${artifactKey.toLowerCase()}`,
          `signature:${artifactKey}`
        ),
        provenanceRef: digestRef(
          `artifact-provenance://aegisai/t054/${artifactKey.toLowerCase()}`,
          `provenance:${artifactKey}`
        )
      };
    }
  );
  const result = buildSastEndToEndQualificationDependencySet(
    {
      revision: '1.0.0',
      providerId: 'microvm-provider://qualification/t054',
      providerAdapterRef: digestRef(
        'provider-adapter://aegisai/t054',
        'provider-adapter'
      ),
      validFrom: clock.validFrom,
      validUntil: clock.validUntil,
      candidateScannerSetDigest,
      baselineScannerSetDigest,
      performanceHardwareClassRef: performance.hardwareClassRef,
      performanceHardwareClassDigest: performance.hardwareClassDigest,
      artifacts
    },
    digest
  );
  assert.ok(result);
  return result;
}

function passedT053Result(manifest, clock) {
  const core = {
    version: SAST_ISOLATED_QUALIFICATION_RESULT_VERSION,
    manifestId: manifest.t053ManifestId,
    manifestDigest: manifest.t053ManifestDigest,
    dependencySetDigest: digest('t053-dependency-set'),
    planDigest: digest('t053-plan'),
    status: 'PASSED',
    expectedCellCount: 123,
    receivedReceiptCount: 123,
    validatedReceiptCount: 123,
    missingCellCount: 0,
    missingCellSetDigest: digest('[]'),
    failureReasons: [],
    evaluatedAt: clock.t053EvaluatedAt,
    t053Complete: true,
    t054EntryAuthorized: true,
    findingAuthority: false,
    policyAuthority: false,
    publicationAuthority: false,
    productionReadinessAuthority: false,
    immutable: true
  };
  const resultDigest = digest(stableJson(core));
  return {
    ...core,
    resultId:
      `sast-isolated-qualification-result://${resultDigest.slice('sha256:'.length)}`,
    resultDigest
  };
}

function buildEntryAttestation(manifest, t053Result, trust, clock) {
  const input = {
    t053ManifestId: manifest.t053ManifestId,
    t053ManifestDigest: manifest.t053ManifestDigest,
    t053ResultId: t053Result.resultId,
    t053ResultDigest: t053Result.resultDigest,
    t053DependencySetDigest: t053Result.dependencySetDigest,
    verifiedAt: clock.entryVerifiedAt,
    verifierRef: digestRef(
      'qualification-verifier://aegisai/t054-entry',
      'entry-verifier'
    )
  };
  const payloadDigest = digest(
    stableJson({
      version: SAST_END_TO_END_QUALIFICATION_ENTRY_ATTESTATION_VERSION,
      ...input,
      t054EntryAuthorized: true,
      findingAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      deploymentAuthority: false,
      productionReadinessAuthority: false
    })
  );
  const result = buildSastEndToEndQualificationEntryAttestation(
    input,
    createSignature(
      'QUALIFICATION_AUTHORITY',
      payloadDigest,
      clock.entryVerifiedAt,
      trust
    ),
    digest
  );
  assert.ok(result);
  return result;
}

function buildReceipt(cell, manifest, plan, dependencySet, clock) {
  const attempt = buildSastEndToEndQualificationAttempt(
    {
      attemptId: digestRef('qualification-attempt://aegisai/t054', cell.cellId),
      sandboxId: digestRef('qualification-sandbox://aegisai/t054', cell.cellId),
      workloadId: digestRef('qualification-workload://aegisai/t054', cell.cellId),
      providerAttestationRef: digestRef(
        'provider-attestation://aegisai/t054',
        cell.cellId
      ),
      runtimeAttestationRef: digestRef(
        'runtime-attestation://aegisai/t054',
        cell.cellId
      ),
      telemetryAttestationRef: digestRef(
        'telemetry-attestation://aegisai/t054',
        cell.cellId
      ),
      startedAt: clock.startedAt,
      completedAt: clock.completedAt,
      cleanupCompletedAt: clock.cleanupCompletedAt,
      outcome: 'COMPLETED',
      latencyMilliseconds: 1000,
      cpuMilliseconds: 100,
      peakMemoryBytes: 1024,
      peakDiskBytes: 1024,
      phaseEgressCount: 0,
      zeroToleranceCounts: { ...ZERO_COUNTS },
      cleanupControls: [...SAST_ISOLATED_QUALIFICATION_CLEANUP_CONTROLS],
      cleanupComplete: true
    },
    digest
  );
  assert.ok(attempt);
  const expectedFindings = cell.expectedFindingCount ?? 0;
  const criticalHigh =
    cell.expectedOutcome === 'DETECT' &&
    (cell.severity === 'CRITICAL' || cell.severity === 'HIGH')
      ? 1
      : 0;
  const receipt = buildSastEndToEndQualificationReceipt(
    {
      manifestId: manifest.manifestId,
      manifestDigest: manifest.manifestDigest,
      dependencySetId: dependencySet.dependencySetId,
      dependencySetDigest: dependencySet.dependencySetDigest,
      planId: plan.planId,
      planDigest: plan.planDigest,
      cellId: cell.cellId,
      cellDigest: cell.cellDigest,
      cellKind: cell.cellKind,
      arm: cell.arm,
      caseId: cell.caseId,
      caseDigest: cell.caseDigest,
      profileId: cell.profileId,
      profileDigest: cell.profileDigest,
      providerId: dependencySet.providerId,
      candidateScannerSetDigest: dependencySet.candidateScannerSetDigest,
      baselineScannerSetDigest: dependencySet.baselineScannerSetDigest,
      hardwareClassRef: cell.hardwareClassRef,
      hardwareClassDigest: cell.hardwareClassDigest,
      attempts: [attempt],
      attemptSetDigest: digest(
        stableJson([
          { attemptId: attempt.attemptId, attemptDigest: attempt.attemptDigest }
        ])
      ),
      phaseObservations: SAST_END_TO_END_QUALIFICATION_PIPELINE_PHASES.map(
        (phase) => ({
          phase,
          status: 'PASSED',
          evidenceDigest: digest(`${cell.cellId}:${phase}`)
        })
      ),
      observedControlOutcome: cell.expectedOutcome,
      observedFindingCount: expectedFindings,
      matchedExpectedFindingCount: expectedFindings,
      observedCriticalHighFindingCount: criticalHigh,
      matchedCriticalHighFindingCount: criticalHigh,
      normalizedOutputDigest: digest(`${cell.cellId}:normalized`),
      fingerprintDigest: digest(`${cell.cellId}:fingerprint`),
      correlationDigest: digest(`${cell.cellId}:correlation`),
      coverageDecisionDigest: digest(`${cell.cellId}:coverage`),
      policyDecisionDigest: digest(`${cell.cellId}:policy`),
      evidenceDecisionDigest: digest(`${cell.cellId}:evidence`),
      externalPublicationAttempted: false,
      customerContentObserved: false,
      customerCodeExecuted: false,
      packageInstallObserved: false,
      repositoryBuildObserved: false,
      dynamicTestObserved: false,
      publicInternetEgressObserved: false,
      completedAt: clock.cleanupCompletedAt
    },
    digest
  );
  assert.ok(receipt);
  return receipt;
}

function createSignature(role, payloadDigest, signedAt, trust) {
  const key = trust.privateKeys.get(role);
  assert.ok(key);
  const signature = {
    version: SAST_END_TO_END_QUALIFICATION_SIGNATURE_VERSION,
    role,
    keyId: key.keyId,
    payloadDigest,
    signedAt,
    algorithm: 'ED25519',
    valueBase64: Buffer.alloc(64).toString('base64')
  };
  const payload = serializeSastEndToEndQualificationSignaturePayload(signature);
  assert.ok(payload);
  signature.valueBase64 = signBytes(
    null,
    Buffer.from(payload, 'utf8'),
    key.privateKey
  ).toString('base64');
  return signature;
}

async function writeJson(root, name, value) {
  const path = join(root, name);
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  return path;
}

function runNode(script, args) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, [script, ...args], {
      cwd: repositoryRoot,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    let settled = false;
    const timeout = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      rejectPromise(new Error(`T054 tool timed out: ${script}`));
    }, 180_000);
    timeout.unref();
    child.once('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      rejectPromise(error);
    });
    child.once('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolvePromise({ code, stdout, stderr });
    });
  });
}

function digestRef(prefix, value) {
  return `${prefix}/${digest(value)}`;
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function digestBytes(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function stableJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`)
    .join(',')}}`;
}
