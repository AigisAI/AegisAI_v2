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
  SAST_END_TO_END_QUALIFICATION_PLAN_VERSION,
  SAST_END_TO_END_QUALIFICATION_RECEIPT_SIGNATURE_ROLES,
  SAST_END_TO_END_QUALIFICATION_SIGNATURE_ROLES,
  SAST_END_TO_END_QUALIFICATION_SIGNATURE_VERSION,
  SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_RECEIPT_SIGNATURE_ROLES,
  buildSastSupplyChainRollbackQualificationReceipt,
  isSastEndToEndQualificationArtifactVerificationSetValid,
  isSastEndToEndQualificationDependencySetValid,
  isSastEndToEndQualificationManifestValid,
  isSastEndToEndQualificationResultValid,
  isSastSupplyChainRollbackQualificationEntryAttestationValid,
  isSastSupplyChainRollbackQualificationLedgerHeadAttestationValid,
  serializeSastEndToEndQualificationSignaturePayload
} from '../../packages/shared/dist/index.js';
import {
  createT055QualificationBundle,
  stableJson
} from '../../packages/shared/test/helpers/t055-qualification-fixture.mjs';
import { loadAndValidateSupplyChainRollbackQualificationPackage } from '../../tools/sast-qualification/supply-chain-rollback-qualification-loader.mjs';
import { buildSupplyChainRollbackQualificationTrustVerifier } from '../../tools/sast-qualification/supply-chain-rollback-qualification-trust.mjs';

const repositoryRoot = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const planTool = join(
  repositoryRoot,
  'tools',
  'sast-qualification',
  'generate-supply-chain-rollback-qualification-plan.mjs'
);
const verifierTool = join(
  repositoryRoot,
  'tools',
  'sast-qualification',
  'verify-supply-chain-rollback-qualification-evidence.mjs'
);

test('T055 verifier remains blocked with exit code 2 and rejects clock spoofing', async () => {
  const run = await runNode(verifierTool, []);
  assert.equal(run.code, 2, run.stderr);
  const result = JSON.parse(run.stdout);
  assert.equal(result.status, 'BLOCKED_T054_QUALIFICATION');
  assert.equal(result.observedReceiptCount, 0);
  assert.equal(result.t056EntryAuthorized, false);
  assert.equal(result.deploymentAuthority, false);
  assert.equal(result.productionReadinessAuthority, false);

  const spoofedClock = await runNode(verifierTool, [
    '--evaluated-at',
    '2026-08-20T00:10:00.000Z'
  ]);
  assert.equal(spoofedClock.code, 1);
  assert.match(spoofedClock.stderr, /invalid or duplicate qualification tool argument/u);
});

test('T055 tools pin an independent trust root and verify every Ed25519 authority', async (t) => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'aegis-t055-tools-'));
  t.after(() => rm(temporaryRoot, { recursive: true, force: true }));
  const qualificationPackage =
    await loadAndValidateSupplyChainRollbackQualificationPackage();
  const trust = buildTrustBundle();
  const signatureFactory = (role, payloadDigest, signedAt) =>
    createSignature(role, payloadDigest, signedAt, trust);
  const bundle = createT055QualificationBundle({
    manifest: qualificationPackage.manifest,
    signatureFactory,
    trustPolicyText: trust.text
  });
  const verifySignature = buildSupplyChainRollbackQualificationTrustVerifier({
    value: trust.value,
    text: trust.text,
    dependencySet: bundle.dependencySet,
    trustedTrustPolicyDigest: digest(trust.text)
  });
  assert.equal(
    isSastEndToEndQualificationArtifactVerificationSetValid(
      bundle.artifactVerificationSet,
      bundle.dependencySet,
      verifySignature,
      digest
    ),
    true,
    'fixture artifact verification must use the real trust bundle'
  );
  assert.equal(
    verifySignature(
      bundle.entryAttestation.signature,
      serializeSastEndToEndQualificationSignaturePayload(
        bundle.entryAttestation.signature
      )
    ),
    true,
    'fixture entry signature must verify against the real trust bundle'
  );
  const { planId: ignoredPlanId, planDigest: ignoredPlanDigest, ...t054PlanCore } =
    bundle.t054Plan;
  assert.ok(ignoredPlanId);
  assert.ok(ignoredPlanDigest);
  assert.deepEqual(
    {
      manifest: isSastEndToEndQualificationManifestValid(
        qualificationPackage.t054Manifest,
        digest
      ),
      result: isSastEndToEndQualificationResultValid(bundle.result, digest),
      dependency: isSastEndToEndQualificationDependencySetValid(
        bundle.dependencySet,
        digest
      ),
      resultPassed: bundle.result.status === 'PASSED',
      resultAuthorized: bundle.result.t055EntryAuthorized === true,
      resultManifest:
        bundle.result.manifestId === qualificationPackage.t054Manifest.manifestId &&
        bundle.result.manifestDigest ===
          qualificationPackage.t054Manifest.manifestDigest,
      resultDependency:
        bundle.result.dependencySetId === bundle.dependencySet.dependencySetId &&
        bundle.result.dependencySetDigest ===
          bundle.dependencySet.dependencySetDigest,
      planVersion:
        bundle.t054Plan.version === SAST_END_TO_END_QUALIFICATION_PLAN_VERSION,
      planDigest:
        digest(stableJson(t054PlanCore)) === bundle.t054Plan.planDigest,
      planResult:
        bundle.t054Plan.planId === bundle.result.planId &&
        bundle.t054Plan.planDigest === bundle.result.planDigest,
      planProvider:
        bundle.t054Plan.t053ProviderId === bundle.dependencySet.providerId &&
        bundle.t054Plan.t053ProviderAdapterRef ===
          bundle.dependencySet.providerAdapterRef,
      planApprovals:
        JSON.stringify(bundle.t054Plan.requiredApprovalRoles) ===
        JSON.stringify(SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES),
      planReceiptRoles:
        JSON.stringify(bundle.t054Plan.requiredReceiptSignatureRoles) ===
        JSON.stringify(SAST_END_TO_END_QUALIFICATION_RECEIPT_SIGNATURE_ROLES)
    },
    {
      manifest: true,
      result: true,
      dependency: true,
      resultPassed: true,
      resultAuthorized: true,
      resultManifest: true,
      resultDependency: true,
      planVersion: true,
      planDigest: true,
      planResult: true,
      planProvider: true,
      planApprovals: true,
      planReceiptRoles: true
    },
    'fixture T054 prerequisite must remain fully rebound'
  );
  assert.equal(
    isSastSupplyChainRollbackQualificationEntryAttestationValid(
      bundle.entryAttestation,
      qualificationPackage.manifest,
      qualificationPackage.t054Manifest,
      bundle.result,
      bundle.dependencySet,
      bundle.artifactVerificationSet,
      bundle.t054Plan,
      verifySignature,
      digest
    ),
    true,
    'fixture entry attestation must bind the real T054 prerequisite'
  );
  assert.equal(bundle.rollbackLedgerHeadAttestations.length, 3);
  assert.ok(
    bundle.rollbackLedgerHeadAttestations.every((attestation) =>
      isSastSupplyChainRollbackQualificationLedgerHeadAttestationValid(
        attestation,
        qualificationPackage.manifest,
        bundle.dependencySet,
        bundle.plan.plannedAt,
        verifySignature,
        digest
      )
    ),
    'fixture rollback ledger heads must be independently signed and authenticated'
  );

  const t054ResultPath = await writeJson(
    temporaryRoot,
    't054-result.json',
    bundle.result
  );
  const dependencyPath = await writeJson(
    temporaryRoot,
    't054-dependency-set.json',
    bundle.dependencySet
  );
  const artifactVerificationPath = await writeJson(
    temporaryRoot,
    't054-artifact-verification-set.json',
    bundle.artifactVerificationSet
  );
  const t054PlanPath = await writeJson(
    temporaryRoot,
    't054-plan.json',
    bundle.t054Plan
  );
  const entryPath = await writeJson(
    temporaryRoot,
    't055-entry-attestation.json',
    bundle.entryAttestation
  );
  const ledgerHeadPath = await writeJson(
    temporaryRoot,
    't055-rollback-ledger-head-attestations.json',
    bundle.rollbackLedgerHeadAttestations
  );
  const trustPath = join(temporaryRoot, 'trust-bundle.json');
  await writeFile(trustPath, trust.text, 'utf8');

  const planArgs = [
    '--t054-result',
    t054ResultPath,
    '--t054-dependency-set',
    dependencyPath,
    '--t054-artifact-verification-set',
    artifactVerificationPath,
    '--t054-plan',
    t054PlanPath,
    '--entry-attestation',
    entryPath,
    '--rollback-ledger-head-attestations',
    ledgerHeadPath,
    '--trust-bundle',
    trustPath
  ];
  const missingRoot = await runNode(planTool, planArgs, {
    SAST_T055_TRUST_POLICY_DIGEST: ''
  });
  assert.equal(missingRoot.code, 1);
  assert.match(missingRoot.stderr, /must independently pin/u);
  const untrustedRoot = await runNode(planTool, planArgs, {
    SAST_T055_TRUST_POLICY_DIGEST: digest('attacker-root')
  });
  assert.equal(untrustedRoot.code, 1);
  assert.match(untrustedRoot.stderr, /independently configured trust-policy digest/u);

  const trustedEnvironment = {
    SAST_T055_TRUST_POLICY_DIGEST: digest(trust.text)
  };
  const tamperedLedgerHeads = structuredClone(
    bundle.rollbackLedgerHeadAttestations
  );
  tamperedLedgerHeads[0].signatures[0].valueBase64 =
    Buffer.alloc(64).toString('base64');
  const tamperedLedgerHeadPath = await writeJson(
    temporaryRoot,
    't055-tampered-rollback-ledger-head-attestations.json',
    tamperedLedgerHeads
  );
  const tamperedLedgerHeadArgs = [...planArgs];
  tamperedLedgerHeadArgs[
    tamperedLedgerHeadArgs.indexOf('--rollback-ledger-head-attestations') + 1
  ] = tamperedLedgerHeadPath;
  const tamperedLedgerHeadRun = await runNode(
    planTool,
    tamperedLedgerHeadArgs,
    trustedEnvironment
  );
  assert.equal(tamperedLedgerHeadRun.code, 1);
  assert.match(
    tamperedLedgerHeadRun.stderr,
    /failed to create T055 drill execution plan/u
  );

  const planRun = await runNode(planTool, planArgs, trustedEnvironment);
  assert.equal(planRun.code, 0, planRun.stderr);
  const plan = JSON.parse(planRun.stdout);
  assert.equal(plan.executionCellCount, 169);
  assert.equal(plan.rollbackLedgerHeadAttestations.length, 3);
  assert.equal(plan.aggregateMetricsAcceptedFromCaller, false);
  assert.equal(plan.productionReadinessAuthority, false);

  const evidence = buildPartialEvidence(
    qualificationPackage.manifest,
    plan,
    bundle.dependencySet,
    bundle.artifactVerificationSet,
    trust
  );
  const planPath = await writeJson(temporaryRoot, 't055-plan.json', plan);
  const approvalsPath = await writeJson(
    temporaryRoot,
    'approvals.json',
    evidence.approvals
  );
  const receiptsPath = await writeJson(
    temporaryRoot,
    'receipts.json',
    evidence.receipts
  );
  const verifierArgs = [
    '--t054-result',
    t054ResultPath,
    '--t054-dependency-set',
    dependencyPath,
    '--t054-artifact-verification-set',
    artifactVerificationPath,
    '--t054-plan',
    t054PlanPath,
    '--entry-attestation',
    entryPath,
    '--plan',
    planPath,
    '--approvals',
    approvalsPath,
    '--receipts',
    receiptsPath,
    '--trust-bundle',
    trustPath
  ];
  const pending = await runNode(verifierTool, verifierArgs, trustedEnvironment);
  assert.equal(pending.code, 2, pending.stderr);
  const pendingResult = JSON.parse(pending.stdout);
  assert.equal(pendingResult.status, 'PENDING_DRILL_EXECUTION');
  assert.equal(pendingResult.validReceiptCount, 1);
  assert.deepEqual(pendingResult.failureReasons, []);
  assert.equal(pendingResult.t056EntryAuthorized, false);

  evidence.receipts[0].signatures[0].valueBase64 =
    Buffer.alloc(64).toString('base64');
  await writeJson(temporaryRoot, 'receipts.json', evidence.receipts);
  const tampered = await runNode(verifierTool, verifierArgs, trustedEnvironment);
  assert.equal(tampered.code, 1, tampered.stderr);
  const tamperedResult = JSON.parse(tampered.stdout);
  assert.equal(tamperedResult.status, 'FAILED');
  assert.ok(tamperedResult.failureReasons.includes('RECEIPT_SIGNATURE_INVALID'));
  assert.equal(tamperedResult.t056EntryAuthorized, false);
});

function buildTrustBundle() {
  const privateKeys = new Map();
  const keys = SAST_END_TO_END_QUALIFICATION_SIGNATURE_ROLES.map((role) => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
    const keyDigest = digestBytes(
      publicKey.export({ type: 'spki', format: 'der' })
    );
    const keyId =
      `qualification-key://aegisai/t055/${role.toLowerCase().replaceAll('_', '-')}/${keyDigest}`;
    privateKeys.set(role, { keyId, privateKey });
    return {
      keyId,
      role,
      algorithm: 'ED25519',
      publicKeyPem,
      validFrom: '2026-08-19T00:00:00.000Z',
      validUntil: '2026-08-22T00:00:00.000Z'
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

function buildPartialEvidence(
  manifest,
  plan,
  dependencySet,
  artifactVerificationSet,
  trust
) {
  const cell = manifest.cells.find(
    (candidate) => candidate.drillKind === 'ARTIFACT_MOUNT_REHASH_ACCEPT'
  );
  assert.ok(cell?.artifactKey);
  const artifact = dependencySet.artifacts.find(
    (candidate) => candidate.artifactKey === cell.artifactKey
  );
  const verification = artifactVerificationSet.verifications.find(
    (candidate) => candidate.artifactKey === cell.artifactKey
  );
  assert.ok(artifact);
  assert.ok(verification);
  const planTime = Date.parse(plan.plannedAt);
  const approvalSignedAt = new Date(planTime).toISOString();
  const startedAt = new Date(planTime + 1).toISOString();
  const completedAt = startedAt;
  const cleanupCompletedAt = startedAt;
  const identity = cell.cellId;
  const receipt = buildSastSupplyChainRollbackQualificationReceipt(
    {
      manifestId: manifest.manifestId,
      manifestDigest: manifest.manifestDigest,
      planId: plan.planId,
      planDigest: plan.planDigest,
      dependencySetId: dependencySet.dependencySetId,
      dependencySetDigest: dependencySet.dependencySetDigest,
      cellId: cell.cellId,
      cellDigest: cell.cellDigest,
      drillKind: cell.drillKind,
      artifactKey: cell.artifactKey,
      profileId: cell.profileId,
      providerId: dependencySet.providerId,
      providerAdapterRef: dependencySet.providerAdapterRef,
      attemptId: digestRef('qualification-attempt://aegisai/t055', identity),
      sandboxId: digestRef('qualification-sandbox://aegisai/t055', identity),
      workloadId: digestRef('qualification-workload://aegisai/t055', identity),
      startedAt,
      completedAt,
      cleanupCompletedAt,
      observedDecision: 'ACCEPTED',
      observedArtifactDigest: artifact.artifactDigest,
      mountRehashDigest: artifact.artifactDigest,
      observedSignatureEnvelopeDigest: verification.signatureEnvelopeDigest,
      observedProvenanceEnvelopeDigest: verification.provenanceEnvelopeDigest,
      artifactMountedReadOnly: true,
      signatureVerified: true,
      provenanceVerified: true,
      allowlisted: true,
      internalMirrorUsed: null,
      databaseFresh: null,
      networkEgressAttempted: false,
      schemaCompatible: null,
      candidateStateBefore: null,
      candidateStateAfter: null,
      baselineStateBefore: null,
      baselineStateAfter: null,
      queueFenceApplied: false,
      rollbackTargetDerived: false,
      baselineReverified: false,
      candidateInvocationsAfterFence: 0,
      candidateReleaseSetDigest: null,
      baselineReleaseSetDigest: null,
      rollbackTargetDigest: null,
      inFlightCandidateWorkloadCountBefore: 0,
      inFlightCandidateWorkloadCountAfter: 0,
      inFlightAbortConfirmed: false,
      rollbackLedgerHeadAttestationId: null,
      rollbackLedgerHeadAttestationDigest: null,
      rollbackLedgerPreviousDigest: null,
      rollbackLedgerEntrySequence: null,
      rollbackLedgerEntryDigest: null,
      rollbackLedgerAppendVerified: false,
      preExecutionRejected: false,
      artifactInvocationCount: 1,
      networkEgressCount: 0,
      productionMutationCount: 0,
      customerContentObserved: false,
      customerCodeExecuted: false,
      packageInstallObserved: false,
      repositoryBuildObserved: false,
      dynamicTestObserved: false,
      cleanupComplete: true,
      providerAttestationRef: digestRef(
        'provider-attestation://aegisai/t055',
        identity
      ),
      runtimeAttestationRef: digestRef(
        'runtime-attestation://aegisai/t055',
        identity
      ),
      telemetryAttestationRef: digestRef(
        'telemetry-attestation://aegisai/t055',
        identity
      ),
      auditRef: digestRef('qualification-audit://aegisai/t055', identity)
    },
    digest
  );
  assert.ok(receipt);
  const approvals = SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES.map((role) =>
    createSignature(role, plan.planDigest, approvalSignedAt, trust)
  );
  const receipts = [
    {
      receipt,
      signatures:
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_RECEIPT_SIGNATURE_ROLES.map(
          (role) =>
            createSignature(role, receipt.receiptDigest, cleanupCompletedAt, trust)
        )
    }
  ];
  return { approvals, receipts };
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

function runNode(script, args, environment = {}) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, [script, ...args], {
      cwd: repositoryRoot,
      env: { ...process.env, ...environment },
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
      rejectPromise(new Error(`T055 tool timed out: ${script}`));
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
