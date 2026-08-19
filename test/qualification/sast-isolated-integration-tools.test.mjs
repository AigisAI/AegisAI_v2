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
  SAST_ISOLATED_QUALIFICATION_APPROVAL_ROLES,
  SAST_ISOLATED_QUALIFICATION_ARTIFACT_KINDS,
  SAST_ISOLATED_QUALIFICATION_CLEANUP_CONTROLS,
  SAST_ISOLATED_QUALIFICATION_PHASES,
  SAST_ISOLATED_QUALIFICATION_RECEIPT_SIGNATURE_ROLES,
  SAST_ISOLATED_QUALIFICATION_SIGNATURE_VERSION,
  buildSastIsolatedQualificationDependencySet,
  buildSastIsolatedQualificationReceipt,
  serializeSastIsolatedQualificationSignaturePayload
} from '../../packages/shared/dist/index.js';
import { loadAndValidateIsolatedIntegrationPackage } from '../../tools/sast-qualification/isolated-integration-loader.mjs';

const repositoryRoot = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const planTool = join(
  repositoryRoot,
  'tools',
  'sast-qualification',
  'generate-isolated-integration-plan.mjs'
);
const verifierTool = join(
  repositoryRoot,
  'tools',
  'sast-qualification',
  'verify-isolated-integration-evidence.mjs'
);

test('T053 verifier returns PENDING with a distinct exit code when provider evidence is absent', async () => {
  const startedAt = Date.now();
  const run = await runNode(verifierTool, []);
  const completedAt = Date.now();
  assert.equal(run.code, 2, run.stderr);
  const result = JSON.parse(run.stdout);
  assert.equal(result.status, 'PENDING_PROVIDER_EXECUTION');
  assert.equal(result.receivedReceiptCount, 0);
  assert.equal(result.t054EntryAuthorized, false);
  assert.equal(result.productionReadinessAuthority, false);
  assert.ok(Date.parse(result.evaluatedAt) >= startedAt - 1_000);
  assert.ok(Date.parse(result.evaluatedAt) <= completedAt + 1_000);

  const spoofedClock = await runNode(verifierTool, [
    '--evaluated-at',
    '2026-08-20T00:10:00.000Z'
  ]);
  assert.equal(spoofedClock.code, 1);
  assert.match(spoofedClock.stderr, /invalid or duplicate qualification tool argument/u);
});

test('T053 tools verify real Ed25519 approvals and 123 receipts, then reject signature tampering', async (t) => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'aegis-t053-tools-'));
  t.after(() => rm(temporaryRoot, { recursive: true, force: true }));
  const qualificationPackage = await loadAndValidateIsolatedIntegrationPackage();
  const clock = buildTestClock();
  const trust = buildTrustBundle(clock);
  const dependencySet = buildDependencySet(trust.text, clock);
  const dependencyPath = await writeJson(
    temporaryRoot,
    'dependency-set.json',
    dependencySet
  );
  const planRun = await runNode(planTool, ['--dependency-set', dependencyPath]);
  assert.equal(planRun.code, 0, planRun.stderr);
  const plan = JSON.parse(planRun.stdout);
  assert.equal(plan.executionCellCount, 123);
  const planPath = await writeJson(temporaryRoot, 'plan.json', plan);
  const approvals = SAST_ISOLATED_QUALIFICATION_APPROVAL_ROLES.map((role) =>
    createSignature(role, plan.planDigest, clock.approvalSignedAt, trust)
  );
  const receipts = qualificationPackage.manifest.cells.map((cell) => {
    const receipt = buildReceipt(
      cell,
      qualificationPackage.manifest,
      plan,
      dependencySet,
      clock
    );
    return {
      receipt,
      signatures: SAST_ISOLATED_QUALIFICATION_RECEIPT_SIGNATURE_ROLES.map((role) =>
        createSignature(
          role,
          receipt.receiptDigest,
          clock.receiptSignedAt,
          trust
        )
      )
    };
  });
  const approvalPath = await writeJson(temporaryRoot, 'approvals.json', approvals);
  const receiptPath = await writeJson(temporaryRoot, 'receipts.json', receipts);
  const trustPath = join(temporaryRoot, 'trust-bundle.json');
  await writeFile(trustPath, trust.text, 'utf8');

  const args = [
    '--dependency-set',
    dependencyPath,
    '--plan',
    planPath,
    '--approvals',
    approvalPath,
    '--receipts',
    receiptPath,
    '--trust-bundle',
    trustPath
  ];
  const passed = await runNode(verifierTool, args);
  assert.equal(passed.code, 0, passed.stderr);
  const passedResult = JSON.parse(passed.stdout);
  assert.equal(passedResult.status, 'PASSED');
  assert.equal(passedResult.validatedReceiptCount, 123);
  assert.equal(passedResult.t054EntryAuthorized, true);
  assert.equal(passedResult.productionReadinessAuthority, false);

  const retroactiveApprovals = SAST_ISOLATED_QUALIFICATION_APPROVAL_ROLES.map(
    (role) => createSignature(role, plan.planDigest, clock.startedAt, trust)
  );
  await writeJson(temporaryRoot, 'approvals.json', retroactiveApprovals);
  const retroactive = await runNode(verifierTool, args);
  assert.equal(retroactive.code, 1, retroactive.stderr);
  const retroactiveResult = JSON.parse(retroactive.stdout);
  assert.equal(retroactiveResult.status, 'FAILED');
  assert.ok(retroactiveResult.failureReasons.includes('APPROVAL_SET_INVALID'));
  assert.equal(retroactiveResult.t054EntryAuthorized, false);

  await writeJson(temporaryRoot, 'approvals.json', approvals);
  receipts[0].signatures[0].valueBase64 = Buffer.alloc(64).toString('base64');
  await writeJson(temporaryRoot, 'receipts.json', receipts);
  const failed = await runNode(verifierTool, args);
  assert.equal(failed.code, 1, failed.stderr);
  const failedResult = JSON.parse(failed.stdout);
  assert.equal(failedResult.status, 'FAILED');
  assert.ok(failedResult.failureReasons.includes('RECEIPT_SIGNATURE_INVALID'));
  assert.equal(failedResult.t054EntryAuthorized, false);
});

function buildTestClock(baseMilliseconds = Date.now()) {
  const instant = (offsetSeconds) =>
    new Date(baseMilliseconds + offsetSeconds * 1_000).toISOString();
  return Object.freeze({
    validFrom: instant(-3_600),
    approvalSignedAt: instant(-1_800),
    startedAt: instant(-1_200),
    executionCompletedAt: instant(-930),
    cleanupStartedAt: instant(-930),
    cleanupCompletedAt: instant(-900),
    receiptSignedAt: instant(-840),
    validUntil: instant(43_200)
  });
}

function buildTrustBundle(clock) {
  const roles = [
    ...SAST_ISOLATED_QUALIFICATION_APPROVAL_ROLES,
    ...SAST_ISOLATED_QUALIFICATION_RECEIPT_SIGNATURE_ROLES
  ];
  const privateKeys = new Map();
  const keys = roles.map((role) => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
    const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
    const keyDigest = digestBytes(publicKeyDer);
    const keyId =
      `qualification-key://aegisai/${role.toLowerCase().replaceAll('_', '-')}/${keyDigest}`;
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
    version: 'sast-isolated-integration-trust-bundle-v1',
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

function buildDependencySet(trustText, clock) {
  const trustDigest = digest(trustText);
  const artifacts = SAST_ISOLATED_QUALIFICATION_ARTIFACT_KINDS.map((kind) => {
    const artifactDigest =
      kind === 'TRUST_POLICY' ? trustDigest : digest(`artifact:${kind}`);
    return {
      kind,
      artifactRef:
        `qualification-artifact://aegisai/${kind.toLowerCase()}/${artifactDigest}`,
      artifactDigest,
      signatureRef: digestRef(
        `signature://aegisai/${kind.toLowerCase()}`,
        `signature:${kind}`
      ),
      provenanceRef: digestRef(
        `provenance://aegisai/${kind.toLowerCase()}`,
        `provenance:${kind}`
      )
    };
  });
  const dependencySet = buildSastIsolatedQualificationDependencySet(
    {
      revision: '1.0.0',
      providerId: 'microvm-provider://qualification/eu-west-1',
      providerAdapterRef: digestRef(
        'provider-adapter://aegisai/qualification-v1',
        'provider-adapter'
      ),
      validFrom: clock.validFrom,
      validUntil: clock.validUntil,
      artifacts
    },
    digest
  );
  assert.ok(dependencySet);
  return dependencySet;
}

function buildReceipt(cell, manifest, plan, dependencySet, clock) {
  const providerAttestationDigest = digest(`provider-attestation:${cell.cellId}`);
  const runtimeAttestationDigest = digest(`runtime-attestation:${cell.cellId}`);
  const receipt = buildSastIsolatedQualificationReceipt(
    {
      planId: plan.planId,
      planDigest: plan.planDigest,
      manifestDigest: manifest.manifestDigest,
      dependencySetDigest: dependencySet.dependencySetDigest,
      providerId: dependencySet.providerId,
      cellId: cell.cellId,
      cellDigest: cell.cellDigest,
      caseId: cell.caseId,
      caseDigest: cell.caseDigest,
      fixtureId: cell.fixtureId,
      fixtureDigest: cell.fixtureDigest,
      profileId: cell.profileId,
      profileDigest: cell.profileDigest,
      attemptId: digestRef('qualification-attempt://aegisai/t053', cell.cellId),
      sandboxId: digestRef('qualification-sandbox://aegisai/t053', cell.cellId),
      workloadId: digestRef('qualification-workload://aegisai/t053', cell.cellId),
      providerAttestationRef:
        `provider-attestation://aegisai/t053/${providerAttestationDigest}`,
      providerAttestationDigest,
      runtimeAttestationRef:
        `runtime-attestation://aegisai/t053/${runtimeAttestationDigest}`,
      runtimeAttestationDigest,
      materializationInputDigest: cell.materializationInputDigest,
      recipeActionDigest: cell.recipeActionDigest,
      materializationProjectionDigest:
        cell.expectedMaterialization.projectionDigest,
      materializationOutputDigest: digest(`materialization-output:${cell.cellId}`),
      materialized: materializationCore(cell.expectedMaterialization),
      executionTarget: cell.executionTarget,
      isolationClass: cell.isolationClass,
      expectedOutcome: cell.expectedOutcome,
      actualOutcome: cell.expectedOutcome,
      startedAt: clock.startedAt,
      executionCompletedAt: clock.executionCompletedAt,
      cleanupStartedAt: clock.cleanupStartedAt,
      cleanupCompletedAt: clock.cleanupCompletedAt,
      cleanupDurationSeconds: 30,
      phaseEgress: SAST_ISOLATED_QUALIFICATION_PHASES.map((phase) => ({
        phase,
        publicInternetConnections: 0,
        bytesSent: 0,
        dnsQueries: 0,
        destinations: []
      })),
      prohibitedEffects: {
        customerCodeExecutions: 0,
        packageInstalls: 0,
        repositoryBuilds: 0,
        dynamicTests: 0,
        publicInternetConnections: 0,
        scmCredentialPersistences: 0,
        hostMutations: 0,
        unauthorizedResultWrites: 0
      },
      cleanupEvidence: SAST_ISOLATED_QUALIFICATION_CLEANUP_CONTROLS.map(
        (control) => {
          const evidenceDigest = digest(`cleanup:${control}:${cell.cellId}`);
          return {
            control,
            status: 'VERIFIED',
            observedAt: clock.cleanupCompletedAt,
            evidenceRef:
              `cleanup-evidence://aegisai/t053/${control.toLowerCase()}/${evidenceDigest}`,
            evidenceDigest
          };
        }
      ),
      freshMicroVmObserved: true,
      sandboxReuseObserved: false,
      platformOwnedFixtureObserved: true,
      repositoryCredentialIssued: false,
      customerContentObserved: false,
      findingAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      productionReadinessAuthority: false,
      immutable: true
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
    version: SAST_ISOLATED_QUALIFICATION_SIGNATURE_VERSION,
    role,
    keyId: key.keyId,
    payloadDigest,
    signedAt,
    algorithm: 'ED25519',
    valueBase64: Buffer.alloc(64).toString('base64')
  };
  const payload = serializeSastIsolatedQualificationSignaturePayload(signature);
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
    child.once('error', rejectPromise);
    child.once('close', (code) => resolvePromise({ code, stdout, stderr }));
  });
}

function materializationCore(value) {
  return {
    bytes: value.bytes,
    entries: value.entries,
    pathDepth: value.pathDepth,
    simulatedDurationSeconds: value.simulatedDurationSeconds,
    jsonDepth: value.jsonDepth,
    maximumStringBytes: value.maximumStringBytes
  };
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
