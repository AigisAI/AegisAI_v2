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
  SAST_END_TO_END_QUALIFICATION_SIGNATURE_ROLES,
  SAST_END_TO_END_QUALIFICATION_SIGNATURE_VERSION,
  serializeSastEndToEndQualificationSignaturePayload
} from '../../packages/shared/dist/index.js';
import {
  createT056GoNoGoBundle
} from '../../packages/shared/test/helpers/t056-go-no-go-fixture.mjs';
import {
  buildProductionGoNoGoTrustVerifier,
  readConfiguredProductionGoNoGoTrustPolicyDigest
} from '../../tools/sast-qualification/production-go-no-go-trust.mjs';

const repositoryRoot = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const planTool = join(
  repositoryRoot,
  'tools',
  'sast-qualification',
  'generate-production-go-no-go-plan.mjs'
);
const verifierTool = join(
  repositoryRoot,
  'tools',
  'sast-qualification',
  'verify-production-go-no-go-evidence.mjs'
);

test('T056 verifier remains blocked with exit code 2 and rejects clock spoofing', async () => {
  const run = await runNode(verifierTool, []);
  assert.equal(run.code, 2, run.stderr);
  const result = JSON.parse(run.stdout);
  assert.equal(result.status, 'BLOCKED_T055_QUALIFICATION');
  assert.equal(result.evaluatedGateCount, 0);
  assert.equal(result.deploymentOperationsEntryAuthorized, false);
  assert.equal(result.deploymentAuthority, false);
  assert.equal(result.kubernetesExecutionAuthority, false);
  assert.equal(result.productionReadinessAuthority, false);

  const spoofedClock = await runNode(verifierTool, [
    '--evaluated-at',
    '2026-08-20T20:30:00.000Z'
  ]);
  assert.equal(spoofedClock.code, 1);
  assert.match(
    spoofedClock.stderr,
    /invalid or duplicate qualification tool argument/u
  );
});

test('T056 tools pin an independent trust root and fail closed around signed GO', async (t) => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'aegis-t056-tools-'));
  t.after(() => rm(temporaryRoot, { recursive: true, force: true }));
  const trust = buildTrustBundle();
  const signatureFactory = (role, payloadDigest, signedAt) =>
    createSignature(role, payloadDigest, signedAt, trust);
  const now = Date.now();
  const bundle = createT056GoNoGoBundle({
    signatureFactory,
    trustPolicyText: trust.text,
    entryVerifiedAt: new Date(now - 10 * 60_000).toISOString(),
    evidenceObservedAtBase: new Date(now - 5 * 60_000).toISOString(),
    evidenceValidUntil: new Date(now + 2 * 60 * 60_000).toISOString(),
    decidedAt: new Date(now - 1_000).toISOString(),
    approvalSignedAt: new Date(now - 2_000).toISOString()
  });

  assert.throws(
    () => readConfiguredProductionGoNoGoTrustPolicyDigest({}),
    /must independently pin/u
  );
  assert.throws(
    () =>
      buildProductionGoNoGoTrustVerifier({
        value: trust.value,
        text: trust.text,
        trustedTrustPolicyDigest: digest('attacker-root')
      }),
    /does not match the independently pinned policy/u
  );
  const verifySignature = buildProductionGoNoGoTrustVerifier({
    value: trust.value,
    text: trust.text,
    trustedTrustPolicyDigest: digest(trust.text)
  });
  const entryPayload = serializeSastEndToEndQualificationSignaturePayload(
    bundle.entryAttestation.signature
  );
  assert.ok(entryPayload);
  assert.equal(
    verifySignature(bundle.entryAttestation.signature, entryPayload),
    true
  );

  const upstreamPath = await writeJson(
    temporaryRoot,
    'upstream-bundle.json',
    bundle.upstream
  );
  const entryPath = await writeJson(
    temporaryRoot,
    'entry-attestation.json',
    bundle.entryAttestation
  );
  const evidencePath = await writeJson(
    temporaryRoot,
    'evidence-attestations.json',
    bundle.evidenceAttestations
  );
  const trustPath = join(temporaryRoot, 'trust-bundle.json');
  await writeFile(trustPath, trust.text, 'utf8');
  const trustedEnvironment = {
    SAST_T056_TRUST_POLICY_DIGEST: digest(trust.text)
  };
  const planArgs = [
    '--upstream-bundle',
    upstreamPath,
    '--entry-attestation',
    entryPath,
    '--evidence-attestations',
    evidencePath,
    '--trust-bundle',
    trustPath,
    '--decision-actor',
    digestRef('deployment-operator://aegisai/t056', 'tool-test')
  ];

  const planRun = await runNode(planTool, planArgs, trustedEnvironment);
  assert.equal(planRun.code, 0, planRun.stderr);
  const plan = JSON.parse(planRun.stdout);
  assert.equal(plan.evidenceAttestationIds.length, 6);
  assert.equal(plan.requiredApprovalRoles.length, 2);
  assert.equal(plan.deploymentOperationsEntryOnly, true);
  assert.equal(plan.deploymentAuthority, false);
  assert.equal(plan.kubernetesExecutionAuthority, false);
  assert.equal(plan.productionReadinessAuthority, false);

  const approvals = SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES.map((role) =>
    createSignature(role, plan.planDigest, plan.decidedAt, trust)
  );
  const planPath = await writeJson(temporaryRoot, 'plan.json', plan);
  const approvalsPath = await writeJson(
    temporaryRoot,
    'approvals.json',
    approvals
  );
  const verifierArgs = [
    '--upstream-bundle',
    upstreamPath,
    '--entry-attestation',
    entryPath,
    '--evidence-attestations',
    evidencePath,
    '--plan',
    planPath,
    '--approvals',
    approvalsPath,
    '--trust-bundle',
    trustPath
  ];

  const accepted = await runNode(verifierTool, verifierArgs, trustedEnvironment);
  assert.equal(accepted.code, 0, accepted.stderr);
  const acceptedRecord = JSON.parse(accepted.stdout);
  assert.equal(acceptedRecord.status, 'GO');
  assert.equal(acceptedRecord.evaluatedGateCount, 54);
  assert.equal(acceptedRecord.passedGateCount, 54);
  assert.equal(acceptedRecord.deploymentOperationsEntryAuthorized, true);
  assert.equal(acceptedRecord.deploymentAuthority, false);
  assert.equal(acceptedRecord.kubernetesExecutionAuthority, false);
  assert.equal(acceptedRecord.productionMutationAuthority, false);
  assert.equal(acceptedRecord.productionReadinessAuthority, false);

  await writeJson(
    temporaryRoot,
    'evidence-attestations.json',
    bundle.evidenceAttestations.slice(0, -1)
  );
  await writeJson(temporaryRoot, 'plan.json', null);
  await writeJson(temporaryRoot, 'approvals.json', []);
  const pending = await runNode(verifierTool, verifierArgs, trustedEnvironment);
  assert.equal(pending.code, 2, pending.stderr);
  const pendingRecord = JSON.parse(pending.stdout);
  assert.equal(pendingRecord.status, 'PENDING_FINAL_EVIDENCE');
  assert.deepEqual(pendingRecord.failureReasons, ['EVIDENCE_INCOMPLETE']);
  assert.equal(pendingRecord.deploymentOperationsEntryAuthorized, false);

  const tamperedEvidence = structuredClone(bundle.evidenceAttestations);
  tamperedEvidence[0].signatures[0].valueBase64 =
    Buffer.alloc(64).toString('base64');
  await writeJson(
    temporaryRoot,
    'evidence-attestations.json',
    tamperedEvidence
  );
  await writeJson(temporaryRoot, 'plan.json', plan);
  await writeJson(temporaryRoot, 'approvals.json', approvals);
  const rejected = await runNode(verifierTool, verifierArgs, trustedEnvironment);
  assert.equal(rejected.code, 1, rejected.stderr);
  const rejectedRecord = JSON.parse(rejected.stdout);
  assert.equal(rejectedRecord.status, 'NO_GO');
  assert.ok(rejectedRecord.failureReasons.includes('EVIDENCE_INVALID'));
  assert.equal(rejectedRecord.deploymentOperationsEntryAuthorized, false);
});

function buildTrustBundle() {
  const privateKeys = new Map();
  const validFrom = new Date(Date.now() - 24 * 60 * 60_000).toISOString();
  const validUntil = new Date(Date.now() + 24 * 60 * 60_000).toISOString();
  const keys = SAST_END_TO_END_QUALIFICATION_SIGNATURE_ROLES.map((role) => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
    const keyDigest = digestBytes(
      publicKey.export({ type: 'spki', format: 'der' })
    );
    const keyId =
      `qualification-key://aegisai/t056/${role.toLowerCase().replaceAll('_', '-')}/${keyDigest}`;
    privateKeys.set(role, { keyId, privateKey });
    return {
      keyId,
      role,
      algorithm: 'ED25519',
      publicKeyPem,
      validFrom,
      validUntil
    };
  });
  const value = {
    version: 'sast-production-go-no-go-trust-bundle-v1',
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
      rejectPromise(new Error(`T056 tool timed out: ${script}`));
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
