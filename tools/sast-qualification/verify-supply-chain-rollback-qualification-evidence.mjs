import { createHash } from 'node:crypto';

import {
  evaluateSastSupplyChainRollbackQualificationEvidence,
  isSastSupplyChainRollbackQualificationPlanValid
} from '../../packages/shared/dist/index.js';
import {
  parseExactArguments,
  readQualificationJson
} from './qualification-json-input.mjs';
import { loadAndValidateSupplyChainRollbackQualificationPackage } from './supply-chain-rollback-qualification-loader.mjs';
import { validateSupplyChainRollbackQualificationPrerequisite } from './supply-chain-rollback-qualification-prerequisite.mjs';

const args = parseExactArguments(process.argv.slice(2), {
  '--t054-result': false,
  '--t054-dependency-set': false,
  '--t054-artifact-verification-set': false,
  '--t054-plan': false,
  '--entry-attestation': false,
  '--plan': false,
  '--approvals': false,
  '--receipts': false,
  '--trust-bundle': false
});
const externalNames = [
  '--t054-result',
  '--t054-dependency-set',
  '--t054-artifact-verification-set',
  '--t054-plan',
  '--entry-attestation',
  '--plan',
  '--approvals',
  '--receipts',
  '--trust-bundle'
];
const externalCount = externalNames.filter((name) => args[name]).length;
if (externalCount !== 0 && externalCount !== externalNames.length) {
  throw new Error('T055 evidence verification requires either zero or all external inputs');
}

const qualificationPackage =
  await loadAndValidateSupplyChainRollbackQualificationPackage();
if (externalCount === 0) {
  process.stdout.write(
    `${JSON.stringify(qualificationPackage.qualificationResult, null, 2)}\n`
  );
  process.exitCode = 2;
} else {
  const [
    t054ResultInput,
    dependencyInput,
    artifactVerificationInput,
    t054PlanInput,
    entryInput,
    planInput,
    approvalInput,
    receiptInput,
    trustInput
  ] = await Promise.all([
    readQualificationJson(args['--t054-result'], 8 * 1024 * 1024, 'T054 result'),
    readQualificationJson(
      args['--t054-dependency-set'],
      4 * 1024 * 1024,
      'T054 dependency set'
    ),
    readQualificationJson(
      args['--t054-artifact-verification-set'],
      8 * 1024 * 1024,
      'T054 artifact verification set'
    ),
    readQualificationJson(args['--t054-plan'], 4 * 1024 * 1024, 'T054 plan'),
    readQualificationJson(
      args['--entry-attestation'],
      2 * 1024 * 1024,
      'T055 entry attestation'
    ),
    readQualificationJson(args['--plan'], 4 * 1024 * 1024, 'T055 plan'),
    readQualificationJson(args['--approvals'], 2 * 1024 * 1024, 'T055 approvals'),
    readQualificationJson(args['--receipts'], 32 * 1024 * 1024, 'T055 receipts'),
    readQualificationJson(args['--trust-bundle'], 2 * 1024 * 1024, 'T055 trust bundle')
  ]);
  const verifySignature =
    validateSupplyChainRollbackQualificationPrerequisite(
      {
        qualificationPackage,
        t054Result: t054ResultInput.value,
        dependencySet: dependencyInput.value,
        artifactVerificationSet: artifactVerificationInput.value,
        t054Plan: t054PlanInput.value,
        entryAttestation: entryInput.value,
        trustBundle: trustInput,
        entryAttestationFailureMessage:
          'T055 entry attestation failed signature or binding validation'
      },
      digest
    );
  if (
    !isSastSupplyChainRollbackQualificationPlanValid(
      planInput.value,
      qualificationPackage.manifest,
      qualificationPackage.t054Manifest,
      t054ResultInput.value,
      dependencyInput.value,
      artifactVerificationInput.value,
      t054PlanInput.value,
      entryInput.value,
      verifySignature,
      digest
    )
  ) {
    throw new Error('T055 execution plan failed exact binding validation');
  }
  if (!Array.isArray(approvalInput.value) || !Array.isArray(receiptInput.value)) {
    throw new Error('T055 approvals and receipt bundle must be arrays');
  }
  const result = evaluateSastSupplyChainRollbackQualificationEvidence(
    {
      manifest: qualificationPackage.manifest,
      t054Manifest: qualificationPackage.t054Manifest,
      t054Result: t054ResultInput.value,
      t054DependencySet: dependencyInput.value,
      t054ArtifactVerificationSet: artifactVerificationInput.value,
      t054Plan: t054PlanInput.value,
      entryAttestation: entryInput.value,
      plan: planInput.value,
      approvals: approvalInput.value,
      signedReceipts: receiptInput.value,
      trustedEvaluatedAt: new Date().toISOString(),
      verifySignature
    },
    digest
  );
  if (!result) throw new Error('T055 aggregate evidence failed structural validation');
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode =
    result.status === 'PASSED'
      ? 0
      : result.status === 'PENDING_DRILL_EXECUTION' ||
          result.status === 'BLOCKED_T054_QUALIFICATION'
        ? 2
        : 1;
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
