import { createHash } from 'node:crypto';

import {
  evaluateSastEndToEndQualificationEvidence,
  isSastEndToEndQualificationDependencySetValid,
  isSastEndToEndQualificationEntryAttestationValid,
  isSastEndToEndQualificationExecutionPlanValid,
  isSastIsolatedQualificationResultValid
} from '../../packages/shared/dist/index.js';
import { loadAndValidateEndToEndQualificationPackage } from './end-to-end-qualification-loader.mjs';
import { buildEndToEndQualificationTrustVerifier } from './end-to-end-qualification-trust.mjs';
import {
  parseExactArguments,
  readQualificationJson
} from './qualification-json-input.mjs';

const args = parseExactArguments(process.argv.slice(2), {
  '--t053-result': false,
  '--entry-attestation': false,
  '--dependency-set': false,
  '--plan': false,
  '--approvals': false,
  '--receipts': false,
  '--trust-bundle': false
});
const externalNames = [
  '--t053-result',
  '--entry-attestation',
  '--dependency-set',
  '--plan',
  '--approvals',
  '--receipts',
  '--trust-bundle'
];
const externalCount = externalNames.filter((name) => args[name]).length;
if (externalCount !== 0 && externalCount !== externalNames.length) {
  throw new Error('T054 evidence verification requires either zero or all external inputs');
}

const qualificationPackage = await loadAndValidateEndToEndQualificationPackage();
if (externalCount === 0) {
  process.stdout.write(
    `${JSON.stringify(qualificationPackage.qualificationResult, null, 2)}\n`
  );
  process.exitCode = 2;
} else {
  const [
    t053Input,
    entryInput,
    dependencyInput,
    planInput,
    approvalInput,
    receiptInput,
    trustInput
  ] = await Promise.all([
    readQualificationJson(args['--t053-result'], 2 * 1024 * 1024, 'T053 result'),
    readQualificationJson(
      args['--entry-attestation'],
      2 * 1024 * 1024,
      'T054 entry attestation'
    ),
    readQualificationJson(
      args['--dependency-set'],
      4 * 1024 * 1024,
      'T054 dependency set'
    ),
    readQualificationJson(args['--plan'], 4 * 1024 * 1024, 'T054 execution plan'),
    readQualificationJson(args['--approvals'], 2 * 1024 * 1024, 'T054 approvals'),
    readQualificationJson(args['--receipts'], 128 * 1024 * 1024, 'T054 receipts'),
    readQualificationJson(
      args['--trust-bundle'],
      2 * 1024 * 1024,
      'T054 trust bundle'
    )
  ]);
  if (
    !isSastIsolatedQualificationResultValid(t053Input.value, digest) ||
    t053Input.value.status !== 'PASSED' ||
    t053Input.value.t054EntryAuthorized !== true
  ) {
    throw new Error('T053 result failed T054 entry validation');
  }
  if (
    !isSastEndToEndQualificationDependencySetValid(dependencyInput.value, digest)
  ) {
    throw new Error('T054 dependency set failed exact contract validation');
  }
  const verifySignature = buildEndToEndQualificationTrustVerifier({
    value: trustInput.value,
    text: trustInput.text,
    dependencySet: dependencyInput.value
  });
  if (
    !isSastEndToEndQualificationEntryAttestationValid(
      entryInput.value,
      t053Input.value,
      qualificationPackage.manifest,
      verifySignature,
      digest
    )
  ) {
    throw new Error('T054 entry attestation failed signature or binding validation');
  }
  if (
    !isSastEndToEndQualificationExecutionPlanValid(
      planInput.value,
      qualificationPackage.manifest,
      dependencyInput.value,
      t053Input.value,
      entryInput.value,
      verifySignature,
      digest
    )
  ) {
    throw new Error('T054 execution plan failed exact binding validation');
  }
  if (!Array.isArray(approvalInput.value) || !Array.isArray(receiptInput.value)) {
    throw new Error('T054 approvals and receipt bundle must be arrays');
  }
  const result = evaluateSastEndToEndQualificationEvidence(
    {
      manifest: qualificationPackage.manifest,
      t053Result: t053Input.value,
      entryAttestation: entryInput.value,
      dependencySet: dependencyInput.value,
      plan: planInput.value,
      approvals: approvalInput.value,
      signedReceipts: receiptInput.value,
      trustedEvaluatedAt: new Date().toISOString(),
      verifySignature
    },
    digest
  );
  if (!result) throw new Error('T054 aggregate evidence failed structural validation');
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode =
    result.status === 'PASSED'
      ? 0
      : result.status === 'PENDING_PROVIDER_EXECUTION' ||
          result.status === 'BLOCKED_T053_QUALIFICATION'
        ? 2
        : 1;
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
