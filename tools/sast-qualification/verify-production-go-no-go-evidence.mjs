import { createHash } from 'node:crypto';

import {
  evaluateSastProductionGoNoGoEvidence
} from '../../packages/shared/dist/index.js';
import {
  parseExactArguments,
  readQualificationJson
} from './qualification-json-input.mjs';
import { loadAndValidateProductionGoNoGoPackage } from './production-go-no-go-loader.mjs';
import { validateProductionGoNoGoPrerequisite } from './production-go-no-go-prerequisite.mjs';

const args = parseExactArguments(process.argv.slice(2), {
  '--upstream-bundle': false,
  '--entry-attestation': false,
  '--evidence-attestations': false,
  '--plan': false,
  '--approvals': false,
  '--trust-bundle': false
});
const externalNames = [
  '--upstream-bundle',
  '--entry-attestation',
  '--evidence-attestations',
  '--plan',
  '--approvals',
  '--trust-bundle'
];
const externalCount = externalNames.filter((name) => args[name]).length;
if (externalCount !== 0 && externalCount !== externalNames.length) {
  throw new Error('T056 evidence verification requires either zero or all external inputs');
}

const qualificationPackage = await loadAndValidateProductionGoNoGoPackage();
if (externalCount === 0) {
  process.stdout.write(
    `${JSON.stringify(qualificationPackage.qualificationRecord, null, 2)}\n`
  );
  process.exitCode = 2;
} else {
  const [upstreamInput, entryInput, evidenceInput, planInput, approvalInput, trustInput] =
    await Promise.all([
      readQualificationJson(args['--upstream-bundle'], 24 * 1024 * 1024, 'T056 upstream bundle'),
      readQualificationJson(args['--entry-attestation'], 2 * 1024 * 1024, 'T056 entry attestation'),
      readQualificationJson(args['--evidence-attestations'], 8 * 1024 * 1024, 'T056 evidence attestations'),
      readQualificationJson(args['--plan'], 4 * 1024 * 1024, 'T056 decision plan'),
      readQualificationJson(args['--approvals'], 2 * 1024 * 1024, 'T056 final approvals'),
      readQualificationJson(args['--trust-bundle'], 2 * 1024 * 1024, 'T056 trust bundle')
    ]);
  const verifySignature = validateProductionGoNoGoPrerequisite(
    {
      qualificationPackage,
      upstreamBundle: upstreamInput.value,
      entryAttestation: entryInput.value,
      trustBundle: trustInput
    },
    digest
  );
  if (!Array.isArray(evidenceInput.value) || !Array.isArray(approvalInput.value)) {
    throw new Error('T056 evidence attestations and approvals must be arrays');
  }
  const record = evaluateSastProductionGoNoGoEvidence(
    {
      manifest: qualificationPackage.manifest,
      t054Manifest: qualificationPackage.t054Manifest,
      t055Manifest: qualificationPackage.t055Manifest,
      upstream: upstreamInput.value,
      entryAttestation: entryInput.value,
      evidenceAttestations: evidenceInput.value,
      plan: planInput.value,
      approvals: approvalInput.value,
      trustedEvaluatedAt: new Date().toISOString(),
      verifySignature
    },
    digest
  );
  if (!record) throw new Error('T056 evidence failed structural validation');
  process.stdout.write(`${JSON.stringify(record, null, 2)}\n`);
  process.exitCode = record.status === 'GO'
    ? 0
    : record.status === 'BLOCKED_T055_QUALIFICATION' ||
        record.status === 'PENDING_FINAL_EVIDENCE'
      ? 2
      : 1;
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
