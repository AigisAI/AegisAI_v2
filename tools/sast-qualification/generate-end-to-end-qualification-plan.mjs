import { createHash } from 'node:crypto';

import {
  buildSastEndToEndQualificationExecutionPlan,
  isSastEndToEndQualificationDependencySetValid,
  isSastEndToEndQualificationEntryAttestationValid,
  isSastIsolatedQualificationResultValid
} from '../../packages/shared/dist/index.js';
import { loadAndValidateEndToEndQualificationPackage } from './end-to-end-qualification-loader.mjs';
import { buildEndToEndQualificationTrustVerifier } from './end-to-end-qualification-trust.mjs';
import {
  parseExactArguments,
  readQualificationJson
} from './qualification-json-input.mjs';

const args = parseExactArguments(process.argv.slice(2), {
  '--t053-result': true,
  '--entry-attestation': true,
  '--dependency-set': true,
  '--trust-bundle': true
});
const [t053Input, entryInput, dependencyInput, trustInput] = await Promise.all([
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
  readQualificationJson(args['--trust-bundle'], 2 * 1024 * 1024, 'T054 trust bundle')
]);
const qualificationPackage = await loadAndValidateEndToEndQualificationPackage();
if (!isSastIsolatedQualificationResultValid(t053Input.value, digest)) {
  throw new Error('T053 result failed exact contract validation');
}
if (t053Input.value.status !== 'PASSED' || t053Input.value.t054EntryAuthorized !== true) {
  throw new Error('T053 result does not authorize T054 entry');
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
  throw new Error('T054 entry attestation failed signature or T053 binding validation');
}
const plan = buildSastEndToEndQualificationExecutionPlan(
  {
    manifest: qualificationPackage.manifest,
    dependencySet: dependencyInput.value,
    t053Result: t053Input.value,
    entryAttestation: entryInput.value,
    plannedAt: new Date().toISOString(),
    verifySignature
  },
  digest
);
if (!plan) throw new Error('failed to create T054 provider execution plan');
process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
