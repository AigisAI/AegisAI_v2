import { createHash } from 'node:crypto';

import {
  buildSastProductionGoNoGoPlan
} from '../../packages/shared/dist/index.js';
import {
  parseExactArguments,
  readQualificationJson
} from './qualification-json-input.mjs';
import { loadAndValidateProductionGoNoGoPackage } from './production-go-no-go-loader.mjs';
import { validateProductionGoNoGoPrerequisite } from './production-go-no-go-prerequisite.mjs';

const args = parseExactArguments(process.argv.slice(2), {
  '--upstream-bundle': true,
  '--entry-attestation': true,
  '--evidence-attestations': true,
  '--trust-bundle': true,
  '--decision-actor': true
});
const [upstreamInput, entryInput, evidenceInput, trustInput] = await Promise.all([
  readQualificationJson(args['--upstream-bundle'], 24 * 1024 * 1024, 'T056 upstream bundle'),
  readQualificationJson(args['--entry-attestation'], 2 * 1024 * 1024, 'T056 entry attestation'),
  readQualificationJson(args['--evidence-attestations'], 8 * 1024 * 1024, 'T056 evidence attestations'),
  readQualificationJson(args['--trust-bundle'], 2 * 1024 * 1024, 'T056 trust bundle')
]);
const qualificationPackage = await loadAndValidateProductionGoNoGoPackage();
const verifySignature = validateProductionGoNoGoPrerequisite(
  {
    qualificationPackage,
    upstreamBundle: upstreamInput.value,
    entryAttestation: entryInput.value,
    trustBundle: trustInput
  },
  digest
);
if (!Array.isArray(evidenceInput.value)) {
  throw new Error('T056 evidence attestations must be an array');
}
const plan = buildSastProductionGoNoGoPlan(
  {
    manifest: qualificationPackage.manifest,
    entryAttestation: entryInput.value,
    evidenceAttestations: evidenceInput.value,
    decisionActorRef: args['--decision-actor'],
    decidedAt: new Date().toISOString(),
    verifySignature
  },
  digest
);
if (!plan) throw new Error('failed to create T056 production go/no-go decision plan');
process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
