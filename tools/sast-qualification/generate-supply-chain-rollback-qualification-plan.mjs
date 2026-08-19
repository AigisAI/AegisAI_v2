import { createHash } from 'node:crypto';

import {
  buildSastSupplyChainRollbackQualificationPlan
} from '../../packages/shared/dist/index.js';
import {
  parseExactArguments,
  readQualificationJson
} from './qualification-json-input.mjs';
import { loadAndValidateSupplyChainRollbackQualificationPackage } from './supply-chain-rollback-qualification-loader.mjs';
import { validateSupplyChainRollbackQualificationPrerequisite } from './supply-chain-rollback-qualification-prerequisite.mjs';

const args = parseExactArguments(process.argv.slice(2), {
  '--t054-result': true,
  '--t054-dependency-set': true,
  '--t054-artifact-verification-set': true,
  '--t054-plan': true,
  '--entry-attestation': true,
  '--rollback-ledger-head-attestations': true,
  '--trust-bundle': true
});
const [
  t054ResultInput,
  dependencyInput,
  artifactVerificationInput,
  t054PlanInput,
  entryInput,
  ledgerHeadInput,
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
  readQualificationJson(
    args['--rollback-ledger-head-attestations'],
    4 * 1024 * 1024,
    'T055 authenticated rollback ledger heads'
  ),
  readQualificationJson(args['--trust-bundle'], 2 * 1024 * 1024, 'T055 trust bundle')
]);

const qualificationPackage =
  await loadAndValidateSupplyChainRollbackQualificationPackage();
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
        'T055 entry attestation failed signature or T054 binding validation'
    },
    digest
  );
const plan = buildSastSupplyChainRollbackQualificationPlan(
  {
    manifest: qualificationPackage.manifest,
    t054Manifest: qualificationPackage.t054Manifest,
    t054Result: t054ResultInput.value,
    t054DependencySet: dependencyInput.value,
    t054ArtifactVerificationSet: artifactVerificationInput.value,
    t054Plan: t054PlanInput.value,
    entryAttestation: entryInput.value,
    rollbackLedgerHeadAttestations: ledgerHeadInput.value,
    plannedAt: new Date().toISOString(),
    verifySignature
  },
  digest
);
if (!plan) throw new Error('failed to create T055 drill execution plan');
process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
