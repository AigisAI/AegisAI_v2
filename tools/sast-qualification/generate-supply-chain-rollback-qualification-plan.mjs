import { createHash } from 'node:crypto';

import {
  buildSastSupplyChainRollbackQualificationPlan,
  isSastEndToEndQualificationArtifactVerificationSetValid,
  isSastEndToEndQualificationDependencySetValid,
  isSastEndToEndQualificationResultValid,
  isSastSupplyChainRollbackQualificationEntryAttestationValid
} from '../../packages/shared/dist/index.js';
import {
  parseExactArguments,
  readQualificationJson
} from './qualification-json-input.mjs';
import { loadAndValidateSupplyChainRollbackQualificationPackage } from './supply-chain-rollback-qualification-loader.mjs';
import {
  buildSupplyChainRollbackQualificationTrustVerifier,
  readConfiguredSupplyChainRollbackTrustPolicyDigest
} from './supply-chain-rollback-qualification-trust.mjs';

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
if (
  !isSastEndToEndQualificationResultValid(t054ResultInput.value, digest) ||
  t054ResultInput.value.status !== 'PASSED' ||
  t054ResultInput.value.t055EntryAuthorized !== true
) {
  throw new Error('T054 result failed T055 entry validation');
}
if (!isSastEndToEndQualificationDependencySetValid(dependencyInput.value, digest)) {
  throw new Error('T054 dependency set failed exact contract validation');
}
const verifySignature = buildSupplyChainRollbackQualificationTrustVerifier({
  value: trustInput.value,
  text: trustInput.text,
  dependencySet: dependencyInput.value,
  trustedTrustPolicyDigest:
    readConfiguredSupplyChainRollbackTrustPolicyDigest()
});
if (
  !isSastEndToEndQualificationArtifactVerificationSetValid(
    artifactVerificationInput.value,
    dependencyInput.value,
    verifySignature,
    digest
  )
) {
  throw new Error('T054 artifact signature/provenance verification set is invalid');
}
if (
  !isSastSupplyChainRollbackQualificationEntryAttestationValid(
    entryInput.value,
    qualificationPackage.manifest,
    qualificationPackage.t054Manifest,
    t054ResultInput.value,
    dependencyInput.value,
    artifactVerificationInput.value,
    t054PlanInput.value,
    verifySignature,
    digest
  )
) {
  throw new Error('T055 entry attestation failed signature or T054 binding validation');
}
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
