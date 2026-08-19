import {
  isSastEndToEndQualificationArtifactVerificationSetValid,
  isSastEndToEndQualificationDependencySetValid,
  isSastEndToEndQualificationResultValid,
  isSastSupplyChainRollbackQualificationEntryAttestationValid
} from '../../packages/shared/dist/index.js';
import {
  buildSupplyChainRollbackQualificationTrustVerifier,
  readConfiguredSupplyChainRollbackTrustPolicyDigest
} from './supply-chain-rollback-qualification-trust.mjs';

export function validateSupplyChainRollbackQualificationPrerequisite(
  {
    qualificationPackage,
    t054Result,
    dependencySet,
    artifactVerificationSet,
    t054Plan,
    entryAttestation,
    trustBundle,
    entryAttestationFailureMessage
  },
  digestCanonical
) {
  if (
    !isSastEndToEndQualificationResultValid(t054Result, digestCanonical) ||
    t054Result.status !== 'PASSED' ||
    t054Result.t055EntryAuthorized !== true
  ) {
    throw new Error('T054 result failed T055 entry validation');
  }
  if (
    !isSastEndToEndQualificationDependencySetValid(
      dependencySet,
      digestCanonical
    )
  ) {
    throw new Error('T054 dependency set failed exact contract validation');
  }
  const verifySignature = buildSupplyChainRollbackQualificationTrustVerifier({
    value: trustBundle.value,
    text: trustBundle.text,
    dependencySet,
    trustedTrustPolicyDigest:
      readConfiguredSupplyChainRollbackTrustPolicyDigest()
  });
  if (
    !isSastEndToEndQualificationArtifactVerificationSetValid(
      artifactVerificationSet,
      dependencySet,
      verifySignature,
      digestCanonical
    )
  ) {
    throw new Error('T054 artifact signature/provenance verification set is invalid');
  }
  if (
    !isSastSupplyChainRollbackQualificationEntryAttestationValid(
      entryAttestation,
      qualificationPackage.manifest,
      qualificationPackage.t054Manifest,
      t054Result,
      dependencySet,
      artifactVerificationSet,
      t054Plan,
      verifySignature,
      digestCanonical
    )
  ) {
    throw new Error(entryAttestationFailureMessage);
  }
  return verifySignature;
}
