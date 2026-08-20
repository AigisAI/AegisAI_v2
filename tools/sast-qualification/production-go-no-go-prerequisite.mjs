import {
  isSastProductionGoNoGoEntryAttestationValid
} from '../../packages/shared/dist/index.js';
import {
  buildProductionGoNoGoTrustVerifier,
  readConfiguredProductionGoNoGoTrustPolicyDigest
} from './production-go-no-go-trust.mjs';

const UPSTREAM_KEYS = [
  't054Result',
  't054DependencySet',
  't054ArtifactVerificationSet',
  't054Plan',
  't055EntryAttestation',
  't055Plan',
  't055Result'
];

export function validateProductionGoNoGoPrerequisite(
  {
    qualificationPackage,
    upstreamBundle,
    entryAttestation,
    trustBundle,
    entryAttestationFailureMessage =
      'T056 entry attestation failed signature or upstream binding validation'
  },
  digestCanonical,
  environment = process.env
) {
  if (!hasExactKeys(upstreamBundle, UPSTREAM_KEYS)) {
    throw new Error('T056 upstream bundle must have the exact reviewed key set');
  }
  const verifySignature = buildProductionGoNoGoTrustVerifier({
    value: trustBundle.value,
    text: trustBundle.text,
    trustedTrustPolicyDigest:
      readConfiguredProductionGoNoGoTrustPolicyDigest(environment)
  });
  if (
    !isSastProductionGoNoGoEntryAttestationValid(
      entryAttestation,
      {
        manifest: qualificationPackage.manifest,
        t054Manifest: qualificationPackage.t054Manifest,
        t055Manifest: qualificationPackage.t055Manifest,
        upstream: upstreamBundle,
        verifySignature
      },
      verifySignature,
      digestCanonical
    )
  ) {
    throw new Error(entryAttestationFailureMessage);
  }
  return verifySignature;
}

function hasExactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    arraysEqual(Object.keys(value).sort(compareText), [...keys].sort(compareText))
  );
}

function arraysEqual(left, right) {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}
