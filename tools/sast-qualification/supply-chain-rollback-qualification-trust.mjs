import { buildEndToEndQualificationTrustVerifier } from './end-to-end-qualification-trust.mjs';

export function buildSupplyChainRollbackQualificationTrustVerifier({
  value,
  text,
  dependencySet,
  trustedTrustPolicyDigest
}) {
  try {
    return buildEndToEndQualificationTrustVerifier({
      value,
      text,
      dependencySet,
      trustedTrustPolicyDigest
    });
  } catch (error) {
    throw new Error(`T055 trust verification failed: ${error.message}`, {
      cause: error
    });
  }
}

export function readConfiguredSupplyChainRollbackTrustPolicyDigest(
  environment = process.env
) {
  const value = environment.SAST_T055_TRUST_POLICY_DIGEST;
  if (
    typeof value !== 'string' ||
    !/^sha256:[a-f0-9]{64}$/u.test(value)
  ) {
    throw new Error(
      'SAST_T055_TRUST_POLICY_DIGEST must independently pin the T055 trust bundle'
    );
  }
  return value;
}
