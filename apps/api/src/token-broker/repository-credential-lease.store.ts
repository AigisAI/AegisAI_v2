import type { SastCredentialLeaseMetadata } from '@aegisai/shared';

export interface ReserveRepositoryCredentialLeaseInput {
  credentialId: string;
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  workloadIdentityRef: string;
  commitSha: string;
  issuedAt: string;
  expiresAt: string;
}

export abstract class RepositoryCredentialLeaseStore {
  abstract reserve(
    input: ReserveRepositoryCredentialLeaseInput
  ): Promise<SastCredentialLeaseMetadata>;

  abstract activate(
    credentialId: string,
    tenantId: string,
    attemptId: string,
    credentialFingerprint: `sha256:${string}`
  ): Promise<SastCredentialLeaseMetadata>;

  abstract markWiped(
    credentialId: string,
    tenantId: string,
    attemptId: string,
    wipedAt: string
  ): Promise<SastCredentialLeaseMetadata>;

  abstract revoke(
    credentialId: string,
    tenantId: string,
    attemptId: string,
    revokedAt: string
  ): Promise<SastCredentialLeaseMetadata>;

  abstract revokeExpired(referenceTime: string): Promise<number>;

  abstract findByAttempt(
    tenantId: string,
    attemptId: string
  ): Promise<SastCredentialLeaseMetadata | null>;
}
