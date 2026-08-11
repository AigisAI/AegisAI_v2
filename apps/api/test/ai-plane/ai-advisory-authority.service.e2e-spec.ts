import { AiAdvisoryAuthorityService } from '../../src/ai-plane/ai-advisory-authority.service';
import {
  aiAuthorityProof,
  aiPolicyReference
} from '../support/sast-ai-advisory-fixture';

describe('AiAdvisoryAuthorityService T044 boundary', () => {
  it('returns only an immutable proof and display-only policy reference', async () => {
    const proof = aiAuthorityProof();
    const store = {
      createProof: jest.fn().mockResolvedValue({ proof, replayed: false }),
      verifyPolicyReference: jest.fn()
    };
    const service = new AiAdvisoryAuthorityService(store as never);

    const result = await service.createProof(
      {
        tenantId: proof.scope.tenantId,
        advisoryId: proof.scope.advisoryId
      },
      () => proof.verifiedAt
    );

    expect(result).toEqual({
      proof,
      replayed: false,
      policyReference: aiPolicyReference()
    });
    expect(result.proof.before.stateDigest).toBe(
      result.proof.after.stateDigest
    );
    expect(result.proof.authority).toEqual(
      expect.objectContaining({
        findingCreateAuthority: false,
        findingStatusMutationAuthority: false,
        findingSeverityMutationAuthority: false,
        lifecycleMutationAuthority: false,
        waiverMutationAuthority: false,
        suppressionMutationAuthority: false,
        policyOverrideAuthority: false,
        blockDecisionAuthority: false,
        advisoryOnly: true
      })
    );
    expect(JSON.stringify(result)).not.toMatch(
      /detectorSignals|plannerSteps|rationale|"sourceContent"\s*:|"secretValue"\s*:/u
    );
  });

  it('rejects caller finding, lifecycle, waiver, suppression, and policy fields', async () => {
    const store = {
      createProof: jest.fn(),
      verifyPolicyReference: jest.fn()
    };
    const service = new AiAdvisoryAuthorityService(store as never);
    const proof = aiAuthorityProof();

    await expect(
      service.createProof({
        tenantId: proof.scope.tenantId,
        advisoryId: proof.scope.advisoryId,
        findingStatus: 'FIXED',
        severity: 'INFO',
        waiver: true,
        suppression: true,
        policyOverride: 'BLOCK'
      } as never)
    ).rejects.toThrow(
      'AI authority proof intent must contain only tenant and advisory identifiers.'
    );
    expect(store.createProof).not.toHaveBeenCalled();
  });

  it('fails closed when a policy reference is missing, drifted, or unavailable', async () => {
    const store = {
      createProof: jest.fn(),
      verifyPolicyReference: jest.fn().mockResolvedValue(true)
    };
    const service = new AiAdvisoryAuthorityService(store as never);
    const reference = aiPolicyReference();

    await expect(
      service.verifyPolicyReference({
        tenantId: 'tenant-ai',
        normalizedFindingId: 'normalized-finding-ai',
        reference
      })
    ).resolves.toBe(true);
    await expect(
      service.verifyPolicyReference({
        tenantId: 'tenant-ai',
        normalizedFindingId: 'normalized-finding-ai',
        reference: { ...reference, suggestedAction: 'BLOCK' } as never
      })
    ).resolves.toBe(false);
    expect(store.verifyPolicyReference).toHaveBeenCalledTimes(1);
  });
});
