import type { PolicyDecision } from '@aegisai/shared';

export type PolicyDecisionCreate = Omit<PolicyDecision, 'id'>;

export abstract class PolicyDecisionStore {
  abstract create(
    input: Readonly<PolicyDecisionCreate>
  ): Promise<PolicyDecision>;

  abstract findByTenantAndId(
    tenantId: string,
    policyDecisionId: string
  ): Promise<PolicyDecision | null>;
}
