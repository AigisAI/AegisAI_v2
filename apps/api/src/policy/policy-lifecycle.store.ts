import type {
  Suppression,
  SuppressionCreateInput,
  Waiver,
  WaiverCreateInput,
  WaiverUpdateInput
} from '@aegisai/shared';

export abstract class PolicyLifecycleStore {
  abstract createWaiver(
    input: Readonly<WaiverCreateInput>
  ): Promise<Waiver>;

  abstract updateWaiver(
    waiverId: string,
    input: Readonly<WaiverUpdateInput>
  ): Promise<Waiver | null>;

  abstract createSuppression(
    input: Readonly<SuppressionCreateInput>
  ): Promise<Suppression>;
}
