import type {
  SastAcceptedEvidenceScope,
  SastEvidenceDigest,
  SastEvidenceFragmentRequest
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

export type SastAcceptedEvidenceSourceResult =
  | {
      status: 'VERIFIED';
      candidateId: string;
      role: SastEvidenceFragmentRequest['role'];
      normalizedPath: string;
      startLine: number;
      endLine: number;
      anchorStartLine: number;
      anchorEndLine: number;
      sourceFileLineCount: number;
      scannerRedactedContent: string;
      sourceContentDigest: SastEvidenceDigest;
      sourceAttestationRef: string;
      scannerRedactionApplied: true;
      scannerRedactionDecisionRef: string;
      platformSecretValues: readonly string[];
    }
  | { status: 'UNAVAILABLE' };

export abstract class SastAcceptedEvidenceSourceAuthority {
  abstract read(input: {
    scope: Readonly<SastAcceptedEvidenceScope>;
    request: Readonly<SastEvidenceFragmentRequest>;
  }): Promise<SastAcceptedEvidenceSourceResult>;
}

@Injectable()
export class UnavailableSastAcceptedEvidenceSourceAuthority
  extends SastAcceptedEvidenceSourceAuthority {
  async read(): Promise<SastAcceptedEvidenceSourceResult> {
    return { status: 'UNAVAILABLE' };
  }
}
