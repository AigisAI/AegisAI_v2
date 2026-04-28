import { Injectable } from "@nestjs/common";
import { randomBytes } from "node:crypto";
import type { TokenBrokerIssueRequest } from "../../../../packages/shared/src";

export interface IssuedTokenCredential {
  credentialType: "SCM_REPOSITORY_ACCESS";
  credentialValue: string;
  issuedAt: string;
  expiresAt: string;
}

@Injectable()
export class TokenCredentialIssuerService {
  issue(input: TokenBrokerIssueRequest): IssuedTokenCredential {
    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + input.ttlSeconds * 1000);

    return {
      credentialType: "SCM_REPOSITORY_ACCESS",
      credentialValue: this.buildCredentialValue(input),
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString()
    };
  }

  private buildCredentialValue(input: TokenBrokerIssueRequest): string {
    const randomPart = randomBytes(24).toString("base64url");
    const scopePart = Buffer.from(
      [
        input.tenantId,
        input.repositoryBindingId,
        input.scanRequestId,
        input.commitSha,
        input.principal
      ].join(":")
    ).toString("base64url");

    return `aegis_tb_${scopePart}.${randomPart}`;
  }
}
