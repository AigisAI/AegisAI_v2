import type {
  IsolationEscalationInput,
  IsolationClass,
  RepositoryBinding,
  ScanLane,
  ScanRequest,
  ScmIntegration,
  ScmProvider
} from "../../../../packages/shared/src";

export interface InstallRepositoryInput {
  providerRepoId: string;
  fullName: string;
  defaultBranch: string;
  isPrivate: boolean;
}

export interface InstallIntegrationInput {
  tenantId: string;
  externalInstallationId: string;
  repoReadPrincipalId: string;
  commentWritePrincipalId?: string;
  integrationAdminPrincipalId?: string;
  repositories?: InstallRepositoryInput[];
}

export interface CreateScanRequestInput {
  tenantId: string;
  repositoryBindingId: string;
  lane: ScanLane;
  targetRef: string;
  commitSha: string;
  policyVersion: string;
  scannerSetVersion: string;
  isolationSignals?: IsolationEscalationInput;
}

export type ControlPlaneIntegration = ScmIntegration;
export type ControlPlaneRepositoryBinding = RepositoryBinding;
export type ControlPlaneScanRequest = ScanRequest;

export interface InstallIntegrationOptions {
  provider: ScmProvider;
  integrationType: "GITHUB_APP" | "GITLAB_CLOUD_INTEGRATION";
}

export interface BuildScanRequestOptions {
  isolationClass: IsolationClass;
}
