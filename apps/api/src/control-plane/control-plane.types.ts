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

export interface GithubWebhookRepositoryInput {
  id?: string | number;
  providerRepoId?: string;
  full_name?: string;
  fullName?: string;
  default_branch?: string;
  defaultBranch?: string;
  private?: boolean;
  isPrivate?: boolean;
}

export interface GithubInstallationWebhookInput {
  tenantId?: string;
  action: string;
  installation: {
    id: string | number;
  };
  repositories?: GithubWebhookRepositoryInput[];
  repositories_added?: GithubWebhookRepositoryInput[];
  repositories_removed?: GithubWebhookRepositoryInput[];
}

export interface GithubInstallationWebhookAck {
  acknowledged: true;
  provider: "GITHUB";
  event: string;
  externalInstallationId: string;
  addedRepositoryCount: number;
  removedRepositoryCount: number;
}

export interface InstallIntegrationInput {
  tenantId: string;
  externalInstallationId: string;
  repoReadPrincipalId: string;
  commentWritePrincipalId?: string;
  integrationAdminPrincipalId?: string;
  repositories?: InstallRepositoryInput[];
  runtimeAccessToken?: string;
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
