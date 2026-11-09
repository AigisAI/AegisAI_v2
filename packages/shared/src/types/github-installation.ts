/** Provider identifiers only; repository metadata is never trusted from callers. */
export interface LinkGithubInstallationRequest {
  installationId: number;
  repositoryIds: number[];
}

/** Provider-verified branch metadata; contains neither source nor a credential. */
export interface ResolvedGithubCommit {
  providerRepoId: string;
  targetRef: string;
  commitSha: string;
}
