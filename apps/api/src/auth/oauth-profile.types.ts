export interface OAuthProfileEmail {
  value?: string | null;
}

export interface OAuthProfilePhoto {
  value?: string | null;
}

export interface GithubOAuthProfile {
  id: string | number;
  username?: string;
  displayName?: string;
  emails?: OAuthProfileEmail[];
  photos?: OAuthProfilePhoto[];
}

export interface GitlabOAuthProfile {
  id: string | number;
  username?: string;
  displayName?: string;
  emails?: OAuthProfileEmail[];
  avatarUrl?: string | null;
}

export type OAuthProviderProfile = GithubOAuthProfile | GitlabOAuthProfile;
