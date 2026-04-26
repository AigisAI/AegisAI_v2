import type { Provider } from './common';

export interface AuthUser {
  id: string;
  email: string | null;
  name: string;
  avatarUrl: string | null;
  connectedProviders: Provider[];
}

export type AuthMeResponse = AuthUser;
export type LogoutResponse = null;
