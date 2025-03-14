export interface StoredToken {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number;
  clientId: string;
  scopes: string[];
  clientCodeChallenge?: string;
  clientCodeChallengeMethod?: string;
}
