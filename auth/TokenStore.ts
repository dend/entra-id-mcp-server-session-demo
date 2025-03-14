import { randomBytes } from 'crypto';

/**
 * Token store to manage mapping between MCP session tokens and Entra ID tokens
 */
export class TokenStore {
  private _tokens: Map<string, {
    accessToken: string;
    expiresAt: number;
    clientId: string;
    scopes: string[];
    clientCodeChallenge?: string;
    clientCodeChallengeMethod?: string;
  }> = new Map();

  /**
   * Store an Entra ID token and return a session token
   */
  storeToken(
    accessToken: string,
    refreshToken: string,
    expiresInSeconds: number = 3600,
    clientId: string,
    scopes: string[] = [],
    clientCodeChallenge?: string,
    clientCodeChallengeMethod?: string,
  ): string {
    // Generate a session token (UUID)
    const sessionToken = randomBytes(16).toString('hex');

    const expiresAt = Date.now() + expiresInSeconds * 1000;
    this._tokens.set(sessionToken, {
      accessToken,
      expiresAt,
      clientId,
      scopes,
      clientCodeChallenge,
      clientCodeChallengeMethod,
    });

    return sessionToken;
  }

  /**
   * Get token data using a session token
   */
  getToken(sessionToken: string): {
    accessToken: string;
    expiresAt: number;
    clientId: string;
    scopes: string[];
    clientCodeChallenge?: string;
    clientCodeChallengeMethod?: string;
  } | undefined {
    const tokenData = this._tokens.get(sessionToken);

    if (!tokenData) {
      return undefined;
    }

    // Check if token is expired
    if (tokenData.expiresAt < Date.now()) {
      this._tokens.delete(sessionToken);
      return undefined;
    }

    return tokenData;
  }

  /**
   * Remove a token from the store
   */
  removeToken(sessionToken: string): void {
    this._tokens.delete(sessionToken);
  }

  /**
   * Clean up expired tokens
   */
  cleanExpiredTokens(): void {
    const now = Date.now();
    for (const [token, data] of this._tokens.entries()) {
      if (data.expiresAt < now) {
        this._tokens.delete(token);
      }
    }
  }
}

// Create a singleton instance to be used throughout the app
export const tokenStore = new TokenStore();