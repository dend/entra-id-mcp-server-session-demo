import crypto from 'crypto';
import { StoredToken } from './StoredToken.js';

export class TokenStore {
  private _tokenMap: Map<string, StoredToken> = new Map();

  /**
   * Store an access token and return a session token
   */
  public storeToken(accessToken: string, refreshToken: string | undefined, expiresIn: number,
    clientId: string, scopes: string[],
    clientCodeChallenge?: string,
    clientCodeChallengeMethod?: string): string {

    const sessionToken = crypto.randomBytes(32).toString('hex');

    const expiresAt = Date.now() + (expiresIn * 1000);

    this._tokenMap.set(sessionToken, {
      accessToken,
      refreshToken,
      expiresAt,
      clientId,
      scopes,
      clientCodeChallenge,
      clientCodeChallengeMethod
    });

    return sessionToken;
  }

  public getToken(sessionToken: string): StoredToken | undefined {
    return this._tokenMap.get(sessionToken);
  }

  public removeToken(sessionToken: string): boolean {
    return this._tokenMap.delete(sessionToken);
  }

  public cleanExpiredTokens(): void {
    const now = Date.now();
    this._tokenMap.forEach((token, key) => {
      if (token.expiresAt < now) {
        this._tokenMap.delete(key);
      }
    });
  }
}