export interface SessionData {
    clientId: string;
    state: string;
    codeVerifier: string;
    redirectUri: string;
    originalState?: string;
    clientCodeChallenge?: string;
    clientCodeChallengeMethod?: string;
}
