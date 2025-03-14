import { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

export interface ClientWithVerifier extends OAuthClientInformationFull {
    verifier: string;
}