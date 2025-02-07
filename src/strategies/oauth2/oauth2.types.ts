import { TokenBasedAuthStrategyConfig, TokenConfig } from "../../types";

export interface OAuth2Endpoints {
  /**
   * Endpoint for user authorization (OAuth login)
   */
  authorizationUrl: string;
  /**
   * Endpoint for exchanging authorization code for tokens
   */
  tokenUrl: string;
  /**
   * Endpoint for fetching user profile data (OIDC)
   */
  userInfoUrl?: string;
  /**
   * Token introspection endpoint for validation
   */
  introspectionUrl?: string;
  /**
   * URL to revoke tokens if needed
   */
  revocationUrl?: string;
}

export interface OAuth2StrategyConfig<TContext = unknown, TUser = unknown>
  extends TokenBasedAuthStrategyConfig<TContext, TUser> {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope?: string;
  grantType:
    | "authorization_code"
    | "client_credentials"
    | "password"
    | "refresh_token";
  endpoints: OAuth2Endpoints;
  validateUser?: (tokenPayload: any) => Promise<TUser | null>;
  credentials?: { username: string; password: string };
  pkce?: PKCEConfig<TContext>;
  accessToken?: TokenConfig;
  refreshToken?: TokenConfig;
}

export interface PKCEConfig<TContext> {
  generateCodeVerifier?: () => string;
  storeCodeVerifier?: (context: TContext, codeVerifier: string) => void;
  retrieveCodeVerifier?: (context: TContext) => string | null;
}
