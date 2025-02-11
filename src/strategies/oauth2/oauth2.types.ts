import {
  BaseAuthStrategyConfig,
  CredentailsConfig,
  PKCEConfig,
  AuthRouteConfig,
  TokenAuthStrategyConfig,
  TokenConfig,
  UserConfig,
} from "../../types";

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

  /**
   * Endpoint for user logout
   */
  logoutUrl?: string;
}

export interface OAuth2StrategyConfig<TContext = unknown, TUser = unknown>
  extends TokenAuthStrategyConfig<TContext, TUser> {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope?: string | string[];
  audience?: string;
  responseType?: "code" | "token" | "id_token" | string;
  grantType:
    | "authorization_code"
    | "client_credentials"
    | "password"
    | "refresh_token"
    | string;
  endpoints: OAuth2Endpoints;
  credentials?: CredentailsConfig<TContext>;
  pkce?: PKCEConfig<TContext>;
}
