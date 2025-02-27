import { Algorithm } from "jsonwebtoken";
import {
  BaseAuthStrategyConfig,
  CredentailsConfig,
  PKCEConfig,
  AuthRouteConfig,
  TokenAuthStrategyConfig,
  TokenConfig,
  UserConfig,
  PersistenceConfig,
  ContextOperationConfig,
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

export interface OAuth2StateConfig<TContext = unknown, TData = any> {
  persistence?: PersistenceConfig;
  context?: ContextOperationConfig<TContext, TData>;
  generateState?: () => string | Promise<string>;
  validateState?: (
    storedState: TContext,
    returnedState: string
  ) => boolean | Promise<boolean>;
}

export interface OAuth2NonceConfig<TContext = unknown, TData = any> {
  persistence?: PersistenceConfig;
  context?: ContextOperationConfig<TContext, TData>;
  generateNonce?: () => string | Promise<string>;
  validateNonce?: (
    storedNonce: string | null,
    returnedNonce: string
  ) => boolean | Promise<boolean>;
}

export type JwksConfig = {
  jwksUri: string;
  issuer: string;
  algorithms?: Algorithm[];
  audience?: string;
};

export interface OAuth2StrategyConfig<TContext = unknown, TUser = unknown>
  extends TokenAuthStrategyConfig<TContext, TUser> {
  autoLogoutOnRefreshFailure?: boolean;
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
  routes: {
    login: AuthRouteConfig;
    callback: AuthRouteConfig;
    logout?: AuthRouteConfig;
    refresh?: AuthRouteConfig;
    revoke?: AuthRouteConfig;
    [key: string]: AuthRouteConfig;
  };
  state?: OAuth2StateConfig<TContext>;
  nonce?: OAuth2NonceConfig;
  jwks?: JwksConfig;
}
