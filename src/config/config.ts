import * as Soap from "@soapjs/soap";

/**
 * Configuration for JWT (JSON Web Token)
 * @typedef {Object} JwtConfig
 * @property {string} secretOrKey - Secret or key for signing JWTs.
 * @property {string|number} expiresIn - Expiration time for the JWT.
 * @property {string} [refreshSecretOrKey] - Optional secret or key for signing refresh JWTs.
 * @property {string|number} [refreshExpiresIn] - Expiration time for the refresh JWT.
 * @property {function} validate - Function to validate the JWT payload.
 * @property {'cookie' | 'header' | 'database'} storageMethod - Method to store the JWT.
 * @property {CookieOptions} [cookieOptions] - Options for storing JWT in cookies.
 */
export interface JwtConfig {
  secretOrKey: string;
  expiresIn: string | number;
  refreshSecretOrKey?: string;
  refreshExpiresIn?: string | number;
  validate: (payload: any) => Promise<boolean>;
  storageMethod: "cookie" | "header" | "database";
  cookieOptions?: CookieOptions;
}

/**
 * Options for cookie storage
 * @typedef {Object} CookieOptions
 * @property {boolean} httpOnly - Whether the cookie is HTTP only.
 * @property {boolean} secure - Whether the cookie is secure.
 * @property {number} [maxAge] - Max age for the cookie.
 */
export interface CookieOptions {
  httpOnly: boolean;
  secure: boolean;
  maxAge?: number;
}

/**
 * Configuration for session
 * @typedef {Object} SessionConfig
 * @property {string} secret - Secret for signing the session ID cookie.
 * @property {boolean} resave - Whether to force save the session on every request.
 * @property {boolean} saveUninitialized - Whether to save uninitialized sessions.
 * @property {any} [store] - Session store (e.g., connect-mongo, connect-redis).
 * @property {function} [serializeUser] - Function to serialize user to session.
 * @property {function} [deserializeUser] - Function to deserialize user from session.
 */
export interface SessionConfig {
  secret: string;
  resave: boolean;
  saveUninitialized: boolean;
  store?: any;
  serializeUser?: (user: any, done: (err: any, id?: any) => void) => void;
  deserializeUser?: (id: any, done: (err: any, user?: any) => void) => void;
}

/**
 * Configuration for Local Strategy
 * @typedef {Object} LocalStrategyConfig
 * @property {function} verify - Function to verify username and password.
 * @property {boolean} [session] - Whether to use session for this strategy.
 * @property {boolean} [useOwnJWT] - Whether to use own JWT after OAuth.
 * @property {string} [login] - Login route configuration.
 * @property {string} [logout] - Logout route configuration.
 * @property {string} [failureRedirect] - Failure redirect.
 * @property {string} [successRedirect] - Success redirect.
 */
export interface LocalStrategyConfig {
  verify: (username: string, password: string) => Promise<any>;
  session?: boolean;
  useOwnJWT?: boolean;
  login?: Soap.AuthRoute;
  logout?: Soap.AuthRoute;
  failureRedirect?: string;
  successRedirect?: string;
}

/**
 * Configuration for OAuth Strategy
 * @typedef {Object} OAuthConfig
 * @property {string} clientID - OAuth client ID.
 * @property {string} clientSecret - OAuth client secret.
 * @property {string} callbackURL - OAuth callback URL.
 * @property {string[]} scope - OAuth scopes.
 * @property {boolean} useOwnJWT - Whether to use own JWT after OAuth.
 * @property {function} verify - Function to verify OAuth profile.
 * @property {boolean} [session] - Whether to use session for this strategy.
 * @property {string} [login] - Login route configuration.
 * @property {string} [logout] - Logout route configuration.
 * @property {string} [failureRedirect] - Failure redirect.
 * @property {string} [successRedirect] - Success redirect.
 */
export interface OAuthConfig {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope: string[];
  useOwnJWT: boolean;
  verify: (
    accessToken: string,
    refreshToken: string,
    profile: any
  ) => Promise<any>;
  session?: boolean;
  login?: Soap.AuthRoute;
  logout?: Soap.AuthRoute;
  failureRedirect?: string;
  successRedirect?: string;
}

/**
 * Configuration for OAuth2 Strategy
 * @typedef {Object} OAuth2Config
 * @property {string} authorizationURL - OAuth2 authorization URL.
 * @property {string} tokenURL - OAuth2 token URL.
 * @property {string} clientID - OAuth2 client ID.
 * @property {string} clientSecret - OAuth2 client secret.
 * @property {string} callbackURL - OAuth2 callback URL.
 * @property {string[]} scope - OAuth2 scopes.
 * @property {boolean} useOwnJWT - Whether to use own JWT after OAuth2.
 * @property {function} verify - Function to verify OAuth2 profile.
 * @property {boolean} [session] - Whether to use session for this strategy.
 * @property {string} [login] - Login route configuration.
 * @property {string} [logout] - Logout route configuration.
 * @property {string} [failureRedirect] - Failure redirect.
 * @property {string} [successRedirect] - Success redirect.
 */
export interface OAuth2Config {
  authorizationURL: string;
  tokenURL: string;
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope: string[];
  useOwnJWT: boolean;
  verify: (
    accessToken: string,
    refreshToken: string,
    profile: any
  ) => Promise<any>;
  session?: boolean;
  login?: Soap.AuthRoute;
  logout?: Soap.AuthRoute;
  failureRedirect?: string;
  successRedirect?: string;
}

/**
 * Configuration for API Key Strategy
 * @typedef {Object} ApiKeyStrategyConfig
 * @property {string} [headerName] - Name of the header containing the API key.
 * @property {string} [queryParamName] - Name of the query parameter containing the API key.
 * @property {string} [bodyParamName] - Name of the body parameter containing the API key.
 * @property {function} validate - Function to validate the API key.
 * @property {boolean} [session] - Whether to use session for this strategy.
 */
export interface ApiKeyStrategyConfig {
  headerName?: string;
  queryParamName?: string;
  bodyParamName?: string;
  validate: (apiKey: string) => Promise<boolean>;
  session?: boolean;
}

/**
 * Configuration for Bearer Strategy
 * @typedef {Object} BearerStrategyConfig
 * @property {function} verify - Function to verify the bearer token.
 * @property {boolean} useOwnJWT - Whether to use own JWT after OAuth2.
 * @property {function} verify - Function to verify OAuth2 profile.
 * @property {boolean} [session] - Whether to use session for this strategy.
 * @property {string} [login] - Login route configuration.
 * @property {string} [logout] - Logout route configuration.
 * @property {string} [refreshToken] - Refresh token route configuration.
 */
export interface BearerStrategyConfig {
  verify: (token: string) => void;
  session?: boolean;
  useOwnJWT?: boolean;
  login?: Soap.AuthRoute;
  logout?: Soap.AuthRoute;
  refreshToken?: Soap.AuthRoute;
}

/**
 * Configuration for Basic Strategy
 * @typedef {Object} BasicStrategyConfig
 * @property {function} verify - Function to verify username and password.
 * @property {boolean} [session] - Whether to use session for this strategy.
 */
export interface BasicStrategyConfig {
  verify: (username: string, password: string) => void;
  session?: boolean;
}

/**
 * Configuration for Web3 Strategy
 * @typedef {Object} Web3StrategyConfig
 * @property {function} verify - Function to verify the Web3 address and signature.
 * @property {boolean} [session] - Whether to use session for this strategy.
 */
export interface Web3StrategyConfig {
  verify: (
    address: string,
    signature: string,
    done: (error: any, user?: any) => void
  ) => void;
  session?: boolean;
}

/**
 * Main configuration for the authentication module
 * @typedef {Object} SoapAuthConfig
 * @property {JwtConfig} [jwt] - JWT configuration.
 * @property {SessionConfig} [session] - Session configuration.
 * @property {Object} strategies - Authentication strategies configuration.
 * @property {LocalStrategyConfig} [strategies.local] - Local strategy configuration.
 * @property {Object.<string, OAuthConfig>} [strategies.oauth] - OAuth strategies configuration.
 * @property {Object.<string, OAuth2Config>} [strategies.oauth2] - OAuth2 strategies configuration.
 * @property {ApiKeyStrategyConfig} [strategies.apiKey] - API key strategy configuration.
 * @property {BearerStrategyConfig} [strategies.bearer] - Bearer strategy configuration.
 * @property {BasicStrategyConfig} [strategies.basic] - Basic strategy configuration.
 * @property {Web3StrategyConfig} [strategies.web3] - Web3 strategy configuration.
 */
export interface SoapAuthConfig {
  jwt?: JwtConfig;
  session?: SessionConfig;
  strategies: {
    local?: LocalStrategyConfig;
    oauth?: { [provider: string]: OAuthConfig };
    oauth2?: { [provider: string]: OAuth2Config };
    apiKey?: ApiKeyStrategyConfig;
    bearer?: BearerStrategyConfig;
    basic?: BasicStrategyConfig;
    web3?: Web3StrategyConfig;
  };
}
