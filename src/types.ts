import * as Soap from "@soapjs/soap";
import { LocalStrategyConfig } from "./strategies/local/local.types";
import { OAuth2StrategyConfig } from "./strategies/oauth2/oauth2.types";
import { ApiKeyStrategyConfig } from "./strategies/api-key/api-key.types";
import { BasicStrategyConfig } from "./strategies/basic/basic.types";
import { JwtConfig } from "./strategies/jwt/jwt.types";

/**
 * Represents a store that handles session persistence.
 * Implementations can store sessions in memory, files, databases, etc.
 *
 * @interface SessionStore
 */
export interface SessionStore {
  /**
   * Retrieves session data for the given session ID.
   * @param sid - The session ID.
   * @param args - Additional optional arguments.
   * @returns A promise that resolves to the session data or null if not found.
   */
  getSession<T = SessionData>(
    sid: string,
    ...args: unknown[]
  ): Promise<T | null>;

  /**
   * Stores session data for the given session ID.
   * @param sid - The session ID.
   * @param session - The session data to store.
   * @param args - Additional optional arguments.
   * @returns Void or a promise that resolves when the session is stored.
   */
  setSession<T = SessionData>(
    sid: string,
    session: T,
    ...args: unknown[]
  ): void | Promise<void>;

  /**
   * Destroys the session associated with the given session ID.
   * @param sid - The session ID.
   * @param args - Additional optional arguments.
   * @returns Void or a promise that resolves when the session is destroyed.
   */
  destroySession(sid: string, ...args: unknown[]): void | Promise<void>;

  /**
   * Updates the session's last modified time or data without replacing the entire session.
   * @param sid - The session ID.
   * @param session - The session data to update.
   * @param args - Additional optional arguments.
   * @returns Void or a promise that resolves when the session is updated.
   */
  touchSession<T = SessionData>(
    sid: string,
    session: T,
    ...args: unknown[]
  ): void | Promise<void>;
}

/**
 * Represents the data stored in a session.
 *
 * @typedef {Object} SessionData
 */
export type SessionData =
  | {
      [key: string]: any;
    }
  | any;

export type SessionInfo<TData = any> = {
  sessionId: string;
  data: TData;
};

/**
 * Configuration for session
 * @typedef {Object} SessionConfig
 * @property {string} secret - Secret for signing the session ID cookie.
 * @property {boolean} [resave] - Whether to force save the session on every request.
 * @property {boolean} [saveUninitialized] - Whether to save uninitialized sessions.
 * @property {CookieStorageOptions} [cookie] - Common options for handling cookies.
 * @property {SessionStore} [store] - Session store (e.g., connect-mongo, connect-redis).
 */
export interface SessionConfig {
  secret: string;
  resave?: boolean;
  saveUninitialized?: boolean;
  store?: SessionStore;
  /**
   * Custom session key used for cookies.
   */
  sessionKey?: string;

  /**
   * Custom session header key used in requests.
   */
  sessionHeader?: string;
  /**
   * Optional function to generate a new session ID.
   * If not provided, a default method may be used.
   */
  generateSessionId?: (...args: unknown[]) => string;

  /**
   * Optional function to create initial session data based on the context.
   * @param data - Optional data to initialize session.
   * @param context - Optional context or input data to initialize session.
   * @returns An object representing the initial session data.
   */
  createSessionData?: <T>(data?: unknown, context?: unknown) => T;

  /**
   * Optional function to deliver a session ID or token into the response or context.
   * @param context - The context of the current request/response.
   * @param sessionId - The session ID or token to deliver.
   */
  embedSessionId?: (context: any, sessionId: string) => void;

  /**
   * Retrieves the session ID from the context.
   *
   * @param context - The authentication context.
   * @returns {string | null} The session ID or null if not found.
   */
  getSessionId(context: any): string | null;

  [key: string]: any;
}

/**
 * Represents a user credentials object returned by the retrieval function.
 */
export type Credentials = {
  id: string;
  hashedPassword: string;
  [key: string]: unknown;
};

export interface AuthResultConfig<TContext = unknown, TUser = unknown> {
  onSuccess?: (
    context: AuthSuccessContext<TUser, TContext>
  ) => Promise<void> | void;
  onFailure?: (context: AuthFailureContext<TContext>) => Promise<void> | void;
}

export interface SecurityConfig {
  security?: {
    maxFailedLoginAttempts?: number;
    lockoutDuration?: number;
    notifyOnLockout?: (account: any) => Promise<void>;
  };
}

export interface BaseAuthStrategyConfig<TContext = unknown, TUser = unknown>
  extends AccountLockConfig<TContext>,
    RateLimitConfig,
    RoleAuthorizationConfig<TUser>,
    SecurityConfig {
  mfa?: MfaConfig<TUser, TContext>;
  session?: SessionConfig;
}

export interface AuditLoggingConfig<TContext = unknown> {
  logAttempt?: (
    userId: string,
    success: boolean,
    context?: TContext
  ) => Promise<void>;
  logPasswordChange?: (userId: string, context?: TContext) => Promise<void>;
}

export interface MfaConfig<TUser = unknown, TContext = unknown> {
  /**
   * Extracts a multi-factor authentication (MFA) code from the context.
   * @param context - The authentication context.
   * @returns {string} MFA code.
   */
  extractMfaCode?: (context?: TContext) => string;
  /**
   * Sends a multi-factor authentication (MFA) code to the user.
   * @param user - The authenticated user.
   * @param context - The authentication context.
   * @returns {Promise<boolean>} A promise resolving to true if the code was sent successfully.
   */
  sendMfaCode?: (user: TUser, context?: TContext) => Promise<boolean>;

  /**
   * Validates the multi-factor authentication (MFA) code provided by the user.
   * @param user - The authenticated user.
   * @param code - The MFA code to validate.
   * @returns {Promise<boolean>} A promise resolving to true if the code is valid.
   */
  validateMfaCode?: (user: TUser, code: string) => Promise<boolean>;

  /**
   * Determines if the given user requires MFA for login.
   * @param user - The authenticated user.
   * @returns {boolean} Whether MFA is required.
   */
  isMfaRequired?: (user: TUser) => boolean;

  /**
   * Generates a new MFA secret for the user (for TOTP apps like Google Authenticator).
   * @param user - The authenticated user.
   * @returns {Promise<string>} The generated secret.
   */
  generateMfaSecret?: (user: TUser) => Promise<string>;

  /**
   * Validates the initial setup of MFA (e.g., first-time TOTP secret verification).
   * @param user - The authenticated user.
   * @param secret - The MFA secret provided by the user.
   * @returns {Promise<boolean>} Whether the MFA setup is valid.
   */
  verifyMfaSetup?: (user: TUser, secret: string) => Promise<boolean>;

  /**
   * Disables MFA for the given user.
   * @param user - The authenticated user.
   * @returns {Promise<void>} Resolves when MFA is successfully disabled.
   */
  disableMfa?: (user: TUser) => Promise<void>;

  /**
   * Provides backup codes for emergency access.
   * @param user - The authenticated user.
   * @returns {Promise<string[]>} An array of backup codes.
   */
  generateBackupCodes?: (user: TUser) => Promise<string[]>;

  /**
   * Validates a backup code provided by the user.
   * @param user - The authenticated user.
   * @param code - The backup code to validate.
   * @returns {Promise<boolean>} A promise resolving to true if the code is valid.
   */
  validateBackupCode?: (user: TUser, code: string) => Promise<boolean>;

  maxMfaAttempts?: number;
  lockMfaOnFailure?: (user: TUser) => Promise<void>;
  getMfaAttempts?: (user: TUser) => Promise<number>;
  resetMfaAttempts?: (user: TUser) => Promise<void>;
  incrementMfaAttempts?: (user: TUser) => Promise<void>;
}

export interface PasswordPolicyConfig {
  validatePassword?: (password: string) => boolean;
  getLastPasswordChange?: (identifier: string) => Date;
  forcePasswordChangeOnFirstLogin?: boolean;
  passwordExpirationDays?: number;
}

export interface CredentialBasedAuthStrategyConfig<
  TContext = unknown,
  TUser = unknown
> extends BaseAuthStrategyConfig<TContext, TUser> {
  passwordPolicy?: PasswordPolicyConfig;
  audit?: AuditLoggingConfig<TContext>;
  logout: {} & AuthResultConfig<TContext, TUser>;
  login: {
    extractCredentials: (
      context: TContext
    ) => Promise<{ identifier: string; password: string }>;
    retrieveUserData: (identifier: string) => Promise<TUser | null>;
    verifyUserCredentials: (
      identifier: string,
      password: string
    ) => Promise<boolean>;
    incrementFailedAttempts?: (identifier: string) => Promise<void>;
    resetFailedAttempts?: (identifier: string) => Promise<void>;
    getFailedAttempts?: (identifier: string) => Promise<number>;
  } & AuthResultConfig<TContext, TUser>;
  passwordReset?: {
    generateResetToken?: (identifier: string) => Promise<string>;
    sendResetEmail?: (identifier: string, token: string) => Promise<void>;
    validateResetToken?: (token: string) => Promise<boolean>;
    updatePassword?: (identifier: string, newPassword: string) => Promise<void>;
  } & AuthResultConfig<TContext, TUser>;
}

export interface TokenBasedAuthStrategyConfig<
  TContext = unknown,
  TUser = unknown
> extends BaseAuthStrategyConfig<TContext, TUser>,
    TokenRotationConfig<TUser> {
  tokens?: TokenHandlersConfig;
  login: {
    retrieveUserData: (identifier: string) => Promise<TUser | null>;
  } & AuthResultConfig<TContext, TUser>;
  logout: {} & AuthResultConfig<TContext, TUser>;
}

export interface TokenRotationConfig<TUser = unknown> {
  enableRotation?: boolean;
  maxRotations?: number;
  storeUsedTokens?: boolean;
  getRefreshToken?: (user: TUser) => Promise<string>;
  rotateToken?: (
    refreshToken: string
  ) => Promise<{ accessToken: string; refreshToken: string }>;
  onTokenRotated?: (
    user: TUser,
    newTokens: { accessToken: string; refreshToken: string }
  ) => Promise<void>;
  onTokenRotationFailure?: (user: TUser, error: Error) => Promise<void>;
}

/**
 * A function to check if the account is locked.
 * @returns A promise resolving to a boolean indicating if the account is locked.
 */
export interface AccountLockConfig<TContext = unknown> {
  logFailedAttempt?: (account: any, context?: TContext) => Promise<void>;
  lockAccount?: (account: any, ...args: unknown[]) => Promise<void>;
  isAccountLocked?: (account: any, ...args: unknown[]) => Promise<boolean>;
}

/**
 * A function to check if the user has exceeded its request limit.
 * @returns A promise resolving to a boolean indicating if the limit is exceeded.
 */
export interface RateLimitConfig {
  checkRateLimit?: (...args: unknown[]) => Promise<boolean>;
  incrementRequestCount?: (...args: unknown[]) => Promise<void>;
}

/**
 * A function to verify if the user has the required role.
 * @param user - The authenticated user object.
 * @param roles - Array of required roles.
 * @returns A promise resolving to a boolean indicating authorization success.
 */
export interface RoleAuthorizationConfig<TUser = unknown> {
  authorizeByRoles?: (user: TUser, roles: string[]) => Promise<boolean>;
  roles?: string[];
}

export type AuthSuccessContext<
  TUser = unknown,
  TContext = unknown,
  TSessionData = unknown
> = {
  user?: TUser;
  context?: TContext;
  session?: SessionInfo<TSessionData>;
  tokens?: string;
  identifier?: string;
  email?: string;
};

export type AuthFailureContext<TContext = unknown> = {
  error: Error;
  context?: TContext;
  identifier?: string;
  email?: string;
};

export type AuthResult<TUser, TSessionData = unknown> = {
  user: TUser;
  session?: SessionInfo<TSessionData>;
  tokens?: {
    accessToken?: string;
    refreshToken?: string | null;
    apiKey?: string | null;
  };
};

/**
 * Represents a generic authentication strategy.
 */
export interface AuthStrategy<TContext = unknown, TUser = unknown> {
  /**
   * (Optional) Asynchronous initialization method for the strategy.
   * Can be used to fetch keys, initialize connections, etc.
   */
  init?(...args: unknown[]): Promise<void>;

  /**
   * Authenticates input data (e.g., token, credentials) and returns user info.
   * @param context - Data required for authentication.
   * @returns A promise resolving with authenticated user data.
   */
  authenticate(
    context?: TContext,
    ...args: unknown[]
  ): Promise<AuthResult<TUser>>;

  /**
   * (Optional) Authorizes a user for a specific action on a resource.
   * @param user - Authenticated user data.
   * @param action - Action to authorize (e.g., "read", "write").
   * @param resource - Optional resource identifier.
   * @returns A promise resolving to a boolean indicating authorization status.
   */
  authorize?(user: any, action: string, resource?: string): Promise<boolean>;

  /**
   * (Optional) Refreshes an authentication token.
   * @param refreshToken - Current refresh token.
   * @returns A promise resolving to a new token.
   */
  refresh?(refreshToken: string): Promise<string>;

  /**
   * Logs out the user by destroying the session.
   *
   * @param {TContext} [context] - The authentication context.
   * @throws {Error} If session manager is not configured or session ID is missing.
   */
  logout?(context?: TContext): Promise<void>;
}

/**
 * Configuration interface for soap-auth, allowing customization of various http authentication strategies.
 *
 * @interface SoapHttpAuthConfig
 */
export interface SoapHttpAuthConfig<TContext = unknown, TUser = unknown> {
  /**
   * Configuration for local username/password strategy.
   * @type {LocalStrategyConfig | undefined}
   */
  local?: LocalStrategyConfig<TContext, TUser>;

  /**
   * Configuration for multiple OAuth2 providers.
   * The key is the provider's identifier, and the value is its configuration.
   * @type {{ [provider: string]: OAuth2StrategyConfig } | undefined}
   */
  oauth2?: { [provider: string]: OAuth2StrategyConfig<TContext, TUser> };

  /**
   * Configuration for API key based strategy.
   * @type {ApiKeyStrategyConfig | undefined}
   */
  apiKey?: ApiKeyStrategyConfig<TContext, TUser>;

  /**
   * Configuration for token-based strategy (e.g. JWT).
   * @type {JwtConfig | undefined}
   */
  jwt?: JwtConfig<TContext, TUser>;

  /**
   * Configuration for basic authentication strategy.
   * @type {BasicStrategyConfig | undefined}
   */
  basic?: BasicStrategyConfig<TContext, TUser>;

  /**
   * Custom authentication strategies.
   * The key is a custom label, and the value is an implementation of AuthStrategy.
   * @type {{ [label: string]: AuthStrategy }}
   */
  custom: { [label: string]: AuthStrategy };
}

/**
 * Configuration interface for soap-auth, allowing customization of various socket authentication strategies.
 *
 * @interface SoapSocketAuthConfig
 */
export interface SoapSocketAuthConfig<TContext = unknown, TUser = unknown> {
  /**
   * Configuration for token-based socket authentication.
   * @type {JwtConfig | undefined}
   */
  jwt?: JwtConfig<TContext, TUser>;

  /**
   * Configuration for API key based socket authentication.
   * @type {ApiKeyStrategyConfig | undefined}
   */
  apiKey?: ApiKeyStrategyConfig<TContext, TUser>;

  /**
   * Custom authentication strategies.
   * The key is a custom provider identifier, and the value is an implementation of AuthStrategy.
   * @type {{ [provider: string]: AuthStrategy }}
   */
  custom: { [provider: string]: AuthStrategy };
}

/**
 * Configuration interface for soap-auth, allowing customization of various authentication strategies.
 *
 * @interface SoapAuthConfig
 */
export interface SoapAuthConfig<TContext = unknown, TUser = unknown> {
  /**
   * Configuration for session management applicable to all strategies unless overridden.
   * @type {SessionConfig | undefined}
   */
  session?: SessionConfig;

  /**
   * Configuration for token management applicable to all strategies unless overridden.
   * @type {TokenHandlersConfig | undefined}
   */
  tokens?: TokenHandlersConfig;
  /**
   * Configuration for http strategies.
   * @type {SoapHttpAuthConfig | undefined}
   */
  http?: SoapHttpAuthConfig<TContext, TUser>;
  /**
   * Configuration for http strategies.
   * @type {SoapHttpAuthConfig | undefined}
   */
  socket?: SoapSocketAuthConfig<TContext, TUser>;

  /**
   * Optional logger implementation for logging within soap-auth.
   * If not provided, a default ConsoleLogger will be used.
   */
  logger?: Soap.Logger;
}

/**
 * Options for cookie storage
 * @typedef {Object} CookieStorageOptions
 * @property {string} cookieName - Name of the cookie.
 * @property {boolean} httpOnly - Whether the cookie is HTTP only.
 * @property {boolean} secure - Whether the cookie is secure.
 * @property {"strict"|"lax"|"none"} [sameSite] - SameSite policy for the cookie.
 * @property {number} [maxAge] - Max age for the cookie.
 */
export interface CookieStorageOptions {
  cookieName: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite?: "strict" | "lax" | "none";
  maxAge?: number;
}

/**
 * Options for header storage
 * @typedef {Object} HeaderStorageOptions
 * @property {string} headerName - Name of the header.
 * @property {string} [scheme] - Scheme for the token (e.g., Bearer).
 */
export interface HeaderStorageOptions {
  headerName: string;
  scheme?: string;
  extractor: (scheme: string) => string | null;
}

/**
 * Options for body storage
 * @typedef {Object} BodyStorageOptions
 * @property {string} name - Name of the body parameter.
 */
export interface BodyStorageOptions {
  name: string;
  extractor: (name: string) => string | null;
}

/**
 * Options for query storage
 * @typedef {Object} QueryStorageOptions
 * @property {string} name - Name of the query parameter.
 */
export interface QueryStorageOptions {
  name: string;
  extractor: (name: string) => string | null;
}

/**
 * Options for session storage
 * @typedef {Object} SessionStorageOptions
 * @property {string} name - Name of the session attribute.
 */
export interface SessionStorageOptions {
  name: string;
  extractor: (name: string) => string | null;
}

/**
 * Options for database storage
 * @typedef {Object} DatabaseOptions
 */
export interface DatabaseOptions {
  extractor: (...args: unknown[]) => Promise<string | null>;
}

/**
 * Represents a generic context that provides optional methods for storing,
 * retrieving, and removing data using various strategies such as headers,
 * cookies, sessions, or request body fields.
 */
export interface StorageContext {
  /**
   * Stores a data in an HTTP header.
   * @param data - The data to be stored.
   * @param options - Optional configuration for header storage (e.g., header name, scheme).
   * @returns A promise that resolves when the data is stored, or void.
   */
  storeInHeader?: (
    data: string,
    options?: HeaderStorageOptions
  ) => Promise<void> | void;

  /**
   * Stores a data in a cookie.
   * @param data - The data to be stored.
   * @param options - Optional configuration for cookie storage (e.g., cookie name, attributes).
   * @returns A promise that resolves when the data is stored, or void.
   */
  storeInCookie?: (
    data: string,
    options?: CookieStorageOptions
  ) => Promise<void> | void;

  /**
   * Stores a data in the session under an optional key.
   * @param data - The data to be stored.
   * @param name - An optional name/key under which to store the data in the session.
   * @returns A promise that resolves when the data is stored, or void.
   */
  storeInSession?: (data: string, name?: string) => Promise<void> | void;

  /**
   * Stores a data in the request body under an optional field name.
   * @param data - The data to be stored.
   * @param name - An optional field name under which to store the data in the request body.
   * @returns A promise that resolves when the data is stored, or void.
   */
  storeInBody?: (data: string, name?: string) => Promise<void> | void;

  /**
   * Retrieves a data from an HTTP header.
   * @param options - Optional configuration for header retrieval (e.g., header name, scheme).
   * @returns The data as a string or null if not found, either directly or wrapped in a promise.
   */
  getFromHeader?: (
    options?: HeaderStorageOptions
  ) => Promise<string | null> | string | null;

  /**
   * Retrieves a data from a cookie.
   * @param cookieName - The name of the cookie from which to retrieve the data.
   * @returns The data as a string, undefined if not found, either directly or wrapped in a promise.
   */
  getFromCookie?: (
    cookieName: string
  ) => Promise<string | undefined> | string | undefined;

  /**
   * Retrieves a data from the session by its key/name.
   * @param name - The name/key under which the data is stored in the session.
   * @returns The data as a string, undefined if not found, either directly or wrapped in a promise.
   */
  getFromSession?: (
    name: string
  ) => Promise<string | undefined> | string | undefined;

  /**
   * Retrieves a data from the request body by a specified field name.
   * @param name - The field name under which the data is stored in the request body.
   * @returns The data as a string, undefined if not found, either directly or wrapped in a promise.
   */
  getFromBodyField?: (
    name: string
  ) => Promise<string | undefined> | string | undefined;

  /**
   * Removes a data from a specified cookie.
   * @param cookieName - The name of the cookie from which to remove the data.
   * @returns A promise that resolves when the data is removed, or void.
   */
  removeFromCookie?: (cookieName: string) => Promise<void> | void;

  /**
   * Removes a data from the session by its key/name.
   * @param name - The name/key under which the data is stored in the session.
   * @returns A promise that resolves when the data is removed, or void.
   */
  removeFromSession?: (name: string) => Promise<void> | void;

  encrypt?: (data: string) => Promise<string> | string;
  decrypt?: (data: string) => Promise<string> | string;
}

/**
 * Interface defining the configuration and operations for managing tokens.
 */
export interface TokenHandlerConfig {
  /**
   * The secret key used to sign tokens.
   * Can be a string or a Buffer (in case of asymmetric keys).
   */
  secretKey: string;

  /**
   * Specifies the expiration time for the token.
   * Example formats: "1h", "2d", or number of seconds.
   */
  expiresIn: string | number;

  /**
   * Expected audience value (`aud`) in the token.
   * Can be a string or an array of allowed audiences.
   */
  audience?: string | string[];

  /**
   * Expected issuer (`iss`) of the token.
   * Can be a string or an array of allowed issuers.
   */
  issuer?: string | string[];

  /**
   * Expected subject (`sub`) of the token.
   */
  subject?: string;

  /**
   * Specifies the type of token being handled.
   */
  tokenType?: string;

  /**
   * Generates a new token with the provided payload.
   *
   * @param payload - Data to encode in the token.
   * @returns {string} The generated token.
   * @throws {Error} If the payload is invalid or token creation fails.
   */
  generate?: (payload: any) => string;

  /**
   * Verifies a token and decodes its content.
   *
   * @param {string} token - The token to verify.
   * @returns {Promise<any>} A promise resolving to the decoded token payload.
   * @throws {Error} If token is invalid or expired.
   */
  verify?: (token: string) => Promise<any>;

  /**
   * Stores the token in a designated storage location (e.g., database, cache, cookies).
   *
   * @param {string} token - The token to be stored.
   * @param {any} data - Additional data to be stored with the token.
   * @param {number} expiresIn - Expiration time in seconds.
   * @returns {Promise<void>} A promise that resolves when the token is successfully stored.
   */
  store?: (token: string, data: any, expiresIn: number) => Promise<void>;

  /**
   * Retrieves the token from the specified context (e.g., headers, cookies, local storage).
   *
   * @param {any} context - The context from which to retrieve the token.
   * @returns {Promise<string | null>} A promise that resolves with the retrieved token, or null if not found.
   */
  retrieve?: (context: any) => Promise<string | null>;

  /**
   * Removes the token from the storage (e.g., during logout or token invalidation).
   *
   * @param {any} context - The context containing the token to be removed.
   * @returns {Promise<void>} A promise that resolves when the token is successfully removed.
   */
  remove?: (context: any) => Promise<void>;

  /**
   * Embeds the token in a given context (e.g., HTTP response headers, cookies).
   *
   * @param {any} context - The context in which to embed the token.
   * @param {string} token - The token to be embedded.
   */
  embed?: (context: any, token: string) => void;

  /**
   * Handles token rotation by generating a new token based on an existing one.
   * Useful for refreshing tokens without requiring re-authentication.
   *
   * @param {string} oldToken - The existing token that needs to be rotated.
   * @returns {Promise<string>} A promise that resolves with the new rotated token.
   */
  rotate?: (oldToken: string) => Promise<string>;
}

export interface TokenHandlersConfig {
  access: TokenHandlerConfig;
  refresh?: TokenHandlerConfig;
}
