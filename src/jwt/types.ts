/**
 * Configuration for JWT (JSON Web Token)
 * @typedef {Object} TokenConfig
 * @property {string} secretOrKey - Secret or key for signing JWTs.
 * @property {string|number} expiresIn - Expiration time for the JWT.
 * @property {string} [refreshSecretOrKey] - Optional secret or key for signing refresh JWTs.
 * @property {string|number} [refreshExpiresIn] - Expiration time for the refresh JWT.
 * @property {function} [dataProvider] - Function to fetch additional data for the token.
 * @property {TokenStorageConfig} [storage] - Configuration for storing the access token.
 * @property {TokenStorageConfig} [refreshStorage] - Configuration for storing the refresh token.
 */
export interface TokenConfig {
  dataProvider?: (decoded: any) => any;
  secretOrKey: string;
  expiresIn: string | number;
  issuer?: string;
  audience?: string;
  algorithms?: string[];
  ignoreExpiration?: boolean;
  refreshSecretOrKey?: string;
  refreshExpiresIn?: string | number;
  storage?: TokenStorageConfig;
  refreshStorage?: TokenStorageConfig;
}

/**
 * Configuration for storing tokens
 * @typedef {Object} TokenStorageConfig
 * @property {"header"|"cookie"|"query"|"body"|"database"|"session"} method - Method of storing the token.
 * @property {TokenHeaderOptions} [headerOptions] - Options for header storage.
 * @property {TokenCookieOptions} [cookieOptions] - Options for cookie storage.
 * @property {TokenBodyOptions} [bodyOptions] - Options for body storage.
 * @property {TokenQueryOptions} [queryOptions] - Options for query storage.
 * @property {TokenSessionOptions} [sessionOptions] - Options for session storage.
 */
export interface TokenStorageConfig {
  method: "header" | "cookie" | "query" | "body" | "database" | "session";
  headerOptions?: TokenHeaderOptions;
  cookieOptions?: TokenCookieOptions;
  bodyOptions?: TokenBodyOptions;
  queryOptions?: TokenQueryOptions;
  sessionOptions?: TokenSessionOptions;
}

/**
 * Options for cookie storage
 * @typedef {Object} TokenCookieOptions
 * @property {string} cookieName - Name of the cookie.
 * @property {boolean} httpOnly - Whether the cookie is HTTP only.
 * @property {boolean} secure - Whether the cookie is secure.
 * @property {"strict"|"lax"|"none"} [sameSite] - SameSite policy for the cookie.
 * @property {number} [maxAge] - Max age for the cookie.
 */
export interface TokenCookieOptions {
  cookieName: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite?: "strict" | "lax" | "none";
  maxAge?: number;
  extractor: (cookieName: string) => string;
}

/**
 * Options for header storage
 * @typedef {Object} TokenHeaderOptions
 * @property {string} headerName - Name of the header.
 * @property {string} [scheme] - Scheme for the token (e.g., Bearer).
 */
export interface TokenHeaderOptions {
  headerName: string;
  scheme?: string;
  extractor: (scheme: string) => string;
}

/**
 * Options for body storage
 * @typedef {Object} TokenBodyOptions
 * @property {string} name - Name of the body parameter.
 */
export interface TokenBodyOptions {
  name: string;
  extractor: (name: string) => string;
}

/**
 * Options for query storage
 * @typedef {Object} TokenQueryOptions
 * @property {string} name - Name of the query parameter.
 */
export interface TokenQueryOptions {
  name: string;
  extractor: (name: string) => string;
}

/**
 * Options for session storage
 * @typedef {Object} TokenSessionOptions
 * @property {string} name - Name of the session attribute.
 */
export interface TokenSessionOptions {
  name: string;
  extractor: (name: string) => string;
}

/**
 * Options for database storage
 * @typedef {Object} TokenDatabaseOptions
 */
export interface TokenDatabaseOptions {
  extractor: (...args: unknown[]) => Promise<string>;
}
