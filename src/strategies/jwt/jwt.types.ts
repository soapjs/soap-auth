import { TokenBasedAuthStrategyConfig, TokenHandlerConfig } from "../../types";

/**
 * Options for verifying a token.
 */
export interface JwtVerifyOptions {
  /**
   * List of allowed algorithms for token verification.
   * Example: ["HS256", "RS256"]
   */
  algorithms?: string[];

  /**
   * Specifies the minimum time before which the token is considered valid.
   * Example formats: "10m" or number of seconds.
   */
  notBefore?: string | number;

  /**
   * Tolerance in seconds for clock skew when verifying expiration and notBefore claims.
   */
  clockTolerance?: number;

  /**
   * Whether to ignore token expiration during verification.
   * If `true`, the token will be accepted even if expired.
   */
  ignoreExpiration?: boolean;

  /**
   * Whether to ignore the `nbf` (not before) claim during verification.
   */
  ignoreNotBefore?: boolean;

  /**
   * If `true`, returns the decoded token with header, payload, and signature.
   */
  complete?: boolean;

  /**
   * A custom timestamp (in seconds) for verification purposes.
   * Used mainly for testing.
   */
  clockTimestamp?: number;

  /**
   * Rest
   */
  [key: string]: any;
}

/**
 * Options for signing a JWT token.
 */
export interface JwtSignOptions {
  /**
   * The algorithm to use for signing the token.
   * Default: "HS256"
   */
  algorithm?:
    | "HS256"
    | "HS384"
    | "HS512"
    | "RS256"
    | "RS384"
    | "RS512"
    | "ES256"
    | "ES384"
    | "ES512"
    | "PS256"
    | "PS384"
    | "PS512"
    | "none";

  /**
   * Specifies the time before which the token should not be accepted for processing.
   * Example formats: "10m" or number of seconds.
   */
  notBefore?: string | number;

  /**
   * The JWT ID (`jti`) claim.
   */
  jwtid?: string;

  /**
   * A timestamp in seconds since epoch that represents the "iat" (issued at) claim.
   * Default: current time.
   */
  issuedAt?: number;

  /**
   * A function to be used to transform the payload before signing.
   * Example use: adding or removing fields dynamically.
   */
  mutatePayload?: (payload: Record<string, any>) => Record<string, any>;

  /**
   * If `true`, the "iat" (issued at) claim will not be included in the payload.
   * Default: `false`
   */
  noTimestamp?: boolean;

  /**
   * A passphrase for encrypted private keys (used in asymmetric algorithms).
   */
  keyid?: string;

  /**
   * If `true`, the JWT will be signed without the payload being a JSON object.
   * Default: `false`
   */
  allowUnsafe?: boolean;
}

export type JwtAccessTokenHandlerConfig = {
  verifyOptions?: JwtVerifyOptions;
  signOptions: JwtSignOptions;
} & TokenHandlerConfig;

export type JwtRefreshTokenHandlerConfig = {
  verifyOptions?: JwtVerifyOptions;
  signOptions: JwtSignOptions;
} & TokenHandlerConfig;

export type JwtConfig<TContext = unknown, TUser = unknown> = {
  access: JwtAccessTokenHandlerConfig;
  refresh?: JwtRefreshTokenHandlerConfig;
} & TokenBasedAuthStrategyConfig<TContext, TUser>;
