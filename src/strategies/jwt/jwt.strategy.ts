import jwt from "jsonwebtoken";
import * as Soap from "@soapjs/soap";
import { TokenAuthStrategy } from "../token-auth.strategy";
import {
  InvalidTokenError,
  UndefinedTokenError,
  UndefinedTokenSecretError,
} from "../../errors";
import { JwtConfig } from "./jwt.types";
import {
  clearDefaultJwtCookie,
  clearDefaultJwtHeader,
  prepareAccessTokenConfig,
  prepareRefreshTokenConfig,
  setDefaultJwtCookie,
  setDefaultJwtHeader,
} from "./jwt.tools";
import { SessionHandler } from "../../session/session-handler";
import { TokenConfig } from "../../types";

/**
 * JWT-based authentication strategy.
 *
 * Handles token-based authentication with access and refresh tokens.
 * Implements best security practices including token rotation and blacklist support.
 *
 * @template TContext - The type of the authentication context.
 * @template TUser - The type of the authenticated user.
 */
export class JwtStrategy<
  TContext = unknown,
  TUser = unknown
> extends TokenAuthStrategy<TContext, TUser> {
  protected accessTokenConfig: TokenConfig<TContext>;
  protected refreshTokenConfig: TokenConfig<TContext>;

  /**
   * Initializes the JWT authentication strategy.
   *
   * @param {JwtConfig<TContext, TUser>} config - Configuration for JWT strategy.
   * @param {SessionHandler} [session] - Optional session handler.
   * @param {Soap.Logger} [logger] - Logger instance.
   * @throws {UndefinedTokenSecretError} If the secret key is missing for access or refresh tokens.
   */
  constructor(
    protected config: JwtConfig<TContext, TUser>,
    protected session?: SessionHandler,
    protected logger?: Soap.Logger
  ) {
    if (!config.accessToken.issuer.secretKey) {
      throw new UndefinedTokenSecretError("Access");
    }
    if (config.refreshToken && !config.refreshToken.issuer.secretKey) {
      throw new UndefinedTokenSecretError("Refresh");
    }

    super(config, session, logger);

    this.accessTokenConfig = prepareAccessTokenConfig(config.accessToken);
    this.refreshTokenConfig = prepareRefreshTokenConfig(config.refreshToken);
    this.logger?.info("JWTStrategy initialized with provided configurations.");
  }

  protected async invalidateRefreshToken(token: string): Promise<void> {
    await this.refreshTokenConfig.persistence.remove?.(token);
  }

  /**
   * Verifies the access token.
   *
   * @param {string} token - The access token to verify.
   * @returns {Promise<any>} The decoded token payload.
   * @throws {InvalidTokenError} If the token is invalid or expired.
   */
  protected verifyAccessToken(token: string): Promise<any> {
    try {
      if (!token) throw new UndefinedTokenError("Access");
      if (!this.accessTokenConfig.issuer.secretKey)
        throw new UndefinedTokenSecretError("Access");

      return new Promise((resolve, reject) => {
        jwt.verify(
          token,
          this.accessTokenConfig.issuer.secretKey,
          this.accessTokenConfig.verifier.options,
          (err, payload) => {
            if (err) reject(err);
            else resolve(payload);
          }
        );
      });
    } catch (error) {
      this.logger?.error("JWT verification failed:", error);
      throw new InvalidTokenError("Access");
    }
  }

  /**
   * Verifies the refresh token, checking against a blacklist.
   *
   * @param {string} token - The refresh token to verify.
   * @returns {Promise<any>} The decoded token payload.
   * @throws {InvalidTokenError} If the token is invalid, expired, or revoked.
   */
  protected verifyRefreshToken(token: string): Promise<any> {
    try {
      if (!token) throw new UndefinedTokenError("Refresh");
      if (!this.refreshTokenConfig.issuer.secretKey)
        throw new UndefinedTokenSecretError("Refresh");

      return new Promise((resolve, reject) => {
        jwt.verify(
          token,
          this.refreshTokenConfig.issuer.secretKey,
          this.refreshTokenConfig.verifier.options,
          (err, payload) => {
            if (err) reject(err);
            else resolve(payload);
          }
        );
      });
    } catch (error) {
      this.logger?.error("JWT verification failed:", error);
      throw new InvalidTokenError("Refresh");
    }
  }

  /**
   * Generates a new access token.
   *
   * @param {any} payload - The payload to encode.
   * @returns {Promise<string>} The generated access token.
   */
  protected generateAccessToken(payload: any): Promise<string> {
    const options = this.accessTokenConfig.issuer.options || {};
    return jwt.sign(payload, this.accessTokenConfig.issuer.secretKey, {
      ...options,
      jti: payload.jti || crypto.randomUUID(),
    });
  }

  /**
   * Generates a new refresh token.
   *
   * @returns {Promise<string>} The generated refresh token.
   */
  protected generateRefreshToken(payload: any): Promise<string> {
    const options = this.refreshTokenConfig.issuer.options || {};
    return jwt.sign(payload, this.refreshTokenConfig.issuer.secretKey, {
      ...options,
      jti: payload.jti || crypto.randomUUID(),
    });
  }

  protected async storeAccessToken(
    token: string,
    context: TContext
  ): Promise<void> {
    if (this.accessTokenConfig.persistence.store) {
      await this.accessTokenConfig.persistence.store(
        token,
        null,
        this.accessTokenConfig.issuer.options.expiresIn
      );
    }
  }

  protected async storeRefreshToken(
    token: string,
    context: TContext
  ): Promise<void> {
    if (this.refreshTokenConfig.persistence.store) {
      await this.refreshTokenConfig.persistence.store(
        token,
        null,
        this.refreshTokenConfig.issuer.options.expiresIn
      );
    }
  }

  /**
   * Embeds the access token into the response headers.
   *
   * @param {string} token - The access token to embed.
   * @param {TContext} context - The authentication context.
   */
  protected embedAccessToken(token: string, context: TContext): void {
    if (this.accessTokenConfig.embed) {
      this.accessTokenConfig.embed(context, token);
    } else {
      setDefaultJwtHeader(token, context);
    }
  }

  /**
   * Embeds the refresh token into cookies for secure storage.
   *
   * @param {string} token - The refresh token to embed.
   * @param {TContext} context - The authentication context.
   */
  protected embedRefreshToken(token: string, context: TContext): void {
    if (this.refreshTokenConfig.embed) {
      this.refreshTokenConfig.embed(context, token);
    } else {
      setDefaultJwtCookie(token, context);
    }
  }

  /**
   * Retrieves the access token from the context.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<string | undefined>} The access token, if available.
   */
  protected retrieveAccessToken(
    context: TContext
  ): Promise<string | undefined> {
    if (this.accessTokenConfig.retrieve) {
      return this.accessTokenConfig.retrieve(context);
    } else {
      return (
        (context as any).req.headers.authorization?.split(" ")[1] ||
        (context as any).request.headers.authorization?.split(" ")[1] ||
        (context as any).headers.authorization?.split(" ")[1]
      );
    }
  }

  /**
   * Retrieves the refresh token from the context.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<string | undefined>} The refresh token, if available.
   */
  protected retrieveRefreshToken(
    context: TContext
  ): Promise<string | undefined> {
    if (this.refreshTokenConfig.retrieve) {
      return this.refreshTokenConfig.retrieve(context);
    }

    return (
      (context as any).req.cookies?.refreshToken ||
      (context as any).request.cookies?.refreshToken ||
      (context as any).cookies.refreshToken
    );
  }

  /**
   * Logs out the user by invalidating the refresh token.
   *
   * @param {TContext} context - The authentication context.
   */
  async logout(context: TContext): Promise<void> {
    const refreshToken = await this.retrieveRefreshToken(context);
    if (refreshToken) {
      await this.invalidateRefreshToken(refreshToken);
      clearDefaultJwtCookie(context);
      clearDefaultJwtHeader(context);
    }
  }
}
