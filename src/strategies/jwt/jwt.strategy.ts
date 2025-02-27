import jwt from "jsonwebtoken";
import * as Soap from "@soapjs/soap";
import { TokenAuthStrategy } from "../token-auth.strategy";
import { UndefinedTokenError, UndefinedTokenSecretError } from "../../errors";
import { JwtTools } from "./jwt.tools";
import { TokenAuthStrategyConfig, TokenConfig } from "../../types";

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
   * @param {TokenAuthStrategyConfig<TContext, TUser>} config - Configuration for JWT strategy.
   * @param {Soap.Logger} [logger] - Logger instance.
   * @throws {UndefinedTokenSecretError} If the secret key is missing for access or refresh tokens.
   */
  constructor(
    protected config: TokenAuthStrategyConfig<TContext, TUser>,
    protected logger?: Soap.Logger
  ) {
    if (!config.accessToken.issuer.secretKey) {
      throw new UndefinedTokenSecretError("Access");
    }
    if (config.refreshToken && !config.refreshToken.issuer.secretKey) {
      throw new UndefinedTokenSecretError("Refresh");
    }

    super(config, null, logger);

    this.accessTokenConfig = JwtTools.prepareAccessTokenConfig(
      config.accessToken
    );
    this.refreshTokenConfig = JwtTools.prepareRefreshTokenConfig(
      config.refreshToken
    );

    this.logger?.info("JWTStrategy initialized with provided configurations.");
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
      throw error;
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
      error;
    }
  }

  /**
   * Generates a new access token.
   *
   * @returns {Promise<string>} The generated access token.
   */
  protected async generateAccessToken(
    user: TUser,
    context: TContext
  ): Promise<string> {
    const payload = this.buildAccessTokenPayload(user, context);
    return Promise.resolve(
      JwtTools.generateAccessToken(payload, this.accessTokenConfig)
    );
  }

  /**
   * Generates a new refresh token.
   *
   * @returns {Promise<string>} The generated refresh token.
   */
  protected async generateRefreshToken(
    user: TUser,
    context: TContext
  ): Promise<string> {
    const payload = this.buildAccessTokenPayload(user, context);
    return Promise.resolve(
      JwtTools.generateRefreshToken(payload, this.refreshTokenConfig)
    );
  }

  protected async storeAccessToken(token: string): Promise<void> {
    if (this.accessTokenConfig.persistence.store) {
      await this.accessTokenConfig.persistence.store(
        token,
        null,
        this.accessTokenConfig.issuer.options.expiresIn
      );
    }
  }

  protected async storeRefreshToken(token: string): Promise<void> {
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
      JwtTools.setDefaultJwtHeader(token, context);
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
      JwtTools.setDefaultJwtCookie(token, context);
    }
  }

  /**
   * Retrieves the access token from the context.
   *
   * @param {TContext} context - The authentication context.
   * @returns {string | undefined} The access token, if available.
   */
  protected extractAccessToken(context: TContext): string | undefined {
    if (this.accessTokenConfig.extract) {
      return this.accessTokenConfig.extract(context);
    } else {
      return (
        (context as any).req?.headers?.authorization?.split(" ")[1] ||
        (context as any).request?.headers?.authorization?.split(" ")[1] ||
        (context as any).headers?.authorization?.split(" ")[1]
      );
    }
  }

  /**
   * Retrieves the refresh token from the context.
   *
   * @param {TContext} context - The authentication context.
   * @returns {string | undefined} The refresh token, if available.
   */
  protected extractRefreshToken(context: TContext): string | undefined {
    if (this.refreshTokenConfig.extract) {
      return this.refreshTokenConfig.extract(context);
    }

    return (
      (context as any).req?.cookies?.refreshToken ||
      (context as any).request?.cookies?.refreshToken ||
      (context as any).cookies?.refreshToken
    );
  }

  protected buildAccessTokenPayload(user: TUser, context: TContext) {
    return this.config.accessToken.issuer.buildPayload
      ? this.config.accessToken.issuer.buildPayload(user, context)
      : { id: (user as any).id, email: (user as any).email };
  }

  protected buildRefreshTokenPayload(user: TUser, context: TContext) {
    return this.config.refreshToken.issuer.buildPayload
      ? this.config.refreshToken.issuer.buildPayload(user, context)
      : { id: (user as any).id };
  }

  /**
   * Logs out the user by invalidating the refresh token.
   *
   * @param {TContext} context - The authentication context.
   */
  async invalidateRefreshToken(
    token: string,
    context?: TContext
  ): Promise<void> {
    const refreshToken = token || (await this.extractRefreshToken(context));

    if (refreshToken) {
      await this.refreshTokenConfig.persistence?.remove?.(refreshToken);

      if (context) {
        JwtTools.clearDefaultJwtCookie(context);
        JwtTools.clearDefaultJwtHeader(context);
      }

      this.logger?.info(`Refresh token invalidated: ${refreshToken}`);
    }
  }

  protected async invalidateAccessToken(
    token: string,
    context?: TContext
  ): Promise<void> {
    const accessToken = token || (await this.extractAccessToken(context));

    if (accessToken) {
      await this.accessTokenConfig.persistence?.remove?.(accessToken);

      if (context) {
        JwtTools.clearDefaultJwtCookie(context);
        JwtTools.clearDefaultJwtHeader(context);
      }

      this.logger?.info(`Access token invalidated: ${accessToken}`);
    }
  }
}
