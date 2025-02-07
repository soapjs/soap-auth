import * as Soap from "@soapjs/soap";
import { AuthResult, TokenBasedAuthStrategyConfig } from "../types";
import { BaseAuthStrategy } from "./base-auth.strategy";
import { TokenConfig } from "../types";
import {
  MissingTokenError,
  InvalidTokenError,
  AuthError,
  UserNotFoundError,
} from "../errors";
import { SessionHandler } from "../session/session-handler";

/**
 * Token-based authentication strategy that supports both access and refresh tokens.
 *
 * @template TContext - The type of the authentication context.
 * @template TUser - The type of the authenticated user.
 */
export abstract class TokenBasedAuthStrategy<
  TContext = unknown,
  TUser = unknown
> extends BaseAuthStrategy<TContext, TUser> {
  /**
   * Constructs an instance of TokenBasedAuthStrategy.
   *
   * @param {TokenBasedAuthStrategyConfig<TContext, TUser>} config - Configuration options for the strategy.
   * @param {TokenConfig} accessTokenConfig - Handler for access tokens.
   * @param {TokenConfig} [refreshTokenConfig] - Optional handler for refresh tokens.
   * @param {SessionHandler} [session] - Optional session management configuration.
   * @param {Soap.Logger} [logger] - Optional logger instance.
   */
  constructor(
    protected config: TokenBasedAuthStrategyConfig<TContext, TUser>,
    protected accessTokenConfig?: TokenConfig,
    protected refreshTokenConfig?: TokenConfig,
    protected session?: SessionHandler,
    protected logger?: Soap.Logger
  ) {
    super(config, session, logger);
  }

  /**
   * Abstract method to retrieve the user based on decoded token data.
   *
   * @param {any} decodedToken - Decoded token payload.
   * @returns {Promise<TUser | null>} A promise resolving to the authenticated user or null.
   */
  protected retrieveUser(decodedToken: any): Promise<TUser | null> {
    return this.config.login.retrieveUserData(decodedToken);
  }

  /**
   * Authenticates a user by verifying the provided access token.
   * If the access token is expired and a refresh token is available, it will attempt token rotation.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<AuthResult<TUser>>} The authentication result containing the user and access token.
   * @throws {MissingTokenError} If no valid tokens are provided.
   * @throws {InvalidTokenError} If token verification fails.
   */
  async authenticate(context: TContext): Promise<AuthResult<TUser>> {
    try {
      let accessToken = await this.accessTokenConfig.retrieve?.(context);
      let refreshToken;

      await this.checkRateLimit(context);

      if (accessToken) {
        try {
          const decoded = await this.accessTokenConfig.verify?.(accessToken);
          const user = await this.retrieveUser(decoded);
          if (!user) {
            throw new UserNotFoundError();
          }
          await this.isAuthorized(user);
          return { user, tokens: { accessToken } };
        } catch (error) {
          this.logger?.warn(
            "Access token is invalid or expired, trying refresh token..."
          );
        }
      }

      if (this.refreshTokenConfig) {
        // Attempt to use refresh token if access token is expired or missing
        refreshToken = await this.refreshTokenConfig?.retrieve?.(context);
        if (!refreshToken) {
          throw new MissingTokenError("Refresh");
        }

        accessToken = await this.refreshTokenConfig?.rotate?.(refreshToken);

        if (!accessToken) {
          throw new MissingTokenError("Access");
        }
      }

      this.accessTokenConfig.embed?.(context, accessToken);

      const decoded = await this.accessTokenConfig.verify?.(accessToken);
      const user = await this.retrieveUser(decoded);

      if (!user) {
        throw new UserNotFoundError();
      }

      await this.isAuthorized(user);
      return { user, tokens: { accessToken, refreshToken } };
    } catch (error) {
      this.logger?.error("Authentication failed:", error);
      throw new AuthError(error, "Authentication failed.");
    }
  }

  /**
   * Logs out the user by removing access and refresh tokens from storage.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<void>} A promise resolving when logout is complete.
   */
  async logout(context: TContext): Promise<void> {
    try {
      await this.accessTokenConfig.remove?.(context);
      if (this.refreshTokenConfig) {
        await this.refreshTokenConfig.remove?.(context);
      }
      await this.config.logout.onSuccess?.(context);
      this.logger?.info("User logged out successfully.");
    } catch (error) {
      this.logger?.error("Error during logout:", error);
      await this.config.logout.onFailure?.({ context, error });
      throw new AuthError(error, "Logout process failed.");
    }
  }

  /**
   * Generates and stores new tokens for the given user.
   *
   * @param {TUser} user - The authenticated user.
   * @param {TContext} context - The authentication context.
   * @returns {Promise<{ accessToken: string; refreshToken?: string }>} A promise resolving with new tokens.
   */
  async generateTokens(
    user: TUser,
    context: TContext
  ): Promise<{ accessToken: string; refreshToken?: string }> {
    const payload = { userId: (user as any).id, roles: (user as any).roles };

    const accessToken = this.accessTokenConfig.generate?.(payload);
    if (!accessToken) throw new Error("Failed to generate access token.");

    await this.accessTokenConfig.store?.(
      accessToken,
      user,
      +this.accessTokenConfig.expiresIn
    );
    this.accessTokenConfig.embed?.(context, accessToken);

    let refreshToken;
    if (this.refreshTokenConfig) {
      refreshToken = this.refreshTokenConfig.generate?.(payload);
      if (refreshToken) {
        await this.refreshTokenConfig.store?.(
          refreshToken,
          user,
          +this.refreshTokenConfig.expiresIn
        );
        this.refreshTokenConfig.embed?.(context, refreshToken);
      }
    }

    return { accessToken, refreshToken };
  }

  /**
   * Handles token rotation by verifying the refresh token and issuing new access/refresh tokens.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<{ accessToken: string; refreshToken?: string }>} The new access and optional refresh tokens.
   * @throws {InvalidTokenError} If refresh token is invalid or expired.
   */
  async rotateToken(
    context: TContext
  ): Promise<{ accessToken: string; refreshToken?: string }> {
    try {
      if (!this.refreshTokenConfig) {
        throw new Error("Refresh token handler is not configured.");
      }

      const refreshToken = await this.refreshTokenConfig.retrieve?.(context);
      if (!refreshToken) {
        throw new MissingTokenError("Refresh");
      }

      const newAccessToken = await this.refreshTokenConfig.rotate?.(
        refreshToken
      );
      this.accessTokenConfig.embed?.(context, newAccessToken);

      return { accessToken: newAccessToken, refreshToken };
    } catch (error) {
      this.logger?.error("Token rotation failed:", error);
      throw new InvalidTokenError("Refresh");
    }
  }

  async isTokenExpired(token: string): Promise<boolean> {
    try {
      const decoded = JSON.parse(
        Buffer.from(token.split(".")[1], "base64").toString()
      );
      if (!decoded.exp) return false;

      const currentTime = Math.floor(Date.now() / 1000);
      return decoded.exp < currentTime;
    } catch (error) {
      this.logger?.warn("Failed to decode token:", error);
      return false;
    }
  }
}
