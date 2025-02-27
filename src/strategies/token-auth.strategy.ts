import * as Soap from "@soapjs/soap";
import { AuthResult, TokenAuthStrategyConfig } from "../types";
import { BaseAuthStrategy } from "./base-auth.strategy";
import {
  MissingTokenError,
  InvalidTokenError,
  UserNotFoundError,
  TokenRotationLimitReachedError,
} from "../errors";
import { SessionHandler } from "../session/session-handler";
import { TokenExpiredError } from "jsonwebtoken";

/**
 * Abstract class defining a token-based authentication strategy.
 * This strategy handles access and refresh tokens, allowing customization of their retrieval,
 * verification, generation, storage, and embedding.
 *
 * @template TContext - The type of the authentication context.
 * @template TUser - The type of the authenticated user.
 */
export abstract class TokenAuthStrategy<
  TContext = unknown,
  TUser = unknown
> extends BaseAuthStrategy<TContext, TUser> {
  constructor(
    protected config: TokenAuthStrategyConfig<TContext, TUser>,
    protected session?: SessionHandler,
    protected logger?: Soap.Logger
  ) {
    super(config, session, logger);
  }

  /**
   * Retrieves an access token from the context.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<string | undefined>} The retrieved access token or undefined if not found.
   */
  protected abstract extractAccessToken(context: TContext): string | undefined;

  /**
   * Retrieves a refresh token from the context.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<string | undefined>} The retrieved refresh token or undefined if not found.
   */
  protected abstract extractRefreshToken(context: TContext): string | undefined;

  /**
   * Verifies an access token and returns its decoded payload.
   *
   * @param {string} token - The access token to verify.
   * @returns {Promise<any>} The decoded token payload.
   */
  protected abstract verifyAccessToken(token: string): Promise<any>;

  /**
   * Verifies a refresh token and returns its decoded payload.
   *
   * @param {string} token - The refresh token to verify.
   * @returns {Promise<any>} The decoded token payload.
   */
  protected abstract verifyRefreshToken(token: string): Promise<any>;

  /**
   * Generates a new access token for the given user.
   *
   * @param {string} token - The access token to store.
   * @param {TContext} context - The authentication context.
   * @returns {Promise<string>} The generated access token.
   */
  protected abstract generateAccessToken(
    data: TUser,
    context: TContext
  ): Promise<string>;

  /**
   * Generates a new refresh token for the given user.
   *
   * @param {string} token - The access token to store.
   * @param {TContext} context - The authentication context.
   * @returns {Promise<string>} The generated refresh token.
   */
  protected abstract generateRefreshToken(
    data: TUser,
    context: TContext
  ): Promise<string>;

  /**
   * Stores an access token in the designated storage (e.g., database, session, cookies).
   *
   * @param {string} token - The access token to store.
   */
  protected abstract storeAccessToken(token: string): Promise<void>;

  /**
   * Stores a refresh token in the designated storage.
   *
   * @param {string} token - The refresh token to store.
   */
  protected abstract storeRefreshToken(token: string): Promise<void>;

  /**
   * Removes an access token in the designated storage (e.g., database, session, cookies) and
   * context
   *
   * @param {string} token - The access token to store.
   * @param {TContext} context - The authentication context.
   */
  protected abstract invalidateAccessToken(
    token: string,
    context?: TContext
  ): Promise<void>;

  /**
   * Removes a refresh token in the designated storage and
   * context
   *
   * @param {string} token - The refresh token to store.
   * @param {TContext} context - The authentication context.
   */
  protected abstract invalidateRefreshToken(
    token: string,
    context?: TContext
  ): Promise<void>;

  /**
   * Embeds an access token into the response context.
   *
   * @param {string} token - The access token.
   * @param {TContext} context - The authentication context.
   */
  protected abstract embedAccessToken(token: string, context: TContext): void;

  /**
   * Embeds a refresh token into the response context.
   *
   * @param {string} token - The refresh token.
   * @param {TContext} context - The authentication context.
   */
  protected abstract embedRefreshToken(token: string, context: TContext): void;

  /**
   * Retrieves user information based on provided payload.
   * Must be implemented by specific strategies.
   *
   * @param {unknown} payload.
   * @returns {Promise<TUser | null>} The user data if found, otherwise null.
   */
  protected async fetchUser(payload: unknown): Promise<TUser | null> {
    if (this.config?.user?.fetchUser) {
      return this.config.user.fetchUser(payload);
    }

    throw new Soap.NotImplementedError("fetchUser");
  }

  /**
   * Authenticates a user by verifying the provided access token.
   * If the access token is expired and a refresh token is available, it attempts token rotation.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<AuthResult<TUser>>} The authentication result containing the user and tokens.
   */
  async authenticate(context: TContext): Promise<AuthResult<TUser>> {
    try {
      await this.rateLimit?.checkRateLimit(context);

      const accessToken = this.extractAccessToken(context);
      const refreshToken = this.extractRefreshToken(context);

      if (accessToken) {
        const { user, isExpired } = await this.verifyAndFetchUser(accessToken);

        if (user) {
          await this.role?.isAuthorized(user);
          return { user, tokens: { accessToken } };
        }

        if (!isExpired) {
          throw new InvalidTokenError("Access");
        }

        this.logger?.warn("Access token expired, attempting refresh...");
      }

      if (!this.config.refreshToken) {
        throw new MissingTokenError("Access");
      }

      if (!refreshToken) {
        throw new MissingTokenError("Refresh");
      }

      return this.refreshTokens(context);
    } catch (error) {
      await this.onFailure("authenticate", { error });
      throw error;
    }
  }

  private async verifyAndFetchUser(
    accessToken: string
  ): Promise<{ user: TUser | null; isExpired: boolean }> {
    try {
      const decoded = await this.verifyAccessToken(accessToken);
      const user = await this.fetchUser(decoded);

      if (!user) {
        throw new UserNotFoundError();
      }

      return { user, isExpired: false };
    } catch (error) {
      this.logger?.error(error);

      if (error instanceof TokenExpiredError) {
        return { user: null, isExpired: true };
      }

      return { user: null, isExpired: false };
    }
  }

  /**
   * Rotates refresh and access tokens by verifying the refresh token and issuing new ones.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<{ accessToken: string; refreshToken?: string }>} The new access and refresh tokens.
   */
  async refreshTokens(
    context: TContext,
    existingUser?: TUser
  ): Promise<AuthResult<TUser>> {
    try {
      if (!this.config.refreshToken) {
        throw new Error("Refresh tokens are not enabled.");
      }

      const refreshToken = this.extractRefreshToken(context);

      if (!refreshToken) {
        throw new MissingTokenError("Refresh");
      }

      const payload = await this.verifyRefreshToken(refreshToken);

      if (!payload) {
        throw new InvalidTokenError("Refresh");
      }

      if (this.config.refreshToken.absoluteExpiry) {
        const { payloadField, onExpiry } =
          this.config.refreshToken.absoluteExpiry;
        const field = payloadField || "absoluteExp";
        const maxTime = payload[field];

        if (maxTime && Date.now() / 1000 > maxTime) {
          this.logger?.warn(`Absolute expiry exceeded for refresh token.`);

          switch (onExpiry) {
            case "logout": {
              await this.session?.logoutSession(context);
              await this.invalidateRefreshToken(refreshToken, context);
              throw new InvalidTokenError("Refresh");
            }
            case "error":
              throw new InvalidTokenError("Refresh");
            case "ignore":
              break;
          }
        }
      }

      let user = existingUser ?? (await this.fetchUser(payload));

      if (!user) {
        throw new UserNotFoundError();
      }

      await this.role?.isAuthorized(user);

      const newTokens = await this.issueTokens(user, context, true);

      return {
        user,
        tokens: newTokens,
      };
    } catch (error) {
      await this.onFailure("refresh_tokens", {
        error,
      });

      throw error;
    }
  }

  async issueTokens(user: TUser, context: TContext, rotate?: boolean) {
    try {
      const accessToken = await this.generateAccessToken(user, context);
      let refreshToken;

      if (this.config.refreshToken) {
        refreshToken = await this.generateRefreshToken(user, context);

        if (rotate && this.config?.refreshToken?.rotation) {
          const oldRefreshToken = this.extractRefreshToken(context);
          refreshToken = await this.rotateToken(oldRefreshToken, user, context);
        } else if (this.generateRefreshToken) {
          refreshToken = await this.generateRefreshToken(user, context);
        }
      }

      await this.storeAccessToken(accessToken);
      this.embedAccessToken(accessToken, context);

      if (refreshToken) {
        await this.storeRefreshToken(refreshToken);
        this.embedRefreshToken(refreshToken, context);
      }

      this.logger?.info(`JWT issued successfully`);

      return { accessToken, refreshToken };
    } catch (error) {
      await this.onFailure("issueTokens", {
        context,
        error,
      });
      throw error;
    }
  }

  protected async rotateToken(
    refreshToken: string,
    user: TUser,
    context: TContext
  ) {
    let rotationCount = 0;
    let newRefreshToken;
    if (this.config.refreshToken.rotation.getRotationCount) {
      rotationCount = await this.config.refreshToken.rotation.getRotationCount(
        refreshToken,
        user,
        context
      );
    }

    if (
      this.config.refreshToken.rotation.isLimitReached(
        rotationCount,
        this.config.refreshToken.rotation.maxRotations,
        user,
        context
      )
    ) {
      throw new TokenRotationLimitReachedError();
    }

    if (this.config.refreshToken.rotation.rotateToken) {
      const result = await this.config.refreshToken.rotation.rotateToken(
        refreshToken,
        user,
        context
      );
      newRefreshToken = result.newToken;

      if (typeof result.newRotationCount === "number") {
        rotationCount = result.newRotationCount;
      } else {
        rotationCount += 1;
      }

      if (this.config.refreshToken.rotation.afterRotation) {
        await this.config.refreshToken.rotation.afterRotation(
          refreshToken,
          newRefreshToken,
          user,
          context,
          rotationCount
        );
      }
    } else {
      this.logger?.warn("Rotation enabled but rotateToken not provided.");
    }

    return newRefreshToken;
  }
}
