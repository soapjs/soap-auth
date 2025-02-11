import * as Soap from "@soapjs/soap";
import { AuthResult, TokenAuthStrategyConfig } from "../types";
import { BaseAuthStrategy } from "./base-auth.strategy";
import {
  MissingTokenError,
  InvalidTokenError,
  AuthError,
  UserNotFoundError,
} from "../errors";
import { SessionHandler } from "../session/session-handler";

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
  protected abstract retrieveAccessToken(
    context: TContext
  ): Promise<string | undefined>;

  /**
   * Retrieves a refresh token from the context.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<string | undefined>} The retrieved refresh token or undefined if not found.
   */
  protected abstract retrieveRefreshToken(
    context: TContext
  ): Promise<string | undefined>;

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
   * @param {any} payload - The token payload (e.g., user ID, roles).
   * @returns {Promise<string>} The generated access token.
   */
  protected abstract generateAccessToken(payload: any): Promise<string>;

  /**
   * Generates a new refresh token for the given user.
   *
   * @param {any} payload - The token payload (e.g., user ID).
   * @returns {Promise<string>} The generated refresh token.
   */
  protected abstract generateRefreshToken(payload: any): Promise<string>;

  /**
   * Stores an access token in the designated storage (e.g., database, session, cookies).
   *
   * @param {string} token - The access token to store.
   * @param {TContext} context - The authentication context.
   */
  protected abstract storeAccessToken(
    token: string,
    context: TContext
  ): Promise<void>;

  /**
   * Stores a refresh token in the designated storage.
   *
   * @param {string} token - The refresh token to store.
   * @param {TContext} context - The authentication context.
   */
  protected abstract storeRefreshToken(
    token: string,
    context: TContext
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
   * Authenticates a user by verifying the provided access token.
   * If the access token is expired and a refresh token is available, it attempts token rotation.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<AuthResult<TUser>>} The authentication result containing the user and tokens.
   * @throws {MissingTokenError} If no valid tokens are provided.
   * @throws {InvalidTokenError} If token verification fails.
   */
  async authenticate(context: TContext): Promise<AuthResult<TUser>> {
    try {
      let accessToken = await this.retrieveAccessToken(context);
      let refreshToken;

      await this.checkRateLimit(context);

      if (accessToken) {
        try {
          const decoded = await this.verifyAccessToken(accessToken);
          const user = await this.config.user.getUserData(decoded);
          if (!user) throw new UserNotFoundError();
          await this.isAuthorized(user);
          return { user, tokens: { accessToken } };
        } catch (error) {
          this.logger?.warn(
            "Access token is invalid or expired, trying refresh token..."
          );
        }
      }

      refreshToken = await this.retrieveRefreshToken(context);
      if (!refreshToken) throw new MissingTokenError("Refresh");

      const newTokens = await this.rotateTokens(context);
      accessToken = newTokens.accessToken;
      refreshToken = newTokens.refreshToken;

      if (!accessToken) throw new MissingTokenError("Access");

      const decoded = await this.verifyAccessToken(accessToken);
      const user = await this.config.user.getUserData(decoded);
      if (!user) throw new UserNotFoundError();

      await this.isAuthorized(user);
      return { user, tokens: { accessToken, refreshToken } };
    } catch (error) {
      this.logger?.error("Authentication failed:", error);
      throw new AuthError(error, "Authentication failed.");
    }
  }

  /**
   * Rotates refresh and access tokens by verifying the refresh token and issuing new ones.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<{ accessToken: string; refreshToken?: string }>} The new access and refresh tokens.
   * @throws {InvalidTokenError} If the refresh token is invalid or expired.
   */
  async rotateTokens(
    context: TContext
  ): Promise<{ accessToken: string; refreshToken?: string }> {
    try {
      const refreshToken = await this.retrieveRefreshToken(context);
      if (!refreshToken) throw new MissingTokenError("Refresh");

      const payload = await this.verifyRefreshToken(refreshToken);
      if (!payload) throw new InvalidTokenError("Refresh");

      const newAccessToken = await this.generateAccessToken(payload);
      let newRefreshToken = await this.generateRefreshToken(payload);

      await this.storeAccessToken(newAccessToken, context);
      if (newRefreshToken) {
        await this.storeRefreshToken(newRefreshToken, context);
      }

      this.embedAccessToken(newAccessToken, context);
      this.embedRefreshToken(newRefreshToken, context);

      return { accessToken: newAccessToken, refreshToken: newRefreshToken };
    } catch (error) {
      this.logger?.error("Token rotation failed:", error);
      throw new InvalidTokenError("Refresh");
    }
  }
}
