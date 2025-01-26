import * as Soap from "@soapjs/soap";
import { AuthResult, AuthStrategy } from "../../types";
import {
  InvalidApiKeyError,
  MissingApiKeyError,
  ExpiredApiKeyError,
} from "./api-key.errors";
import { ApiKeyStrategyConfig } from "./api-key.types";
import {
  AccountLockedError,
  RateLimitExceededError,
  UnauthorizedRoleError,
} from "../../errors";

/**
 * Implements an API key authentication strategy.
 *
 * @template TContext - The type of the authentication context.
 * @template TUser - The type of the authenticated user.
 */
export class ApiKeyStrategy<TContext = unknown, TUser = unknown>
  implements AuthStrategy<TContext, TUser>
{
  /**
   * Creates an instance of ApiKeyStrategy with the provided configuration.
   * @param config - Configuration options for API key authentication.
   * @param logger - Logger instance for logging purposes.
   */
  constructor(
    private config: ApiKeyStrategyConfig<TContext, TUser>,
    private logger: Soap.Logger
  ) {
    if (!this.config.extractApiKey || !this.config.retrieveUserByApiKey) {
      throw new Error(
        "ApiKeyStrategy requires extractApiKey and retrieveUserByApiKey functions."
      );
    }
  }

  /**
   * Initializes the API key strategy.
   * No special asynchronous initialization is required by default.
   * @returns {Promise<void>} Resolves immediately.
   */
  async init(): Promise<void> {
    return Promise.resolve();
  }

  /**
   * Authenticates a user using an API key.
   * @param context - An optional authentication context.
   * @returns {Promise<AuthResult<TUser>>} Resolves with user data if successful.
   * @throws {MissingApiKeyError} If API key is missing.
   * @throws {InvalidApiKeyError} If authentication fails due to invalid API key.
   */
  async authenticate(context?: TContext): Promise<AuthResult<TUser>> {
    try {
      const apiKey = this.config.extractApiKey(context);

      if (!apiKey) {
        throw new MissingApiKeyError();
      }

      if (await this.config.isAccountLocked?.(apiKey, context)) {
        throw new AccountLockedError();
      }

      if (await this.config.isApiKeyExpired?.(apiKey)) {
        throw new ExpiredApiKeyError();
      }

      if (
        this.config.checkRateLimit &&
        (await this.config.checkRateLimit(apiKey))
      ) {
        throw new RateLimitExceededError();
      }

      const user = await this.config.retrieveUserByApiKey(apiKey);

      if (!user) {
        await this.config.logFailedAttempt?.(apiKey, context);
        throw new InvalidApiKeyError();
      }

      if (this.config.authorizeByRoles) {
        const hasAccess = await this.config.authorizeByRoles(
          user,
          this.config.roles || []
        );
        if (!hasAccess) {
          throw new UnauthorizedRoleError();
        }
      }

      await this.trackApiKeyUsage(apiKey);
      await this.incrementRequestCount(apiKey);
      await this.config.onSuccess?.({ user, context });

      return { user };
    } catch (error) {
      this.logger.error("API Key authentication error:", error);
      try {
        await this.config.onFailure?.({ error, context });
      } catch (callbackError) {
        this.logger.error(
          "onFailure callback error during authentication:",
          callbackError
        );
      }
      throw error;
    }
  }

  /**
   * Authorizes a user for a specific action on a resource.
   * @param user - Authenticated user data.
   * @param action - Action to authorize (e.g., "read", "write").
   * @param resource - Optional resource identifier.
   * @returns {Promise<boolean>} Resolves to a boolean indicating authorization status.
   */
  async authorize(
    user: TUser,
    action: string,
    resource?: string
  ): Promise<boolean> {
    if (this.config.authorize) {
      return this.config.authorize(user, action, resource);
    }

    throw new Error("Authorization logic is not implemented.");
  }

  /**
   * Revokes an API key, effectively logging out the user.
   * @param apiKey - The API key to revoke.
   * @returns {Promise<void>} Resolves when the API key is revoked.
   */
  async revoke(apiKey: string): Promise<void> {
    if (this.config.revokeApiKey) {
      await this.config.revokeApiKey(apiKey);
    } else {
      throw new Error("Revoke API key functionality is not configured.");
    }
  }

  /**
   * Tracks API key usage for monitoring and analytics purposes.
   * @param apiKey - The API key to track.
   */
  private async trackApiKeyUsage(apiKey: string): Promise<void> {
    try {
      if (this.config.trackApiKeyUsage) {
        await this.config.trackApiKeyUsage(apiKey);
      }
    } catch (error) {
      this.logger.warn("Failed to track API key usage:", error);
    }
  }

  /**
   * Increments request count for the provided API key.
   * Useful for tracking usage limits.
   * @param apiKey - The API key for which to increment the request count.
   */
  private async incrementRequestCount(apiKey: string): Promise<void> {
    try {
      await this.config.incrementRequestCount?.(apiKey);
    } catch (error) {
      this.logger.warn("Failed to increment request count:", error);
    }
  }
}
