import * as Soap from "@soapjs/soap";
import { AuthResult, AuthStrategy } from "../../types";
import {
  InvalidApiKeyError,
  MissingApiKeyError,
  ExpiredApiKeyError,
} from "./api-key.errors";
import { ApiKeyStrategyConfig } from "./api-key.types";
import { AccountLockedError } from "../../errors";
import { BaseAuthStrategy } from "../base-auth.strategy";

/**
 * Implements an API key authentication strategy.
 *
 * @template TContext - The type of the authentication context.
 * @template TUser - The type of the authenticated user.
 */
export class ApiKeyStrategy<TContext = unknown, TUser = unknown>
  extends BaseAuthStrategy<TContext, TUser>
  implements AuthStrategy<TContext, TUser>
{
  protected apiKeyValidity: {
    sessionDuration: number;
    longTermDuration: number;
  };

  /**
   * Creates an instance of ApiKeyStrategy with the provided configuration.
   * @param config - Configuration options for API key authentication.
   * @param logger - Logger instance for logging purposes.
   */
  constructor(
    protected config: ApiKeyStrategyConfig<TContext, TUser>,
    logger: Soap.Logger
  ) {
    super(config, null, logger);
    if (!this.config.extractApiKey || !this.config.retrieveUserByApiKey) {
      throw new Error(
        "ApiKeyStrategy requires extractApiKey and retrieveUserByApiKey functions."
      );
    }

    this.apiKeyValidity = {
      sessionDuration: config.sessionDuration || 15 * 60 * 1000, // 15 min
      longTermDuration: config.longTermDuration || 90 * 24 * 60 * 60 * 1000, // 90 days
    };
  }

  protected async fetchUser(
    apiKey: string,
    context: TContext
  ): Promise<TUser | null> {
    const maxRetries = this.config.retrieveUserMaxRetries ?? 0;
    const retryDelay = this.config.retrieveUserRetryDelay ?? 100;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const user = await this.config.retrieveUserByApiKey(apiKey, context);
        return user;
      } catch (error) {
        this.logger.warn(`Attempt ${attempt + 1} failed: ${error}`);
        if (attempt < maxRetries) {
          await new Promise((resolve) => setTimeout(resolve, retryDelay));
        } else {
          throw error;
        }
      }
    }

    return null;
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
    let apiKey: string;
    const apiKeyType = this.config.keyType ?? "long-term";

    try {
      apiKey = this.config.extractApiKey(context);

      if (!apiKey) {
        throw new MissingApiKeyError();
      }

      if (await this.accountLock?.isAccountLocked(apiKey)) {
        throw new AccountLockedError();
      }

      await this.rateLimit?.checkRateLimit(apiKey);

      if (await this.config.isApiKeyExpired?.(apiKey)) {
        throw new ExpiredApiKeyError();
      }

      const user = await this.fetchUser(apiKey, context);

      if (!user) {
        throw new InvalidApiKeyError();
      }

      await this.role?.isAuthorized(user);

      if (apiKeyType === "one-time") {
        await this.config.revokeApiKey?.(apiKey);
      }

      await this.rateLimit?.incrementRequestCount(apiKey);
      await this.trackApiKeyUsage(apiKey);
      await this.onSuccess("authenticate", { user, context });

      return { user };
    } catch (error) {
      if (this.accountLock) {
        this.accountLock.logFailedAttempt(apiKey, context);
      }
      await this.onFailure("authenticate", {
        context,
        error,
      });
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

    return true;
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
      await this.config.trackApiKeyUsage?.(apiKey);
    } catch (error) {
      this.logger.warn("Failed to track API key usage:", error);
    }
  }
}
