import {
  RateLimitConfig,
  RoleAuthorizationConfig,
  AuthFailureContext,
  AuthSuccessContext,
  AccountLockConfig,
} from "../../types";

/**
 * Configuration options for the API key authentication process.
 */
export interface ApiKeyStrategyConfig<TContext = unknown, TUser = unknown>
  extends ApiKeyTrackingConfig,
    RateLimitConfig,
    RoleAuthorizationConfig<TUser>,
    AccountLockConfig<TContext> {
  /**
   * A function to extract the API key from the context.
   * @param context - The request context.
   * @returns The extracted API key as a string or null if not found.
   */
  extractApiKey: (context: TContext) => string | null;

  /**
   * A function to retrieve user information based on the provided API key.
   * @param apiKey - The API key to lookup the user.
   * @returns A promise resolving to the user object or null if not found.
   */
  retrieveUserByApiKey: (apiKey: string) => Promise<TUser | null>;

  /**
   * A function to authorize a user for a specific action on a resource.
   * @param user - The authenticated user data.
   * @param action - The action to authorize (e.g., "read", "write").
   * @param resource - Optional resource identifier.
   * @returns A promise resolving to a boolean indicating authorization status.
   */
  authorize?: (
    user: TUser,
    action: string,
    resource?: string
  ) => Promise<boolean>;

  /**
   * A function to revoke an API key, effectively logging out the user.
   * @param apiKey - The API key to revoke.
   * @returns A promise that resolves when the API key is revoked.
   */
  revokeApiKey?: (apiKey: string) => Promise<void>;

  /**
   * Callback invoked upon successful authentication.
   *
   * @param context - The context of the request, which may include request and response objects or other relevant data.
   * @returns {Promise<void>|void} Optionally returns a promise that resolves when success handling is complete.
   */
  onSuccess?: (
    context: AuthSuccessContext<TUser, TContext>
  ) => Promise<void> | void;

  /**
   * Callback invoked upon failed authentication.
   *
   * @param context - The context of the request, which may include request and response objects or other relevant data.
   * @returns {Promise<void>|void} Optionally returns a promise that resolves when failure handling is complete.
   */
  onFailure?: (context: AuthFailureContext<TContext>) => Promise<void> | void;
}

/**
 * A function to check if the API key is still valid based on last usage timestamp.
 * @param apiKey - The API key to check.
 * @returns A promise resolving to a boolean indicating whether the key is still valid.
 */
export interface ApiKeyTrackingConfig {
  trackApiKeyUsage?: (apiKey: string) => Promise<void>;
  isApiKeyExpired?: (apiKey: string) => Promise<boolean>;
}
