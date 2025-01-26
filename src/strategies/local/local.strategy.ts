import * as Soap from "@soapjs/soap";
import { AuthError, InvalidCredentialsError } from "../../errors";
import { TokenHandlerConfig, TokenHandlersConfig } from "../../types";
import { CredentialBasedAuthStrategy } from "../credential-based-auth.strategy";
import { LocalStrategyConfig } from "./local.types";
import { SessionHandler } from "../../session/session-handler";

/**
 * A strategy for authenticating users via local username and password credentials.
 * Extends the `CredentialBasedAuthStrategy` for common authentication operations.
 *
 * @template TContext - The type of authentication context (e.g., HTTP request).
 * @template TUser - The type of the authenticated user object.
 */
export class LocalStrategy<
  TContext = unknown,
  TUser = unknown
> extends CredentialBasedAuthStrategy<TContext, TUser> {
  /**
   * Constructs an instance of LocalStrategy.
   *
   * @param {LocalStrategyConfig<TContext, TUser>} config - Configuration options for the strategy.
   * @param {SessionHandler} [session] - Session configuration.
   * @param {Soap.Logger} [logger] - Logger instance.
   */
  constructor(
    protected config: LocalStrategyConfig<TContext, TUser>,
    protected session?: SessionHandler,
    protected logger?: Soap.Logger
  ) {
    super(config, session, logger);
  }

  /**
   * Extracts credentials (username and password) from the provided context.
   *
   * @param {TContext} context - The authentication context containing user credentials.
   * @returns {Promise<{ identifier: string; password: string }>} The extracted credentials.
   * @throws {Error} If credentials are missing or invalid.
   */
  protected async extractCredentials(
    context?: TContext
  ): Promise<{ identifier: string; password: string }> {
    return this.config.login.extractCredentials(context);
  }

  /**
   * Verifies the provided credentials against the stored ones.
   *
   * @param {object} credentials - The credentials containing the identifier and password.
   * @returns {Promise<boolean>} True if the credentials are valid, otherwise false.
   */
  protected async verifyCredentials(credentials: {
    identifier: string;
    password: string;
  }): Promise<boolean> {
    return this.config.login.verifyUserCredentials(
      credentials.identifier,
      credentials.password
    );
  }

  /**
   * Retrieves the user's profile based on the provided credentials.
   *
   * @param {object} credentials - The user's identifier and password.
   * @returns {Promise<TUser | null>} The user object if found, otherwise null.
   */
  protected async retrieveUser(credentials: {
    identifier: string;
    password: string;
  }): Promise<TUser | null> {
    return this.config.login.retrieveUserData(credentials.identifier);
  }

  /**
   * Initiates the password reset process for the user.
   *
   * @param {string} email - The user's email address to receive the reset link.
   * @returns {Promise<void>} Resolves when the reset email is sent.
   * @throws {AuthError} If the password reset operation fails.
   */
  async requestPasswordReset(email: string): Promise<void> {
    try {
      if (!this.config.passwordReset?.generateResetToken) {
        throw new Error("Password reset token generation is not configured.");
      }

      const token = await this.config.passwordReset.generateResetToken(email);
      await this.config.passwordReset.sendResetEmail?.(email, token);
      this.logger?.info(`Password reset requested for email: ${email}`);

      await this.config.passwordReset.onSuccess?.({ email });
    } catch (error) {
      this.logger?.error("Password reset request error:", error);
      await this.config.passwordReset.onFailure?.({ email, error });
      throw new AuthError(error, "Password reset request failed.");
    }
  }

  /**
   * Resets the user's password using a valid reset token.
   *
   * @param {string} email - The user's email address.
   * @param {string} token - The password reset token.
   * @param {string} newPassword - The new password to be set.
   * @returns {Promise<void>} Resolves when the password is updated successfully.
   * @throws {AuthError} If the reset operation fails due to invalid token.
   */
  async resetPassword(
    email: string,
    token: string,
    newPassword: string
  ): Promise<void> {
    try {
      if (!this.config.passwordReset?.validateResetToken) {
        throw new Error("Password reset token validation is not configured.");
      }

      const isValid = await this.config.passwordReset.validateResetToken(token);
      if (!isValid) throw new Error("Invalid or expired reset token.");

      await this.config.passwordReset.updatePassword(email, newPassword);
      this.logger?.info(`Password reset successful for email: ${email}`);

      await this.config.passwordReset.onSuccess?.({ email });
    } catch (error) {
      this.logger?.error("Password reset error:", error);
      await this.config.passwordReset.onFailure?.({ email, error });
      throw new AuthError(error, "Password reset failed.");
    }
  }

  /**
   * Changes the user's password by verifying their current password.
   *
   * @param {string} email - The user's email address.
   * @param {string} oldPassword - The user's current password.
   * @param {string} newPassword - The new password to set.
   * @returns {Promise<void>} Resolves when the password is changed successfully.
   * @throws {InvalidCredentialsError} If the current password is incorrect.
   */
  async changePassword(
    email: string,
    oldPassword: string,
    newPassword: string
  ): Promise<void> {
    try {
      const isAuthenticated = await this.config.login.verifyUserCredentials(
        email,
        oldPassword
      );
      if (!isAuthenticated) {
        throw new InvalidCredentialsError();
      }

      await this.config.passwordReset?.updatePassword?.(email, newPassword);
      this.logger?.info(`Password changed successfully for email: ${email}`);

      await this.config.passwordReset?.onSuccess?.({ email });
    } catch (error) {
      this.logger?.error("Change password error:", error);
      await this.config.passwordReset?.onFailure?.({ email, error });
      throw new AuthError(error, "Change password failed.");
    }
  }
}
