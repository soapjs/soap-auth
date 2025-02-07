import * as Soap from "@soapjs/soap";
import {
  AccountLockedError,
  AuthError,
  InvalidCredentialsError,
  MissingCredentialsError,
  UserNotFoundError,
} from "../errors";
import { AuthResult, CredentialBasedAuthStrategyConfig } from "../types";
import { BaseAuthStrategy } from "./base-auth.strategy";
import { SessionHandler } from "../session/session-handler";

/**
 * Abstract class for credential-based authentication strategies.
 * Provides core authentication, logout, and password management functionality.
 *
 * @template TContext - The type of the authentication context.
 * @template TUser - The type of the authenticated user.
 */
export abstract class CredentialBasedAuthStrategy<
  TContext = unknown,
  TUser = unknown
> extends BaseAuthStrategy<TContext, TUser> {
  /**
   * Extracts credentials from the given context.
   * Must be implemented by specific strategies.
   *
   * @param {TContext} [context] - The authentication context.
   * @returns {Promise<any>} The extracted credentials.
   */
  protected abstract extractCredentials(
    context?: TContext
  ): Promise<{ identifier: string; password: string }>;
  /**
   * Verifies the provided credentials.
   * Must be implemented by specific strategies.
   *
   * @param {any} credentials - The user credentials.
   * @returns {Promise<boolean>} A promise resolving to true if credentials are valid, otherwise false.
   */
  protected abstract verifyCredentials(credentials: any): Promise<boolean>;
  /**
   * Retrieves user information based on provided credentials.
   * Must be implemented by specific strategies.
   *
   * @param {any} credentials - The user credentials.
   * @returns {Promise<TUser | null>} The user data if found, otherwise null.
   */
  protected abstract retrieveUser(credentials: any): Promise<TUser | null>;

  /**
   * Constructs an instance of CredentialBasedAuthStrategy.
   *
   * @param {CredentialBasedAuthStrategyConfig<TContext, TUser>} config - Configuration options for the strategy.
   * @param {SessionHandler} [session] - Session configuration.
   * @param {Soap.Logger} [logger] - Logger instance.
   */
  constructor(
    protected config: CredentialBasedAuthStrategyConfig<TContext, TUser>,
    protected session?: SessionHandler,
    protected logger?: Soap.Logger
  ) {
    super(config, session, logger);
  }

  /**
   * Authenticates a user based on provided credentials.
   *
   * @param {TContext} [context] - The authentication context.
   * @returns {Promise<AuthResult<TUser>>} The authentication result containing the user.
   * @throws {MissingCredentialsError} If credentials are missing.
   * @throws {InvalidCredentialsError} If credentials are invalid.
   * @throws {UserNotFoundError} If user data cannot be retrieved.
   */
  async authenticate(context?: TContext): Promise<AuthResult<TUser>> {
    try {
      const credentials = await this.extractCredentials(context);
      if (!credentials) throw new MissingCredentialsError();

      await this.isAccountLocked(credentials.identifier);
      await this.checkFailedAttempts(credentials.identifier);
      await this.checkRateLimit(credentials.identifier);
      await this.checkPasswordExpiry(credentials.identifier);

      const valid = await this.verifyCredentials(credentials);

      if (!valid) {
        await this.config.login.incrementFailedAttempts?.(
          credentials.identifier
        );
        throw new InvalidCredentialsError();
      }

      await this.config.login.resetFailedAttempts?.(credentials.identifier);

      const user = await this.retrieveUser(credentials);
      if (!user) throw new UserNotFoundError();

      await this.checkMfa(user, context);
      await this.isAuthorized(user);
      await this.handleSession(user, context);

      return { user };
    } catch (e) {
      const error = new AuthError(e, "Authentication failed.");
      this.logger.error("Authentication failed:", error);

      await this.config.logout.onFailure?.({ context, error: error });

      throw error;
    }
  }

  /**
   * Handles session management for authenticated users.
   *
   * @param {TUser} user - The authenticated user.
   * @param {TContext} [context] - The authentication context.
   */
  protected async handleSession(user: TUser, context?: TContext) {
    if (this.session) {
      const sessionId = this.session.generateSessionId();
      await this.session.set(sessionId, user);
    }
  }

  /**
   * Logs out the user by destroying the session.
   *
   * @param {TContext} [context] - The authentication context.
   * @throws {Error} If session manager is not configured or session ID is missing.
   */
  async logout(context?: TContext): Promise<void> {
    try {
      if (this.session) {
        const sessionId = this.session.getSessionId?.(context);

        if (!sessionId) {
          throw new Error("Session ID is missing in the context.");
        }

        await this.session.destroy(sessionId);

        this.logger.info(
          `Session destroyed successfully, sessionId: ${sessionId}`
        );
      }

      await this.config.logout.onSuccess?.(context);

      this.logger.info(`User logged out successfully.`);
    } catch (e) {
      const error = new AuthError(e, "Logout process failed.");
      this.logger.error("Error during logout:", e);

      await this.config.logout.onFailure?.({ context, error: e });

      throw error;
    }
  }

  /**
   * Initiates the password reset process by generating and sending a reset token.
   *
   * @param {string} identifier - The user's identifier.
   * @param {string} email - The user's email.
   * @throws {Error} If password reset configuration is missing.
   */
  async requestPasswordReset(
    identifier: string,
    email?: string
  ): Promise<void> {
    try {
      if (!this.config.passwordReset?.generateResetToken) {
        throw new Error("Password reset token generation is not configured.");
      }

      const token = await this.config.passwordReset.generateResetToken(
        identifier
      );

      if (email) {
        await this.config.passwordReset.sendResetEmail?.(email, token);
      }

      await this.config.passwordReset.onSuccess?.({ identifier });

      this.logger.info(
        `Password reset requested for identifier: ${identifier}`
      );
    } catch (e) {
      const error = new AuthError(e, "Password reset request error.");
      this.logger.error("Password reset request error:", e);
      await this.config.passwordReset.onFailure?.({ identifier, error: e });
      throw error;
    }
  }

  /**
   * Resets the user's password by verifying the reset token and updating the password.
   *
   * @param {string} identifier - The user's identifier.
   * @param {string} token - The reset token.
   * @param {string} newPassword - The new password to be set.
   * @throws {Error} If reset token is invalid or expired.
   */
  async resetPassword(
    identifier: string,
    token: string,
    newPassword: string
  ): Promise<void> {
    try {
      if (!this.config.passwordReset?.validateResetToken) {
        throw new Error("Password reset token validation is not configured.");
      }

      const isValid = await this.config.passwordReset.validateResetToken(token);

      if (!isValid) {
        throw new Error("Invalid or expired reset token.");
      }

      await this.config.passwordReset.updatePassword(identifier, newPassword);
      await this.config.passwordReset.onSuccess?.({ identifier });

      this.logger.info(
        `Password successfully reset for identifier: ${identifier}`
      );
    } catch (e) {
      const error = new AuthError(e, "Password reset error");
      this.logger.error("Password reset error:", e);
      await this.config.passwordReset.onFailure?.({ identifier, error: e });
      throw error;
    }
  }

  /**
   * Changes the user's password by verifying the old password and updating it with a new one.
   *
   * @param {string} email - The user's email.
   * @param {string} oldPassword - The current password.
   * @param {string} newPassword - The new password.
   * @throws {InvalidCredentialsError} If old password is incorrect.
   */
  async changePassword(
    identifier: string,
    oldPassword: string,
    newPassword: string
  ): Promise<void> {
    try {
      if (!this.config.login.verifyUserCredentials) {
        throw new Error("Credential verification is not configured.");
      }

      const isAuthenticated = await this.config.login.verifyUserCredentials(
        identifier,
        oldPassword
      );
      if (!isAuthenticated) {
        throw new InvalidCredentialsError();
      }

      await this.config.passwordReset?.updatePassword?.(
        identifier,
        newPassword
      );
      await this.config.passwordReset?.onSuccess?.({ identifier });

      this.logger.info(
        `Password changed successfully for identifier: ${identifier}`
      );
    } catch (e) {
      const error = new AuthError(e, "Change password error");
      this.logger.error("Change password error:", e);
      await this.config.passwordReset?.onFailure?.({ identifier, error: e });
      throw error;
    }
  }

  /**
   * Logs a user authentication attempt.
   *
   * @param {string} identifier - The user's unique identifier.
   * @param {boolean} success - Whether the authentication attempt was successful.
   * @param {TContext} [context] - The authentication context.
   */
  protected async auditLoginAttempt(
    identifier: string,
    success: boolean,
    context?: TContext
  ): Promise<void> {
    await this.config.audit?.logAttempt?.(identifier, success, context);
  }

  /**
   * Logs a password change event.
   *
   * @param {string} identifier - The user's unique identifier.
   * @param {TContext} [context] - The context of the request.
   */
  protected async auditPasswordChange(
    identifier: string,
    context?: TContext
  ): Promise<void> {
    await this.config.audit?.logPasswordChange?.(identifier, context);
  }

  protected validatePasswordPolicy(password: string): boolean {
    return this.config.passwordPolicy.validatePassword?.(password) ?? true;
  }

  /**
   * Checks if the user has exceeded the allowed number of failed login attempts.
   * If the threshold is reached, the account is temporarily locked.
   *
   * @param {string} identifier - The user's unique identifier.
   * @throws {AccountLockedError} If the maximum number of failed attempts is exceeded.
   */

  protected async checkFailedAttempts(identifier: string) {
    try {
      if (this.config.security?.maxFailedLoginAttempts) {
        const failedAttempts =
          (await this.config.login.getFailedAttempts?.(identifier)) || 0;

        if (failedAttempts >= this.config.security.maxFailedLoginAttempts) {
          this.logger.warn(`User ${identifier} is temporarily locked out.`);
          throw new AccountLockedError();
        }
      }
    } catch (e) {
      this.logger.error("Check failed attempts:", e);
    }
  }

  /**
   * Checks if the user's account is currently locked due to security policies.
   * If the lockout period has expired, the lock is removed.
   *
   * @param {string} account - The account identifier.
   * @param {...unknown[]} args - Additional arguments that may be passed to the function.
   * @returns {Promise<boolean>} A promise that resolves to true if the account is locked.
   * @throws {AccountLockedError} If the account is currently locked.
   */
  protected async isAccountLocked(
    account: any,
    ...args: unknown[]
  ): Promise<boolean> {
    if (await this.config.lock.isAccountLocked?.(account, ...args)) {
      throw new AccountLockedError();
    }

    if (typeof account === "string" && this.config.security?.lockoutDuration) {
      const lockoutKey = `lockout:${account}`;
      const lockoutSession = await this.session?.get(lockoutKey);

      if (lockoutSession) {
        const elapsed = Date.now() - Number(lockoutSession.date);
        if (elapsed < this.config.security.lockoutDuration * 60 * 1000) {
          this.logger.warn(`Account ${account} is temporarily locked out.`);
          return true;
        } else {
          await this.session?.destroy(lockoutKey);
        }
      }
    }

    return false;
  }

  /**
   * Increments the count of failed login attempts and locks the account if needed.
   *
   * @param {string} account - The user's unique identifier.
   */
  protected async incrementFailedAttempts(account: any): Promise<void> {
    if (this.config.login.incrementFailedAttempts) {
      await this.config.login.incrementFailedAttempts(account);

      const failedAttempts =
        (await this.config.login.getFailedAttempts?.(account)) || 0;

      if (
        this.config.security?.maxFailedLoginAttempts &&
        failedAttempts >= this.config.security.maxFailedLoginAttempts
      ) {
        const lockoutKey = `lockout:${account}`;
        await this.session?.set(lockoutKey, {
          date: Date.now(),
        });
        this.logger.warn(
          `Account ${account} has been locked due to failed attempts.`
        );
        this.notifyAccountLocked(account);
      }
    }
  }

  /**
   * Sends a notification when an account is locked.
   *
   * @param {string} identifier - The user's unique identifier.
   */
  protected async notifyAccountLocked(identifier: string) {
    if (this.config.security?.notifyOnLockout) {
      await this.config.security.notifyOnLockout(identifier);
    }
  }

  protected async checkPasswordExpiry(identifier: string): Promise<void> {
    if (this.config.passwordPolicy?.passwordExpirationDays) {
      const lastChanged =
        await this.config.passwordPolicy.getLastPasswordChange?.(identifier);
      if (
        lastChanged &&
        Date.now() - Number(lastChanged) >
          this.config.passwordPolicy.passwordExpirationDays * 86400000
      ) {
        throw new Error("Password expired, please reset your password.");
      }
    }
  }
}
