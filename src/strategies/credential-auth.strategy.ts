import * as Soap from "@soapjs/soap";
import {
  ExpiredPasswordError,
  ExpiredResetTokenError,
  InvalidCredentialsError,
  MissingCredentialsError,
  UserNotFoundError,
} from "../errors";
import { AuthResult, CredentialAuthStrategyConfig } from "../types";
import { BaseAuthStrategy } from "./base-auth.strategy";
import { SessionHandler } from "../session/session-handler";
import { JwtStrategy } from "./jwt/jwt.strategy";
import { PasswordService } from "../services/password.service";

/**
 * Abstract class for credential-based authentication strategies.
 * Provides core authentication, logout, and password management functionality.
 *
 * @template TContext - The type of the authentication context.
 * @template TUser - The type of the authenticated user.
 */
export abstract class CredentialAuthStrategy<
  TContext = unknown,
  TUser = unknown
> extends BaseAuthStrategy<TContext, TUser> {
  protected password: PasswordService;
  /**
   * Verifies user credentials.
   *
   * @param {string} identifier - The user identifier (e.g., email or username).
   * @param {string} password - The user's password.
   * @returns {Promise<boolean>} Whether the credentials are valid.
   */
  protected abstract verifyCredentials(
    identifier: string,
    password: string
  ): Promise<boolean>;

  /**
   * Extracts user credentials from the authentication context.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<{ identifier: string; password: string }>} The extracted credentials.
   */
  protected abstract extractCredentials(context: TContext): any;

  /**
   * Constructs an instance of CredentialBasedAuthStrategy.
   *
   * @param {CredentialAuthStrategyConfig<TContext, TUser>} config - Configuration options for the strategy.
   * @param {SessionHandler} [session] - Session configuration.
   * @param {JwtStrategy<TContext, TUser>} [jwt] - JWT configuration.
   * @param {Soap.Logger} [logger] - Logger instance.
   */
  constructor(
    protected config: CredentialAuthStrategyConfig<TContext, TUser>,
    protected session?: SessionHandler,
    protected jwt?: JwtStrategy<TContext, TUser>,
    protected logger?: Soap.Logger
  ) {
    super(config, session, logger);

    if (config.passwordPolicy) {
      this.password = new PasswordService(config.passwordPolicy, logger);
    }
  }

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

  async authenticate(context: TContext): Promise<AuthResult<TUser>> {
    try {
      await this.rateLimit?.checkRateLimit(context);

      if (this.jwt) {
        try {
          return await this.jwt.authenticate(context);
        } catch (e) {
          this.logger?.warn(
            "JWT authentication failed, falling back to session."
          );
        }
      }

      if (this.session) {
        return await this.authenticateWithSession(context);
      }

      this.logger?.warn("No authentication method found. Proceeding as guest.");

      if (this.config.allowGuest) {
        return { user: null };
      }

      throw new UserNotFoundError();
    } catch (error) {
      await this.onFailure("authenticate", {
        context,
        error,
      });
      throw error;
    }
  }

  async login(context: TContext): Promise<AuthResult<TUser>> {
    try {
      await this.rateLimit?.checkRateLimit(context);

      const credentials = await this.extractCredentials(context);

      if (!credentials) {
        throw new MissingCredentialsError();
      }

      await this.accountLock?.isAccountLocked(credentials.identifier);
      await this.throttle?.checkFailedAttempts(credentials.identifier);

      if (
        (await this.verifyCredentials(
          credentials.identifier,
          credentials.password
        )) === false
      ) {
        await this.throttle?.incrementFailedAttempts(credentials.identifier);
        throw new InvalidCredentialsError();
      }

      const isPasswordChangeRequired =
        await this.password?.isPasswordChangeRequired(credentials.identifier);

      if (isPasswordChangeRequired) {
        throw new ExpiredPasswordError();
      }

      await this.throttle?.resetFailedAttempts(credentials.identifier);
      const user = await this.fetchUser(credentials.identifier);

      if (!user) {
        throw new UserNotFoundError();
      }

      await this.mfa?.checkMfa(user, context);
      await this.role?.isAuthorized(user);

      const tokens = await this.jwt?.issueTokens(user, context);
      const session = await this.session?.issueSession(user, context);

      return { user, session, tokens };
    } catch (error) {
      await this.onFailure("login", {
        context,
        error,
      });
      throw error;
    }
  }

  /**
   * Logs out the user by destroying the session.
   *
   * @param {TContext} [context] - The authentication context.
   * @throws {Error} If session manager is not configured or session ID is missing.
   */
  /**
   * Logs out the user by destroying the session.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<void>} Resolves when the logout process is complete.
   */
  async logout(context: TContext): Promise<void> {
    try {
      await this.session?.logoutSession(context);
      await this.onSuccess("logout", context);
    } catch (error) {
      await this.onFailure("logout", {
        error,
      });
      throw error;
    }
  }

  /**
   * Initiates the password reset process by generating and sending a reset token.
   *
   * @param {string} identifier - The user's identifier.
   * @param {string} [email] - The user's email.
   * @throws {Error} If password reset configuration is missing.
   */
  async requestPasswordReset(
    identifier: string,
    email?: string
  ): Promise<void> {
    try {
      const token = await this.password.generateResetToken(identifier);

      if (email) {
        await this.password.sendResetEmail(email, token);
      }

      await this.onSuccess("request_password_reset", {
        identifier,
        tokens: { reset: token },
      });

      this.logger.info(
        `Password reset requested for identifier: ${identifier}`
      );
    } catch (error) {
      await this.onFailure("request_password_reset", {
        identifier,
        email,
        error,
      });
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
      if (!this.password?.validateResetToken) {
        throw new Soap.NotImplementedError("validateResetToken");
      }

      if ((await this.password.validateResetToken(token)) === false) {
        throw new ExpiredResetTokenError();
      }

      await this.password.updatePassword(identifier, newPassword);
      await this.onSuccess("password_reset", { identifier });

      this.logger.info(
        `Password successfully reset for identifier: ${identifier}`
      );
    } catch (error) {
      await this.onFailure("password_reset", {
        identifier,
        additional: { token },
        error,
      });
      throw error;
    }
  }

  async changePassword(
    identifier: string,
    oldPassword: string,
    newPassword: string
  ): Promise<void> {
    try {
      if (!(await this.verifyCredentials(identifier, oldPassword))) {
        throw new InvalidCredentialsError();
      }

      await this.password.updatePassword(identifier, newPassword);
      await this.onSuccess("change_password", { identifier });

      this.logger.info(
        `Password changed successfully for identifier: ${identifier}`
      );
    } catch (error) {
      await this.onFailure("change_password", {
        identifier,
        error,
      });
      throw error;
    }
  }
}
