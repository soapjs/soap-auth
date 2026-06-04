import * as Soap from "@soapjs/soap";
import { CredentialAuthStrategy } from "../credential-auth.strategy";
import { LocalStrategyConfig } from "./local.types";
import { SessionHandler } from "../../session/session-handler";
import { prepareLocalConfig } from "./local.tools";
import { JwtStrategy } from "../jwt/jwt.strategy";
import {
  InvalidCredentialsError,
  MissingCredentialsError,
  UserNotFoundError,
} from "../../errors";
import { ValidationUtils, ValidationError } from "../../utils/validation";

/**
 * A strategy for authenticating users via local username and password credentials.
 * Extends the `CredentialBasedAuthStrategy` for common authentication operations.
 *
 * @template TContext - The type of authentication context (e.g., HTTP request).
 * @template TUser - The type of the authenticated user object.
 */
export class LocalStrategy<
  TContext = Soap.HttpContext,
  TUser extends Soap.AuthUser = Soap.AuthUser
> extends CredentialAuthStrategy<TContext, TUser> {
  readonly name = "local";
  /**
   * Constructs an instance of LocalStrategy.
   *
   * @param {LocalStrategyConfig<TContext, TUser>} config - Configuration options for the strategy.
   * @param {SessionHandler} [session] - Session configuration.
   * @param {JwtStrategy<TContext, TUser>} [jwt] - JWT configuration.
   * @param {Soap.Logger} [logger] - Logger instance.
   */
  constructor(
    config: LocalStrategyConfig<TContext, TUser>,
    protected session?: SessionHandler,
    protected jwt?: JwtStrategy<TContext, TUser>,
    protected logger?: Soap.Logger
  ) {
    // Validate configuration before super call
    LocalStrategy.validateConfig(config);
    
    super(prepareLocalConfig(config), session, jwt, logger);
  }

  /**
   * Validates Local strategy configuration
   */
  private static validateConfig(config: LocalStrategyConfig<any, any>): void {
    try {
      ValidationUtils.required(config, "config");
      
      // Validate credentials configuration
      if (config.credentials) {
        ValidationUtils.required(config.credentials.extractCredentials, "config.credentials.extractCredentials");
        ValidationUtils.function(config.credentials.extractCredentials, "config.credentials.extractCredentials");
        ValidationUtils.required(config.credentials.verifyCredentials, "config.credentials.verifyCredentials");
        ValidationUtils.function(config.credentials.verifyCredentials, "config.credentials.verifyCredentials");
      }

      // Validate user configuration
      if (config.user) {
        ValidationUtils.required(config.user.fetchUser, "config.user.fetchUser");
        ValidationUtils.function(config.user.fetchUser, "config.user.fetchUser");
      }

      // Validate routes configuration
      if (config.routes) {
        ValidationUtils.required(config.routes.login, "config.routes.login");
        ValidationUtils.required(config.routes.logout, "config.routes.logout");
        ValidationUtils.object(config.routes.login, "config.routes.login");
        ValidationUtils.object(config.routes.logout, "config.routes.logout");
        
        if (config.routes.login) {
          ValidationUtils.nonEmptyString(config.routes.login.path, "config.routes.login.path");
          ValidationUtils.nonEmptyString(config.routes.login.method, "config.routes.login.method");
        }
        
        if (config.routes.logout) {
          ValidationUtils.nonEmptyString(config.routes.logout.path, "config.routes.logout.path");
          ValidationUtils.nonEmptyString(config.routes.logout.method, "config.routes.logout.method");
        }
      }

    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new ValidationError(`Invalid Local strategy configuration: ${error.message}`);
    }
  }

  /**
   * Extracts credentials (username and password) from the provided context.
   *
   * @param {TContext} context - The authentication context containing user credentials.
   * @returns {Promise<{ identifier: string; password: string }>} The extracted credentials.
   * @throws {Error} If credentials are missing or invalid.
   */
  protected extractCredentials(
    context?: TContext
  ): Promise<{ identifier: string; password: string }> {
    // Validate context
    ValidationUtils.required(context, "context");
    
    return this.config.credentials.extractCredentials(context);
  }

  /**
   * Verifies the provided credentials against the stored ones.
   *
   * @param {object} credentials - The credentials containing the identifier and password.
   * @returns {Promise<boolean>} True if the credentials are valid, otherwise false.
   */
  protected async verifyCredentials(
    identifier: string,
    password: string
  ): Promise<boolean> {
    // Validate inputs
    ValidationUtils.nonEmptyString(identifier, "identifier");
    ValidationUtils.nonEmptyString(password, "password");
    
    return this.config.credentials.verifyCredentials(identifier, password);
  }

  /**
   * Retrieves the user's profile based on the provided identifier.
   *
   * The parent {@link CredentialAuthStrategy.login} dispatches this method as
   * `this.fetchUser(credentials.identifier)` — i.e. with a plain string, not
   * the full credentials object. Older code passes the credentials object
   * (e.g. {@link changePassword} below), so accept both shapes for backwards
   * compatibility.
   *
   * @param identifierOrCredentials - The identifier string OR a credentials
   *   object that exposes `.identifier`.
   * @returns {Promise<TUser | null>} The user object if found, otherwise null.
   */
  protected async fetchUser(
    identifierOrCredentials:
      | string
      | { identifier: string; password?: string }
  ): Promise<TUser | null> {
    ValidationUtils.required(identifierOrCredentials, "identifier");

    const identifier =
      typeof identifierOrCredentials === "string"
        ? identifierOrCredentials
        : identifierOrCredentials?.identifier;

    ValidationUtils.nonEmptyString(identifier, "identifier");

    return this.config.user.fetchUser(identifier);
  }

  async changePassword(context: TContext): Promise<void> {
    try {
      const credentials = await this.config.credentials.extractCredentials(
        context
      );

      if (!credentials) {
        throw new MissingCredentialsError();
      }

      if (
        !credentials.identifier ||
        !credentials.password ||
        !credentials.newPassword
      ) {
        throw new InvalidCredentialsError();
      }

      await this.accountLock?.isAccountLocked(credentials.identifier);
      await this.throttle?.checkFailedAttempts(credentials.identifier);

      const user = await this.fetchUser(credentials);

      if (!user) {
        throw new UserNotFoundError();
      }

      if (
        (await this.verifyCredentials(
          credentials.identifier,
          credentials.password
        )) === false
      ) {
        await this.throttle?.incrementFailedAttempts(credentials.identifier);
        throw new InvalidCredentialsError();
      }

      await this.password.validatePassword(
        credentials.newPassword,
        credentials.password
      );

      await this.password.updatePassword(
        credentials.identifier,
        credentials.newPassword
      );

      await this.throttle?.resetFailedAttempts(credentials.identifier);
      await this.onSuccess("change_password", {
        identifier: credentials.identifier,
      });

      this.logger?.info(`User password ${credentials.identifier} changed.`);
    } catch (error) {
      await this.onFailure("change_password", { context, error });
      throw error;
    }
  }
}
