import * as Soap from "@soapjs/soap";
import { CredentialBasedAuthStrategy } from "../credential-based-auth.strategy";
import { InvalidCredentialsError, MissingCredentialsError } from "../../errors";
import { BasicContext, BasicStrategyConfig } from "./basic.types";
import { SessionHandler } from "../../session/session-handler";

export class BasicStrategy<
  TContext extends BasicContext = BasicContext,
  TUser = unknown
> extends CredentialBasedAuthStrategy<TContext, TUser> {
  /**
   * Constructs an instance of BasicStrategy.
   *
   * @param {BasicStrategyConfig<TContext, TUser>} config - Configuration options for the strategy.
   * @param {SessionHandler} [session] - Session configuration.
   * @param {Soap.Logger} [logger] - Logger instance.
   */
  constructor(
    protected config: BasicStrategyConfig<TContext, TUser>,
    protected session?: SessionHandler,
    protected logger?: Soap.Logger
  ) {
    super(config, session, logger);
  }

  /**
   * Extracts credentials from the Authorization header in the request context.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<{ identifier: string; password: string }>} The extracted credentials.
   * @throws {Error} If the credentials are missing or malformed.
   */
  protected async extractCredentials(
    context?: TContext
  ): Promise<{ identifier: string; password: string }> {
    const authHeader =
      context?.headers?.authorization || context?.headers?.["x-custom-auth"];

    if (!authHeader) {
      throw new MissingCredentialsError();
    }

    const parts = authHeader.split(" ");
    if (parts.length !== 2 || parts[0] !== "Basic") {
      throw new InvalidCredentialsError();
    }

    try {
      const decoded = Buffer.from(parts[1], "base64").toString("utf-8");
      const [username, password] = decoded.split(":");

      if (!username || !password) {
        throw new InvalidCredentialsError();
      }

      return { identifier: username, password };
    } catch {
      throw new InvalidCredentialsError();
    }
  }

  /**
   * Verifies if the provided credentials are valid.
   *
   * @param {object} credentials - The extracted credentials.
   * @returns {Promise<boolean>} True if credentials are valid.
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
   * Retrieves user data based on the provided credentials.
   *
   * @param {object} credentials - The extracted credentials.
   * @returns {Promise<TUser | null>} The user data if found, otherwise null.
   */
  protected async retrieveUser(credentials: {
    identifier: string;
    password: string;
  }): Promise<TUser | null> {
    return this.config.login.retrieveUserData(credentials.identifier);
  }

  /**
   * Initiates the password reset process.
   *
   * @param email - The user's email.
   * @returns {Promise<void>} Resolves when the reset process is initiated.
   */
  async requestPasswordReset(email: string): Promise<void> {
    await super.requestPasswordReset(email);
  }

  /**
   * Resets the user's password using a reset token.
   *
   * @param email - The user's email.
   * @param token - The reset token.
   * @param newPassword - The new password to set.
   * @returns {Promise<void>} Resolves when the password is updated successfully.
   */
  async resetPassword(
    email: string,
    token: string,
    newPassword: string
  ): Promise<void> {
    await super.resetPassword(email, token, newPassword);
  }

  /**
   * Changes the user's password by verifying the old password.
   *
   * @param email - The user's email.
   * @param oldPassword - The current password.
   * @param newPassword - The new password to set.
   * @returns {Promise<void>} Resolves when the password is changed successfully.
   */
  async changePassword(
    email: string,
    oldPassword: string,
    newPassword: string
  ): Promise<void> {
    await super.changePassword(email, oldPassword, newPassword);
  }
}
