import * as Soap from "@soapjs/soap";
import { CredentialAuthStrategy } from "../credential-auth.strategy";
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
> extends CredentialAuthStrategy<TContext, TUser> {
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
  protected extractCredentials(
    context?: TContext
  ): Promise<{ identifier: string; password: string }> {
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
    return this.config.credentials.verifyCredentials(identifier, password);
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
    return this.config.user.getUserData(credentials.identifier);
  }
}
