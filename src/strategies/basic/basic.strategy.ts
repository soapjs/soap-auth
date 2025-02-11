import * as Soap from "@soapjs/soap";
import { CredentialAuthStrategy } from "../credential-auth.strategy";
import { InvalidCredentialsError, MissingCredentialsError } from "../../errors";
import { BasicContext, BasicStrategyConfig } from "./basic.types";
import { SessionHandler } from "../../session/session-handler";

export class BasicStrategy<
  TContext extends BasicContext = BasicContext,
  TUser = unknown
> extends CredentialAuthStrategy<TContext, TUser> {
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
   * @returns {{ identifier: string; password: string }} The extracted credentials.
   * @throws {Error} If the credentials are missing or malformed.
   */
  protected extractCredentials(context?: TContext): {
    identifier: string;
    password: string;
  } {
    const authHeader = this.config.credentials.extractCredentials
      ? this.config.credentials.extractCredentials<string>(context)
      : context?.headers?.authorization ||
        context?.headers?.["x-custom-auth"] ||
        context?.headers?.["proxy-authorization"];

    if (!authHeader) {
      throw new MissingCredentialsError();
    }

    if (!authHeader || !authHeader.toLowerCase().startsWith("basic ")) {
      throw new InvalidCredentialsError();
    }

    const encoded = authHeader.substring(6);

    try {
      const decoded = Buffer.from(encoded, "base64").toString("utf-8");
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
   * Retrieves user data based on the provided credentials.
   *
   * @param {object} credentials - The extracted credentials.
   * @returns {Promise<TUser | null>} The user data if found, otherwise null.
   */
  protected async retrieveUser(credentials: {
    identifier: string;
    password: string;
  }): Promise<TUser | null> {
    return this.config.user.getUserData(credentials.identifier);
  }
}
