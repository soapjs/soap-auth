import * as Soap from "@soapjs/soap";
import { CredentialAuthStrategy } from "../credential-auth.strategy";
import { InvalidCredentialsError, MissingCredentialsError } from "../../errors";
import { BasicContext, BasicStrategyConfig } from "./basic.types";
import { SessionHandler } from "../../session/session-handler";
import { JwtStrategy } from "../jwt/jwt.strategy";
import { prepareBasicConfig } from "./basic.tools";

export class BasicStrategy<
  TContext = unknown,
  TUser = unknown
> extends CredentialAuthStrategy<TContext, TUser> {
  /**
   * Constructs an instance of BasicStrategy.
   *
   * @param {BasicStrategyConfig<TContext, TUser>} config - Configuration options for the strategy.
   * @param {SessionHandler} [session] - Session configuration.
   * @param {JwtStrategy<TContext, TUser>} [jwt] - JWT configuration.
   * @param {Soap.Logger} [logger] - Logger instance.
   */
  constructor(
    protected config: BasicStrategyConfig<TContext, TUser>,
    protected session?: SessionHandler,
    protected jwt?: JwtStrategy<TContext, TUser>,
    protected logger?: Soap.Logger
  ) {
    super(prepareBasicConfig(config), session, jwt, logger);
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
    const authHeader = this.config.credentials?.extractCredentials
      ? this.config.credentials.extractCredentials<string>(context)
      : (context as BasicContext)?.headers?.authorization ||
        (context as BasicContext)?.headers?.["x-custom-auth"] ||
        (context as BasicContext)?.headers?.["proxy-authorization"];

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
}
