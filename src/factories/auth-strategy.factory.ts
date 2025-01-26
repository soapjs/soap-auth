import * as Soap from "@soapjs/soap";
import { AuthStrategy, SessionConfig, SoapAuthConfig } from "../types";
import { resolveConfig } from "../tools/tools";
import { SessionHandler } from "../session/session-handler";

/**
 * Abstract factory class for creating authentication strategies.
 */
export abstract class AuthStrategyFactory {
  /**
   * Abstract method to create authentication strategies based on the provided configuration.
   *
   * @param {SoapAuthConfig} config - The authentication configuration object.
   * @returns {Map<string, AuthStrategy>} A map of authentication strategies.
   */
  abstract createStrategies(config: SoapAuthConfig): Map<string, AuthStrategy>;

  /**
   * Creates an instance of the authentication strategy factory.
   *
   * @param {Soap.Logger} [logger] - Optional logger instance.
   */
  constructor(protected logger?: Soap.Logger) {}

  /**
   * Creates a session handler based on the provided session configuration.
   * If no specific session configuration is provided, the global configuration is used.
   *
   * @param {SessionConfig} strategyConfig - The session configuration for the strategy.
   * @param {SessionConfig} globalConfig - The global session configuration.
   * @returns {SessionHandler | undefined} A session handler instance or undefined if no session configuration is provided.
   */
  protected getSessionHandler(
    strategyConfig: SessionConfig,
    globalConfig: SessionConfig
  ) {
    const sessionConfig = resolveConfig<SessionConfig>(
      strategyConfig,
      globalConfig
    );
    return sessionConfig ? new SessionHandler(sessionConfig) : undefined;
  }
}
