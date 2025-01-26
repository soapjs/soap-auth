import { ApiKeyStrategy } from "../strategies/api-key/api-key.strategy";
import { JwtStrategy } from "../strategies/jwt/jwt.strategy";
import { AuthStrategy, SoapAuthConfig } from "../types";
import { AuthStrategyFactory } from "./auth-strategy.factory";

/**
 * Factory class responsible for creating WebSocket authentication strategies.
 */
export class SocketAuthStrategyFactory extends AuthStrategyFactory {
  /**
   * Creates Socket authentication strategies based on the provided configuration.
   *
   * @param {SoapAuthConfig} config - The authentication configuration object.
   * @returns {Map<string, AuthStrategy>} A map of WebSocket authentication strategies.
   */
  createStrategies(config: SoapAuthConfig): Map<string, AuthStrategy> {
    const strategies = new Map<string, AuthStrategy>();

    if (!config.socket) {
      return strategies;
    }

    if (config.socket.apiKey) {
      strategies.set(
        "apiKey",
        new ApiKeyStrategy(config.socket.apiKey, this.logger)
      );
    }

    if (config.socket.jwt) {
      strategies.set(
        "jwt",
        new JwtStrategy(
          config.socket.jwt,
          this.getSessionHandler(config.socket.jwt.session, config.session),
          this.logger
        )
      );
    }

    if (config.socket.custom) {
      Object.entries(config.socket.custom).forEach(([key, strategy]) => {
        strategies.set(key, strategy);
      });
    }

    return strategies;
  }
}
