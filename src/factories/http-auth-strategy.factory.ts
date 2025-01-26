import { OAuth2Strategy } from "../strategies/oauth2/oauth2.strategy";
import { ApiKeyStrategy } from "../strategies/api-key/api-key.strategy";
import { JwtStrategy } from "../strategies/jwt/jwt.strategy";
import { BasicStrategy } from "../strategies/basic/basic.strategy";
import { AuthStrategy, SoapAuthConfig, TokenHandlerConfig } from "../types";
import { AuthStrategyFactory } from "./auth-strategy.factory";
import { resolveConfig } from "../tools/tools";
import { LocalStrategy } from "../strategies/local/local.strategy";

/**
 * Factory class responsible for creating HTTP authentication strategies.
 */
export class HttpAuthStrategyFactory extends AuthStrategyFactory {
  /**
   * Creates HTTP authentication strategies based on the provided configuration.
   *
   * @param {SoapAuthConfig} config - The authentication configuration object.
   * @returns {Map<string, AuthStrategy>} A map of HTTP authentication strategies.
   */
  createStrategies(config: SoapAuthConfig): Map<string, AuthStrategy> {
    const strategies = new Map<string, AuthStrategy>();

    if (!config.http) {
      return strategies;
    }

    if (config.http.oauth2) {
      for (const provider in config.http.oauth2) {
        strategies.set(
          provider,
          new OAuth2Strategy(
            config.http.oauth2[provider],
            resolveConfig<TokenHandlerConfig>(
              config.http.oauth2[provider].tokens.access,
              config.tokens.access
            ),
            resolveConfig<TokenHandlerConfig>(
              config.http.oauth2[provider].tokens.refresh,
              config.tokens.refresh
            ),
            this.getSessionHandler(
              config.http.oauth2[provider].session,
              config.session
            ),
            config.logger
          )
        );
      }
    }

    if (config.http.apiKey) {
      strategies.set(
        "apiKey",
        new ApiKeyStrategy(config.http.apiKey, this.logger)
      );
    }

    if (config.http.basic) {
      strategies.set(
        "basic",
        new BasicStrategy(
          config.http.basic,
          this.getSessionHandler(config.http.basic.session, config.session),
          config.logger
        )
      );
    }

    if (config.http.local) {
      strategies.set(
        "local",
        new LocalStrategy(
          config.http.local,
          this.getSessionHandler(config.http.local.session, config.session),
          config.logger
        )
      );
    }

    if (config.http.jwt) {
      strategies.set(
        "jwt",
        new JwtStrategy(
          config.http.jwt,
          this.getSessionHandler(config.http.jwt.session, config.session),
          this.logger
        )
      );
    }

    if (config.http.custom) {
      Object.entries(config.http.custom).forEach(([key, strategy]) => {
        strategies.set(key, strategy);
      });
    }

    return strategies;
  }
}
