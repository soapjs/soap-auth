import passport from "passport";
import { ApiKeyStrategyConfig } from "../config";
import { AuthStrategy } from "./auth-strategy";

/**
 * Class representing an ApiKey authentication strategy for various providers.
 *
 * @extends AuthStrategy
 */
export class ApiKeyStrategy extends AuthStrategy {
  /**
   * Creates an instance of ApiKeyStrategy.
   *
   * @param {ApiKeyStrategyConfig} config - The configuration options for the api-key strategy.
   */
  constructor(private config: ApiKeyStrategyConfig) {
    super();
  }

  /**
   * Dynamically loads the api-key strategy based on the provider.
   *
   * @returns {any} The loaded strategy.
   * @throws {Error} If the strategy cannot be loaded.
   */
  private getStrategy() {
    try {
      return require(`passport-custom`).Strategy;
    } catch (error) {
      throw new Error(`ApiKey strategy failure: ${error.message}`);
    }
  }

  /**
   * Initializes the api-key strategy and sets up the necessary routes and middlewares.
   */
  init(): void {
    const {
      config: { headerName, queryParamName, bodyParamName, session, validate },
    } = this;
    const ApiKeyProviderStrategy = this.getStrategy();
    passport.use(
      "api-key",
      new ApiKeyProviderStrategy(async (req, done) => {
        let apiKey: string;
        if (headerName && req.headers[headerName]) {
          apiKey = req.headers[headerName] as string;
        } else if (req.headers["x-api-key"]) {
          apiKey = req.headers["x-api-key"] as string;
        } else if (queryParamName && req.query[queryParamName]) {
          apiKey = req.query[queryParamName] as string;
        } else if (bodyParamName && req.body[bodyParamName]) {
          apiKey = req.body[bodyParamName] as string;
        }

        if (!apiKey) {
          return done(new Error("API Key not provided"));
        }

        try {
          const result = await validate(apiKey);
          return done(null, result);
        } catch (error) {
          return done(error);
        }
      })
    );
  }
}
