import passport from "passport";
import { AuthStrategy } from "./auth-strategy";
import { BasicStrategyConfig } from "./basic-strategy.types";

/**
 * Class representing the basic authentication strategy for various providers.
 *
 * @extends AuthStrategy
 */
export class BasicStrategy extends AuthStrategy {
  /**
   * Creates an instance of BasicStrategy.
   *
   * @param {BasicStrategyConfig} config - The configuration options for the basic strategy.
   */
  constructor(
    private config: BasicStrategyConfig,
    private jwtId: string,
    private sessionId: string
  ) {
    super();
  }

  /**
   * Dynamically loads the basic strategy based on the provider.
   *
   * @returns {any} The loaded strategy.
   * @throws {Error} If the strategy cannot be loaded.
   */
  private getStrategy() {
    try {
      return require(`passport-http`).Strategy;
    } catch (error) {
      throw new Error(`Basic strategy failure: ${error.message}`);
    }
  }

  /**
   * Validates the configuration to ensure no conflicts between session and JWT.
   *
   * @throws {Error} If there is a conflict between session and JWT usage.
   */
  private validateConfig() {
    const { jwt, session } = this.config;
    if (jwt && session) {
      throw new Error(
        "Configuration conflict: Both session and JWT are provided. Please use only one method of authentication."
      );
    }
  }

  /**
   * Initializes the basic strategy and sets up the necessary routes and middlewares.
   */
  init(): void {
    const {
      config: { session, jwt, verify, routes },
    } = this;

    this.validateConfig();

    const BasicProviderStrategy = this.getStrategy();
    passport.use(
      new BasicProviderStrategy(
        async (username: string, password: string, done: any) => {
          try {
            const data = await verify(username, password);
            // if validation returns an error instead of throwing it
            if (data instanceof Error) {
              return done(data);
            }
            return done(null, data);
          } catch (error) {
            return done(error);
          }
        }
      )
    );

    if (session) {
      this.middlewares.setAuthenticatedOnlyMiddleware(this.sessionId);
    } else if (jwt) {
      this.middlewares.setAuthenticatedOnlyMiddleware(this.jwtId, false);
    }

    if (routes) {
      Object.keys(routes).forEach((key) => {
        this.routes.setRoute(key, routes[key]);
      });
    }
  }
}
