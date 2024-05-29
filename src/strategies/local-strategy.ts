import passport from "passport";
import { AuthStrategy } from "./auth-strategy";
import { LocalStrategyConfig } from "./local-strategy.types";

/**
 * Class representing the local authentication strategy for various providers.
 *
 * @extends AuthStrategy
 */
export class LocalStrategy extends AuthStrategy {
  /**
   * Creates an instance of LocalStrategy.
   *
   * @param {LocalStrategyConfig} config - The configuration options for the local strategy.
   */
  constructor(
    private config: LocalStrategyConfig,
    private jwtId: string,
    private sessionId: string
  ) {
    super();
  }

  /**
   * Dynamically loads the local strategy based on the provider.
   *
   * @returns {any} The loaded strategy.
   * @throws {Error} If the strategy cannot be loaded.
   */
  private getStrategy() {
    try {
      return require(`passport-local`).Strategy;
    } catch (error) {
      throw new Error(`Local strategy failure: ${error.message}`);
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
   * Initializes the local strategy and sets up the necessary routes and middlewares.
   */
  init(): void {
    const {
      config: { session, verify, jwt, routes },
    } = this;

    this.validateConfig();

    const localProviderStrategy = this.getStrategy();
    passport.use(
      new localProviderStrategy(
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
      this.middlewares.setAuthenticatedOnlyMiddleware(this.sessionId); // sessionId jest generowany przy tworzeniu strategii jezeli ma opcje session
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
