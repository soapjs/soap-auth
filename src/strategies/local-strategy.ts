import passport from "passport";
import { LocalStrategyConfig } from "../config";
import { AuthStrategy } from "./auth-strategy";
import { StrategyType } from "./enums";

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
  constructor(private config: LocalStrategyConfig) {
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
   * Initializes the local strategy and sets up the necessary routes and middlewares.
   */
  init(): void {
    const {
      config: {
        session,
        verify,
        useOwnJWT,
        login,
        logout,
        failureRedirect,
        successRedirect,
      },
    } = this;
    const localProviderStrategy = this.getStrategy();
    passport.use(
      new localProviderStrategy(
        async (username: string, password: string, done: any) => {
          try {
            const data = await verify(username, password);
            return done(null, data);
          } catch (error) {
            return done(error);
          }
        }
      )
    );

    if (useOwnJWT) {
      this.middlewares.setAuthenticatedOnlyMiddleware(StrategyType.JWT, false);
    } else {
      this.middlewares.setAuthenticatedOnlyMiddleware(
        StrategyType.Local,
        session
      );
    }

    if (login) {
      const { handler, ...rest } = login;
      this.routes.setLoginRoute({
        ...rest,
        handler:
          handler || passport.authenticate(StrategyType.Local, { session }),
      });
    }

    if (logout) {
      this.routes.setLogoutRoute(logout);
    }
  }
}
