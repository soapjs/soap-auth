import passport from "passport";
import { BasicStrategyConfig } from "../config";
import { AuthStrategy } from "./auth-strategy";
import { StrategyType } from "./enums";

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
  constructor(private config: BasicStrategyConfig) {
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
   * Initializes the basic strategy and sets up the necessary routes and middlewares.
   */
  init(): void {
    const {
      config: { session, verify },
    } = this;
    const BasicProviderStrategy = this.getStrategy();
    passport.use(
      new BasicProviderStrategy(
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

    this.middlewares.setAuthenticatedOnlyMiddleware(
      StrategyType.Basic,
      session
    );
  }
}
