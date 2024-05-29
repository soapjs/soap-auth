import passport from "passport";

import { AuthStrategy } from "./auth-strategy";
import { JwtTools } from "../jwt";
import { StrategyType } from "./enums";
import { OAuth2Config } from "./oauth2-strategy.types";

/**
 * Class representing an OAuth2 authentication strategy.
 *
 * @extends AuthStrategy
 */
export class OAuth2Strategy extends AuthStrategy {
  private jwtTools: JwtTools;
  /**
   * Creates an instance of OAuth2Strategy.
   *
   * @param {OAuth2Config} config - The configuration options for the OAuth2 strategy.
   */
  constructor(
    private config: OAuth2Config,
    private jwtId: string,
    private sessionId: string
  ) {
    super();

    if (config.jwt) {
      this.jwtTools = new JwtTools(config.jwt);
    }
  }

  /**
   * Dynamically loads the OAuth strategy based on the provider.
   *
   * @param {string} provider - The name of the OAuth provider.
   * @returns {any} The loaded strategy.
   * @throws {Error} If the strategy cannot be loaded.
   */
  private getStrategy(provider: string) {
    try {
      return require(provider).Strategy;
    } catch (error) {
      throw new Error(`OAuth2 ${provider} strategy failure: ${error.message}`);
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
   * Initializes the OAuth2 strategy and sets up the necessary routes and middlewares.
   */
  init(): void {
    const OAuth2Strategy = this.getStrategy("passport-oauth2");
    const {
      jwtTools,
      config: {
        authorizationURL,
        tokenURL,
        clientID,
        clientSecret,
        callbackURL,
        session,
        verify,
        scope,
        jwt,
        routes,
      },
    } = this;

    this.validateConfig();

    passport.use(
      new OAuth2Strategy(
        {
          authorizationURL,
          tokenURL,
          clientID,
          clientSecret,
          callbackURL,
          scope,
        },
        async (
          accessToken: string,
          refreshToken: string,
          profile: any,
          done: any
        ) => {
          try {
            const data = await verify(accessToken, refreshToken, profile);
            if (jwt) {
              const token = jwtTools.generateToken(data);
              const refreshToken = jwtTools.generateRefreshToken(data);
              return done(null, { data, token, refreshToken });
            }
            return done(null, data);
          } catch (error) {
            return done(error);
          }
        }
      )
    );

    if (jwt) {
      this.middlewares.setAuthenticatedOnlyMiddleware(this.jwtId, false);
    } else if (session) {
      this.middlewares.setAuthenticatedOnlyMiddleware(this.sessionId);
    }

    if (routes) {
      Object.keys(routes).forEach((key) => {
        this.routes.setRoute(key, routes[key]);
      });
    }
  }
}
