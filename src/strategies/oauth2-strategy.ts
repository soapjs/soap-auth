import passport from "passport";

import { OAuth2Config } from "../config";
import { AuthStrategy } from "./auth-strategy";
import { JwtTools } from "../jwt";
import { StrategyType } from "./enums";

/**
 * Class representing an OAuth2 authentication strategy.
 *
 * @extends AuthStrategy
 */
export class OAuth2Strategy extends AuthStrategy {
  /**
   * Creates an instance of OAuth2Strategy.
   *
   * @param {OAuth2Config} config - The configuration options for the OAuth2 strategy.
   * @param {JwtTools} jwt - The JWT utility for generating tokens.
   */
  constructor(private config: OAuth2Config, private jwt: JwtTools) {
    super();
  }

  /**
   * Dynamically loads the OAuth2 strategy.
   *
   * @param {string} name - The name of the strategy to load.
   * @returns {any} The loaded strategy.
   * @throws {Error} If the strategy cannot be loaded.
   */
  private getStrategy(name: string) {
    try {
      return require(name).Strategy;
    } catch (error) {
      throw new Error(`${name} strategy failure: ${error.message}`);
    }
  }

  /**
   * Initializes the OAuth2 strategy and sets up the necessary routes and middlewares.
   */
  init(): void {
    const OAuth2Strategy = this.getStrategy("passport-oauth2");
    const {
      authorizationURL,
      tokenURL,
      clientID,
      clientSecret,
      callbackURL,
      session,
      verify,
      login,
      logout,
      scope,
      useOwnJWT,
      failureRedirect,
      successRedirect,
    } = this.config;

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
            const user = await verify(accessToken, refreshToken, profile);
            if (useOwnJWT && this.jwt) {
              const token = this.jwt.generateToken(user);
              const refreshToken = this.jwt.generateRefreshToken(user);
              return done(null, { user, token, refreshToken });
            }
            return done(null, user);
          } catch (error) {
            return done(error);
          }
        }
      )
    );

    if (useOwnJWT) {
      this.middlewares.setAuthenticatedOnlyMiddleware(StrategyType.JWT);
    } else if (session) {
      this.middlewares.setAuthenticatedOnlyMiddleware(StrategyType.Session);
    }

    if (login) {
      this.routes.setLoginRoute({
        ...login,
        middlewares: [],
        handler: passport.authenticate(StrategyType.OAuth2, { session }),
      });
    }

    const parsedCallbackUrl = new URL(callbackURL);

    this.routes.setLoginCallbackRoute({
      path: `${parsedCallbackUrl.pathname}${parsedCallbackUrl.search}`,
      method: "get",
      middlewares: [
        passport.authenticate(StrategyType.OAuth2, {
          failureRedirect,
          session,
        }),
      ],
      handler: function (req, res, next) {
        if (successRedirect) {
          res.redirect(successRedirect);
        } else {
          next();
        }
      },
    });

    if (logout) {
      this.routes.setLogoutRoute({
        ...logout,
        middlewares: [],
        handler: passport.authenticate(StrategyType.OAuth2, { session }),
      });
    }
  }
}
