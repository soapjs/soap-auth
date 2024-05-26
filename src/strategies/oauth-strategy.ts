import passport from "passport";
import { OAuthConfig } from "../config";
import { AuthStrategy } from "./auth-strategy";
import { JwtTools } from "../jwt";
import { StrategyType } from "./enums";

/**
 * Class representing an OAuth authentication strategy for various providers.
 *
 * @extends AuthStrategy
 */
export class OAuthStrategy extends AuthStrategy {
  /**
   * Creates an instance of OAuthStrategy.
   *
   * @param {OAuthConfig} config - The configuration options for the OAuth strategy.
   * @param {JwtTools} jwt - The JWT utility for generating tokens.
   */
  constructor(
    private provider: string,
    private config: OAuthConfig,
    private jwt: JwtTools
  ) {
    super();
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
      return require(`passport-${provider}`).Strategy;
    } catch (error) {
      throw new Error(`${provider} strategy failure: ${error.message}`);
    }
  }

  /**
   * Initializes the OAuth strategy and sets up the necessary routes and middlewares.
   */
  init(): void {
    const {
      provider,
      config: {
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
      },
    } = this;

    const OAuthProviderStrategy = this.getStrategy(provider);

    passport.use(
      new OAuthProviderStrategy(
        {
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
            if (useOwnJWT) {
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
        handler: passport.authenticate(provider, { session }),
      });
    }

    const parsedCallbackUrl = new URL(callbackURL);

    this.routes.setLoginCallbackRoute({
      path: `${parsedCallbackUrl.pathname}${parsedCallbackUrl.search}`,
      method: "get",
      middlewares: [
        passport.authenticate(provider, {
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
      });
    }
  }
}
