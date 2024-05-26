import passport from "passport";
import { BearerStrategyConfig } from "../config";
import { AuthStrategy } from "./auth-strategy";
import { JwtTools } from "../jwt";
import { StrategyType } from "./enums";

export const defaultLogoutHandler = (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.status(200).json({ message: "Logged out successfully" });
  });
};

export const defaultRefreshTokenHandler =
  (jwt: JwtTools) => async (req, res, next) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ message: "Refresh token is required" });
    }

    const result = await jwt.verifyRefreshToken(refreshToken);

    if (result instanceof Error) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    const newToken = jwt.generateToken(result);
    const newRefreshToken = jwt.generateRefreshToken(result);

    res.json({ token: newToken, refreshToken: newRefreshToken });
  };

/**
 * Class representing an Bearer authentication strategy for various providers.
 *
 * @extends AuthStrategy
 */
export class BearerStrategy extends AuthStrategy {
  /**
   * Creates an instance of BearerStrategy.
   *
   * @param {BearerStrategyConfig} config - The configuration options for the bearer strategy.
   */
  constructor(private config: BearerStrategyConfig, private jwt: JwtTools) {
    super();
  }

  /**
   * Dynamically loads the bearer strategy based on the provider.
   *
   * @returns {any} The loaded strategy.
   * @throws {Error} If the strategy cannot be loaded.
   */
  private getStrategy() {
    try {
      return require(`passport-http-bearer`).Strategy;
    } catch (error) {
      throw new Error(`Bearer strategy failure: ${error.message}`);
    }
  }

  /**
   * Initializes the bearer strategy and sets up the necessary routes and middlewares.
   */
  init(): void {
    const {
      jwt,
      config: { verify, useOwnJWT, login, logout, refreshToken, session },
    } = this;
    const BearerProviderStrategy = this.getStrategy();
    passport.use(
      new BearerProviderStrategy(async (token: string, done: any) => {
        try {
          const data = await verify(token);
          if (useOwnJWT) {
            const jwtToken = jwt.generateToken(data);
            const jwtRefreshToken = jwt.generateRefreshToken(data);

            return done(null, {
              data,
              token: jwtToken,
              refreshToken: jwtRefreshToken,
            });
          }
          return done(null, data);
        } catch (error) {
          return done(error);
        }
      })
    );

    if (useOwnJWT) {
      this.middlewares.setAuthenticatedOnlyMiddleware(StrategyType.JWT, false);
    } else {
      this.middlewares.setAuthenticatedOnlyMiddleware(
        StrategyType.Bearer,
        session
      );
    }

    if (login) {
      const { handler, ...rest } = login;
      this.routes.setLoginRoute({
        ...rest,
        handler:
          handler || passport.authenticate(StrategyType.Bearer, { session }),
      });
    }

    if (logout) {
      const { handler, ...rest } = logout;
      this.routes.setLogoutRoute({
        ...rest,
        handler: handler || defaultLogoutHandler,
      });
    }

    if (refreshToken) {
      const { handler, ...rest } = refreshToken;
      this.routes.setRefreshTokenRoute({
        ...rest,
        handler: handler || defaultRefreshTokenHandler(jwt),
      });
    }
  }
}
