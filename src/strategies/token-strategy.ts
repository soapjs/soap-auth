import passport from "passport";
import * as Soap from "@soapjs/soap";
import { ExtractJwt, StrategyOptions } from "passport-jwt";

import { AuthStrategy } from "./auth-strategy";
import { TokenConfig } from "../jwt";
import { TokenStrategyConfig } from "./token-strategy.types";

export const generateJwtStrategyOptions = (
  jwtConfig: TokenConfig
): StrategyOptions => {
  const {
    storage: { method, ...options },
  } = jwtConfig;
  let extractor;
  switch (method) {
    case "header": {
      extractor =
        options.headerOptions.extractor ||
        ExtractJwt.fromAuthHeaderWithScheme(
          options.headerOptions.scheme || "Bearer"
        );
      break;
    }

    case "cookie": {
      if (options.cookieOptions.extractor) {
        extractor = options.cookieOptions.extractor;
      } else {
        extractor = (ctx) =>
          ctx.cookies[options.cookieOptions?.cookieName || "token"];
      }
      break;
    }

    case "query": {
      extractor =
        options.queryOptions.extractor ||
        ExtractJwt.fromUrlQueryParameter(options.queryOptions.name || "token");
      break;
    }

    case "body": {
      if (options.bodyOptions.extractor) {
        extractor = options.bodyOptions.extractor;
      } else {
        extractor = (req) => req.body[options.bodyOptions?.name || "token"];
      }
      break;
    }

    case "database": {
      throw new Error(
        "In this context, a database is an invalid storage method"
      );
    }

    case "session": {
      if (options.sessionOptions.extractor) {
        extractor = options.sessionOptions.extractor;
      } else {
        extractor = (req) =>
          req.session[options.sessionOptions?.name || "token"];
      }
      break;
    }

    default:
      throw new Error("Invalid storage method");
  }

  return Soap.removeUndefinedProperties({
    jwtFromRequest: extractor,
    secretOrKey: jwtConfig.secretOrKey,
    issuer: jwtConfig.issuer,
    audience: jwtConfig.audience,
    algorithms: jwtConfig.algorithms,
    ignoreExpiration: jwtConfig.ignoreExpiration,
  });
};

/**
 * Class representing an token authentication strategy for various providers.
 *
 * @extends AuthStrategy
 */
export class TokenStrategy extends AuthStrategy {
  /**
   * Creates an instance of TokenStrategy.
   *
   * @param {TokenStrategyConfig} config - The configuration options for the token strategy.
   */
  constructor(private config: TokenStrategyConfig, private jwtId = "jwt") {
    super();
  }

  /**
   * Dynamically loads the token strategy based on the provider.
   *
   * @returns {any} The loaded strategy.
   * @throws {Error} If the strategy cannot be loaded.
   */
  private getStrategy() {
    try {
      return require(`passport-jwt`).Strategy;
    } catch (error) {
      throw new Error(`token strategy failure: ${error.message}`);
    }
  }

  /**
   * Initializes the token strategy and sets up the necessary routes and middlewares.
   */
  init(): void {
    const {
      config: { routes, jwt },
    } = this;

    if (!jwt) {
      throw new Error("JWT configuration is required");
    }

    const options = generateJwtStrategyOptions(jwt);
    const tokenProviderStrategy = this.getStrategy();
    passport.use(
      new tokenProviderStrategy(
        options,
        async (payload: any, done: Soap.AnyFunction) => {
          try {
            const result = jwt.dataProvider
              ? await jwt.dataProvider(payload)
              : true;

            if (!result) {
              return done(null, false);
            }

            return done(null, result);
          } catch (error) {
            return done(error);
          }
        }
      )
    );

    this.middlewares.setAuthenticatedOnlyMiddleware(this.jwtId, false);

    if (routes) {
      Object.keys(routes).forEach((key) => {
        this.routes.setRoute(key, routes[key]);
      });
    }
  }
}
