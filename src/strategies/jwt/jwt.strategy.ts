import jwt from "jsonwebtoken";
import * as Soap from "@soapjs/soap";
import { promisify } from "util";
import { TokenBasedAuthStrategy } from "../token-based-auth.strategy";
import {
  InvalidTokenError,
  UndefinedTokenError,
  UndefinedTokenSecretError,
} from "../../errors";
import { JwtConfig } from "./jwt.types";
import {
  prepareAccessTokenConfig,
  prepareRefreshTokenConfig,
} from "./jwt.tools";
import { SessionHandler } from "../../session/session-handler";

const verifyAsync = promisify(jwt.verify);

export class JwtStrategy<
  TContext = unknown,
  TUser = unknown
> extends TokenBasedAuthStrategy<TContext, TUser> {
  constructor(
    protected config: JwtConfig<TContext, TUser>,
    protected session?: SessionHandler,
    protected logger?: Soap.Logger
  ) {
    if (!config.access.secretKey) {
      throw new UndefinedTokenSecretError("Access");
    }
    if (config.refresh && !config.refresh.secretKey) {
      throw new UndefinedTokenSecretError("Refresh");
    }
    const accessTokenConfig = prepareAccessTokenConfig(config);
    const refreshTokenConfig = prepareRefreshTokenConfig(config);

    super(
      config,
      {
        ...accessTokenConfig,
        generate(payload: any) {
          return jwt.sign(
            payload,
            accessTokenConfig.secretKey,
            accessTokenConfig.signOptions
          );
        },
        verify(token: string) {
          try {
            if (!token) throw new UndefinedTokenError("Access");
            if (!accessTokenConfig.secretKey)
              throw new UndefinedTokenSecretError("Access");

            return verifyAsync(
              token,
              accessTokenConfig.secretKey,
              accessTokenConfig.verifyOptions
            );
          } catch (error) {
            this.logger?.error("JWT verification failed:", error);
            throw new InvalidTokenError("Access");
          }
        },
      },
      {
        ...refreshTokenConfig,
        generate(payload: any) {
          return jwt.sign(
            payload,
            refreshTokenConfig.secretKey,
            refreshTokenConfig.signOptions
          );
        },
        verify(token: string) {
          try {
            if (!token) throw new UndefinedTokenError("Refresh");
            if (!refreshTokenConfig.secretKey)
              throw new UndefinedTokenSecretError("Refresh");

            return verifyAsync(
              token,
              refreshTokenConfig.secretKey,
              refreshTokenConfig.verifyOptions
            );
          } catch (error) {
            this.logger?.error("JWT verification failed:", error);
            throw new InvalidTokenError("Refresh");
          }
        },
      }
    );

    this.logger?.info("JWTStrategy initialized with provided configurations.");
  }
}
