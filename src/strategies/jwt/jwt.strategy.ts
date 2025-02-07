import jwt from "jsonwebtoken";
import * as Soap from "@soapjs/soap";
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

export class JwtStrategy<
  TContext = unknown,
  TUser = unknown
> extends TokenBasedAuthStrategy<TContext, TUser> {
  constructor(
    protected config: JwtConfig<TContext, TUser>,
    protected session?: SessionHandler,
    protected logger?: Soap.Logger
  ) {
    if (!config.accessToken.secretKey) {
      throw new UndefinedTokenSecretError("Access");
    }
    if (config.refreshToken && !config.refreshToken.secretKey) {
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

            return new Promise((resolve, reject) => {
              jwt.verify(
                token,
                accessTokenConfig.secretKey,
                accessTokenConfig.verifyOptions,
                (err, payload) => {
                  if (err) reject(err);
                  else resolve(payload);
                }
              );
            });
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

            return new Promise((resolve, reject) => {
              jwt.verify(
                token,
                refreshTokenConfig.secretKey,
                refreshTokenConfig.verifyOptions,
                (err, payload) => {
                  if (err) reject(err);
                  else resolve(payload);
                }
              );
            });
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
