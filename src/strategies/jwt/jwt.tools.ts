import * as Soap from "@soapjs/soap";
import jwt, { SignOptions } from "jsonwebtoken";
import crypto from "crypto";
import { JwtConfig } from "./jwt.types";
import {
  UndefinedTokenError,
  UndefinedTokenSecretError,
  InvalidTokenError,
} from "../../errors";
import { TokenAuthStrategyConfig, TokenConfig } from "../../types";

/**
 * JWT Tools
 *
 * Utility functions for handling JWT token operations.
 * This includes generation, verification, embedding, and retrieval of tokens.
 */
export class JwtTools {
  /**
   * Generates a new access token.
   *
   * @param {any} payload - The payload to encode in the token.
   * @param {JwtConfig["accessToken"]} config - Configuration for the access token.
   * @returns {string} The generated JWT access token.
   * @throws {UndefinedTokenSecretError} If the secret key is missing.
   */
  static generateAccessToken(
    payload: any,
    config: JwtConfig["accessToken"]
  ): string {
    if (!config.issuer.secretKey) {
      throw new UndefinedTokenSecretError("Access");
    }
    return jwt.sign(
      payload,
      config.issuer.secretKey,
      config.issuer.options as SignOptions
    );
  }

  /**
   * Generates a new refresh token.
   *
   * @param {any} payload - The payload to encode in the refresh token.
   * @param {JwtConfig["refreshToken"]} config - Configuration for the refresh token.
   * @returns {string} The generated JWT refresh token.
   * @throws {UndefinedTokenSecretError} If the secret key is missing.
   */
  static generateRefreshToken(
    payload: any,
    config: JwtConfig["refreshToken"]
  ): string {
    if (!config.issuer.secretKey) {
      throw new UndefinedTokenSecretError("Refresh");
    }
    return jwt.sign(
      payload,
      config.issuer.secretKey,
      config.issuer.options as SignOptions
    );
  }

  /**
   * Verifies and decodes the access token.
   *
   * @param {string} token - The access token to verify.
   * @param {JwtConfig["accessToken"]} config - Configuration for the access token.
   * @returns {any} The decoded token payload.
   * @throws {UndefinedTokenError} If the token is undefined.
   * @throws {UndefinedTokenSecretError} If the secret key is missing.
   * @throws {InvalidTokenError} If the token is invalid or expired.
   */
  static verifyAccessToken(
    token: string,
    config: JwtConfig["accessToken"]
  ): any {
    if (!token) throw new UndefinedTokenError("Access");
    if (!config.issuer.secretKey) throw new UndefinedTokenSecretError("Access");

    try {
      return jwt.verify(
        token,
        config.issuer.secretKey,
        config.verifier.options
      );
    } catch (error) {
      throw new InvalidTokenError("Access");
    }
  }

  /**
   * Verifies and decodes the refresh token.
   *
   * @param {string} token - The refresh token to verify.
   * @param {JwtConfig["refreshToken"]} config - Configuration for the refresh token.
   * @returns {any} The decoded token payload.
   * @throws {UndefinedTokenError} If the token is undefined.
   * @throws {UndefinedTokenSecretError} If the secret key is missing.
   * @throws {InvalidTokenError} If the token is invalid, expired, or revoked.
   */
  static verifyRefreshToken(
    token: string,
    config: JwtConfig["refreshToken"]
  ): any {
    if (!token) throw new UndefinedTokenError("Refresh");
    if (!config.issuer.secretKey)
      throw new UndefinedTokenSecretError("Refresh");

    try {
      return jwt.verify(
        token,
        config.issuer.secretKey,
        config.verifier.options
      );
    } catch (error) {
      throw new InvalidTokenError("Refresh");
    }
  }

  /**
   * Embeds the access token into the response headers.
   *
   * @param {string} token - The access token to embed.
   * @param {any} context - The authentication context (Express request/response).
   */
  static setAccessTokenHeader(token: string, context: any): void {
    context.res.setHeader("Authorization", `Bearer ${token}`);
  }

  /**
   * Embeds the refresh token into cookies for secure storage.
   *
   * @param {string} token - The refresh token to embed.
   * @param {any} context - The authentication context (Express request/response).
   */
  static setRefreshTokenCookie(token: string, context: any): void {
    context.res.cookie("refreshToken", token, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
    });
  }

  /**
   * Clears the JWT tokens from headers and cookies.
   *
   * @param {any} context - The authentication context (Express request/response).
   */
  static clearTokens(context: any): void {
    context.res.clearCookie("refreshToken");
    context.res.setHeader("Authorization", "");
  }

  /**
   * Retrieves the access token from the request headers.
   *
   * @param {any} context - The authentication context (Express request).
   * @returns {string | undefined} The access token, if available.
   */
  static getAccessToken(context: any): string | undefined {
    return context.req.headers.authorization?.split(" ")[1];
  }

  /**
   * Retrieves the refresh token from the request cookies.
   *
   * @param {any} context - The authentication context (Express request).
   * @returns {string | undefined} The refresh token, if available.
   */
  static getRefreshToken(context: any): string | undefined {
    return context.req.cookies?.refreshToken;
  }

  static prepareAccessTokenConfig = <TContext = any>(
    config: TokenConfig<TContext>
  ): TokenConfig<TContext> => {
    return Soap.removeUndefinedProperties<TokenConfig<TContext>>({
      ...config,
      issuer: {
        ...config.issuer,
        options: {
          ...config.issuer.options,
          expiresIn: config.issuer.options.expiresIn || "1h",
          algorithm: config.issuer.options.algorithm || "HS256",
        },
      },
      verifier: {
        ...config.verifier,
        options: {
          ...config.verifier.options,
          algorithms: config.verifier.options.algorithms || ["HS256"],
          expiresIn: config.verifier.options.expiresIn || "1h",
        },
      },
    });
  };

  static prepareRefreshTokenConfig = <TContext = any>(
    config: TokenConfig<TContext>
  ): TokenConfig<TContext> => {
    return Soap.removeUndefinedProperties<TokenConfig<TContext>>({
      ...config,
      issuer: {
        ...config.issuer,
        options: {
          ...config.issuer.options,
          expiresIn: config.issuer.options.expiresIn || "7d",
          algorithm: config.issuer.options.algorithm || "HS256",
        },
      },
      verifier: {
        ...config.verifier,
        options: {
          ...config.verifier.options,
          algorithms: config.verifier.options.algorithms || ["HS256"],
          expiresIn: config.verifier.options.expiresIn || "7d",
        },
      },
    });
  };

  static setDefaultJwtCookie = (token: string, context: any) => {
    const options = {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7d
    };

    if (context?.res) {
      context.res.cookie("refreshToken", token, options);
    } else if (context?.response) {
      context.response.cookie("refreshToken", token, options);
    } else if (context?.cookie) {
      context.cookie("refreshToken", token, options);
    }
  };

  static setDefaultJwtHeader = (token: string, context: any) => {
    if (typeof (context as any)?.res?.setHeader === "function") {
      (context as any).res.setHeader("Authorization", `Bearer ${token}`);
    } else if (typeof (context as any)?.response?.setHeader === "function") {
      (context as any).response.setHeader("Authorization", `Bearer ${token}`);
    } else if (typeof (context as any)?.setHeader === "function") {
      (context as any).setHeader("Authorization", `Bearer ${token}`);
    }
  };

  static clearDefaultJwtHeader = (context: any) => {
    if (typeof (context as any)?.res?.setHeader === "function") {
      (context as any).res.setHeader("Authorization", ``);
    } else if (typeof (context as any)?.response?.setHeader === "function") {
      (context as any).response.setHeader("Authorization", ``);
    } else if (typeof (context as any)?.setHeader === "function") {
      (context as any).setHeader("Authorization", ``);
    }
  };

  static clearDefaultJwtCookie = (context: any) => {
    const options = {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
    };

    if (typeof context?.res?.clearCookie === "function") {
      context.res.clearCookie("refreshToken", options);
    } else if (typeof context?.response?.clearCookie === "function") {
      context.response.clearCookie("refreshToken", options);
    } else if (typeof context?.clearCookie === "function") {
      context.clearCookie("refreshToken", options);
    }
  };
}

export const prepareJwtConfig = <TContext = any, TUser = any>(
  config: Partial<TokenAuthStrategyConfig<TContext, TUser>>
): TokenAuthStrategyConfig<TContext, TUser> => {
  return Soap.removeUndefinedProperties<
    TokenAuthStrategyConfig<TContext, TUser>
  >({
    ...config,
    routes: {
      login: config.routes?.login ?? {
        path: "/auth/jwt/login",
        method: "POST",
      },
      logout: config.routes?.logout ?? {
        path: "/auth/jwt/logout",
        method: "POST",
      },
      refresh: config.routes?.refresh ?? {
        path: "/auth/jwt/refresh",
        method: "POST",
      },
      ...config.routes,

      user: {
        ...config.user,
        validateUser:
          config.user?.validateUser ?? (() => Promise.resolve(true)),
      },
      accessToken: JwtTools.prepareAccessTokenConfig(config.accessToken),
      refreshToken: config.refreshToken
        ? JwtTools.prepareRefreshTokenConfig(config.refreshToken)
        : undefined,
    },
  });
};
