import { describe, it, expect, jest } from "@jest/globals";
import { JwtTools } from "../jwt.tools";
import {
  UndefinedTokenError,
  UndefinedTokenSecretError,
  InvalidTokenError,
} from "../../../errors";
import { JwtConfig } from "../jwt.types";

describe("JwtTools", () => {
  const secretKey = "test-secret";
  const payload = { id: "user123", email: "test@example.com" };
  const config: JwtConfig = {
    accessToken: {
      issuer: { secretKey, options: { expiresIn: "1h" } },
      verifier: { options: {} },
    },
    refreshToken: {
      issuer: { secretKey, options: { expiresIn: "7d" } },
      verifier: { options: {} },
    },
  };

  it("should generate an access token", () => {
    const token = JwtTools.generateAccessToken(payload, config.accessToken);
    expect(typeof token).toBe("string");
  });

  it("should throw error when generating access token without secret key", () => {
    const invalidConfig: any = {
      ...config,
      accessToken: { issuer: { secretKey: "" } },
    };
    expect(() =>
      JwtTools.generateAccessToken(payload, invalidConfig.accessToken)
    ).toThrow(UndefinedTokenSecretError);
  });

  it("should generate a refresh token", () => {
    const token = JwtTools.generateRefreshToken(payload, config.refreshToken);
    expect(typeof token).toBe("string");
  });

  it("should throw error when generating refresh token without secret key", () => {
    const invalidConfig: any = {
      ...config,
      refreshToken: { issuer: { secretKey: "" } },
    };
    expect(() =>
      JwtTools.generateRefreshToken(payload, invalidConfig.refreshToken)
    ).toThrow(UndefinedTokenSecretError);
  });

  it("should verify a valid access token", () => {
    const token = JwtTools.generateAccessToken(payload, config.accessToken);
    const decoded = JwtTools.verifyAccessToken(token, config.accessToken);
    expect(decoded.id).toBe(payload.id);
  });

  it("should throw error for undefined access token", () => {
    expect(() => JwtTools.verifyAccessToken("", config.accessToken)).toThrow(
      UndefinedTokenError
    );
  });

  it("should throw error for invalid access token", () => {
    expect(() =>
      JwtTools.verifyAccessToken("invalid-token", config.accessToken)
    ).toThrow(InvalidTokenError);
  });

  it("should verify a valid refresh token", () => {
    const token = JwtTools.generateRefreshToken(payload, config.refreshToken);
    const decoded = JwtTools.verifyRefreshToken(token, config.refreshToken);
    expect(decoded.id).toBe(payload.id);
  });

  it("should throw error for undefined refresh token", () => {
    expect(() => JwtTools.verifyRefreshToken("", config.refreshToken)).toThrow(
      UndefinedTokenError
    );
  });

  it("should throw error for invalid refresh token", () => {
    expect(() =>
      JwtTools.verifyRefreshToken("invalid-token", config.refreshToken)
    ).toThrow(InvalidTokenError);
  });

  it("should set the access token in the response header", () => {
    const token = JwtTools.generateAccessToken(payload, config.accessToken);
    const context: any = { res: { setHeader: jest.fn() } };

    JwtTools.setAccessTokenHeader(token, context);
    expect(context.res.setHeader).toHaveBeenCalledWith(
      "Authorization",
      `Bearer ${token}`
    );
  });

  it("should set the refresh token in cookies", () => {
    const token = JwtTools.generateRefreshToken(payload, config.refreshToken);
    const context: any = { res: { cookie: jest.fn() } };

    JwtTools.setRefreshTokenCookie(token, context);
    expect(context.res.cookie).toHaveBeenCalledWith(
      "refreshToken",
      token,
      expect.any(Object)
    );
  });

  it("should clear tokens from headers and cookies", () => {
    const context: any = {
      res: { clearCookie: jest.fn(), setHeader: jest.fn() },
    };

    JwtTools.clearTokens(context);
    expect(context.res.clearCookie).toHaveBeenCalledWith("refreshToken");
    expect(context.res.setHeader).toHaveBeenCalledWith("Authorization", "");
  });

  it("should retrieve an access token from request headers", () => {
    const token = JwtTools.generateAccessToken(payload, config.accessToken);
    const context: any = {
      req: { headers: { authorization: `Bearer ${token}` } },
    };

    const extractedToken = JwtTools.getAccessToken(context);
    expect(extractedToken).toBe(token);
  });

  it("should retrieve a refresh token from request cookies", () => {
    const token = JwtTools.generateRefreshToken(payload, config.refreshToken);
    const context: any = { req: { cookies: { refreshToken: token } } };

    const extractedToken = JwtTools.getRefreshToken(context);
    expect(extractedToken).toBe(token);
  });
});
