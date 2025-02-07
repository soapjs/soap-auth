import * as Soap from "@soapjs/soap";
import {
  JwtAccessTokenConfig,
  JwtConfig,
  JwtRefreshTokenConfig,
} from "./jwt.types";

export const prepareAccessTokenConfig = (
  config: JwtConfig
): JwtAccessTokenConfig => {
  return Soap.removeUndefinedProperties<any>({
    ...config.accessToken,
    tokenType: "Access",
    expiresIn: config.accessToken.expiresIn || "1h",
    signOptions: {
      ...config.accessToken.signOptions,
      algorithm: config.accessToken.signOptions.algorithm || "HS256",
      expiresIn: config.accessToken.expiresIn || "1h",
      audience: config.accessToken.audience,
      issuer: config.accessToken.issuer,
      subject: config.accessToken.subject,
    },
    verifyOptions: config.accessToken.verifyOptions
      ? {
          ...config.accessToken.verifyOptions,
          algorithms: config.accessToken.verifyOptions.algorithms || ["HS256"],
          expiresIn: config.accessToken.expiresIn || "1h",
          audience: config.accessToken.audience,
          issuer: config.accessToken.issuer,
          subject: config.accessToken.subject,
        }
      : {},
  });
};

export const prepareRefreshTokenConfig = (
  config: JwtConfig
): JwtRefreshTokenConfig => {
  return Soap.removeUndefinedProperties<any>({
    ...config.refreshToken,
    secretKey: config.refreshToken.secretKey,
    tokenType: "Refresh",
    signOptions: {
      ...config.refreshToken.signOptions,
      algorithm: config.refreshToken.signOptions.algorithm || "HS256",
      expiresIn: config.refreshToken.expiresIn || "7d",
      audience: config.refreshToken.audience,
      issuer: config.refreshToken.issuer,
      subject: config.refreshToken.subject,
    },
    verifyOptions: config.refreshToken.verifyOptions
      ? {
          ...config.refreshToken.verifyOptions,
          algorithm: config.refreshToken.verifyOptions.algorithms || ["HS256"],
          expiresIn: config.refreshToken.expiresIn || "7d",
          audience: config.refreshToken.audience,
          issuer: config.refreshToken.issuer,
          subject: config.refreshToken.subject,
        }
      : {},
  });
};
