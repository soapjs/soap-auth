import * as Soap from "@soapjs/soap";
import {
  JwtAccessTokenHandlerConfig,
  JwtConfig,
  JwtRefreshTokenHandlerConfig,
} from "./jwt.types";

export const prepareAccessTokenConfig = (
  config: JwtConfig
): JwtAccessTokenHandlerConfig => {
  return Soap.removeUndefinedProperties<any>({
    ...config.access,
    tokenType: "Access",
    expiresIn: config.access.expiresIn || "1h",
    signOptions: {
      ...config.access.signOptions,
      algorithm: config.access.signOptions.algorithm || "HS256",
      expiresIn: config.access.expiresIn || "1h",
      audience: config.access.audience,
      issuer: config.access.issuer,
      subject: config.access.subject,
    },
    verifyOptions: config.access.verifyOptions
      ? {
          ...config.access.verifyOptions,
          algorithms: config.access.verifyOptions.algorithms || ["HS256"],
          expiresIn: config.access.expiresIn || "1h",
          audience: config.access.audience,
          issuer: config.access.issuer,
          subject: config.access.subject,
        }
      : {},
  });
};

export const prepareRefreshTokenConfig = (
  config: JwtConfig
): JwtRefreshTokenHandlerConfig => {
  return Soap.removeUndefinedProperties<any>({
    ...config.refresh,
    secretKey: config.refresh.secretKey,
    tokenType: "Refresh",
    signOptions: {
      ...config.refresh.signOptions,
      algorithm: config.refresh.signOptions.algorithm || "HS256",
      expiresIn: config.refresh.expiresIn || "7d",
      audience: config.refresh.audience,
      issuer: config.refresh.issuer,
      subject: config.refresh.subject,
    },
    verifyOptions: config.refresh.verifyOptions
      ? {
          ...config.refresh.verifyOptions,
          algorithm: config.refresh.verifyOptions.algorithms || ["HS256"],
          expiresIn: config.refresh.expiresIn || "7d",
          audience: config.refresh.audience,
          issuer: config.refresh.issuer,
          subject: config.refresh.subject,
        }
      : {},
  });
};
