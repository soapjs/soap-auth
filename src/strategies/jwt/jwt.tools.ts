import * as Soap from "@soapjs/soap";
import { TokenConfig } from "../../types";

export const prepareAccessTokenConfig = <TContext = any>(
  config: TokenConfig<TContext>
): TokenConfig<TContext> => {
  return Soap.removeUndefinedProperties<TokenConfig<TContext>>({
    ...config,
    generation: {
      ...config.issuer.options,
      expiresIn: config.issuer.options.expiresIn || "1h",
      algorithm: config.issuer.options.algorithm || "HS256",
    },
    verification: {
      ...config.verifier.options,
      algorithms: config.verifier.options.algorithms || ["HS256"],
      expiresIn: config.verifier.options.expiresIn || "1h",
    },
  });
};

export const prepareRefreshTokenConfig = <TContext = any>(
  config: TokenConfig<TContext>
): TokenConfig<TContext> => {
  return Soap.removeUndefinedProperties<TokenConfig<TContext>>({
    ...config,
    generation: {
      ...config.issuer,
      expiresIn: config.issuer.options.expiresIn || "7d",
      algorithm: config.issuer.options.algorithm || "HS256",
    },
    verification: {
      ...config.verifier.options,
      algorithms: config.verifier.options.algorithms || ["HS256"],
      expiresIn: config.verifier.options.expiresIn || "7d",
    },
  });
};

export const setDefaultJwtCookie = (token: string, context: any) => {
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

export const setDefaultJwtHeader = (token: string, context: any) => {
  if (typeof (context as any)?.res?.setHeader === "function") {
    (context as any).res.setHeader("Authorization", `Bearer ${token}`);
  } else if (typeof (context as any)?.response?.setHeader === "function") {
    (context as any).response.setHeader("Authorization", `Bearer ${token}`);
  } else if (typeof (context as any)?.setHeader === "function") {
    (context as any).setHeader("Authorization", `Bearer ${token}`);
  }
};

export const clearDefaultJwtHeader = (context: any) => {
  if (typeof (context as any)?.res?.setHeader === "function") {
    (context as any).res.setHeader("Authorization", ``);
  } else if (typeof (context as any)?.response?.setHeader === "function") {
    (context as any).response.setHeader("Authorization", ``);
  } else if (typeof (context as any)?.setHeader === "function") {
    (context as any).setHeader("Authorization", ``);
  }
};

export const clearDefaultJwtCookie = (context: any) => {
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
