import * as Soap from "@soapjs/soap";
import { ApiKeyStrategyConfig } from "./api-key.types";

export const prepareApiKeyConfig = <TContext = any, TUser = any>(
  config: Partial<ApiKeyStrategyConfig<TContext, TUser>>
): ApiKeyStrategyConfig<TContext, TUser> => {
  return Soap.removeUndefinedProperties<ApiKeyStrategyConfig<TContext, TUser>>({
    ...config,
    keyType: config.keyType || "long-term",
    retrieveUserMaxRetries: config.retrieveUserMaxRetries ?? 3,
    retrieveUserRetryDelay: config.retrieveUserRetryDelay ?? 1000,
    sessionDuration: config.sessionDuration ?? 3600,
    longTermDuration: config.longTermDuration ?? 86400,
    trackApiKeyUsage: config.trackApiKeyUsage || (() => Promise.resolve()),
  });
};
