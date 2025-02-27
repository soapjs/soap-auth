import * as Soap from "@soapjs/soap";
import { BasicStrategyConfig } from "./basic.types";

export const prepareBasicConfig = <TContext = any, TUser = any>(
  config: BasicStrategyConfig<TContext, TUser>
): BasicStrategyConfig<TContext, TUser> => {
  return Soap.removeUndefinedProperties<BasicStrategyConfig<TContext, TUser>>({
    ...config,
    routes: {
      ...config.routes,
      login: {
        path: config.routes.login.path || "/auth/basic/login",
        method: config.routes.login.method || "POST",
      },
      logout: {
        path: config.routes.logout.path || "/auth/basic/logout",
        method: config.routes.logout.method || "POST",
      },
    },
  });
};
