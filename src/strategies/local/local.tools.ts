import * as Soap from "@soapjs/soap";
import { LocalStrategyConfig } from "./local.types";

export const prepareLocalConfig = <TContext = any, TUser = any>(
  config: LocalStrategyConfig<TContext, TUser>
): LocalStrategyConfig<TContext, TUser> => {

  return Soap.removeUndefinedProperties<LocalStrategyConfig<TContext, TUser>>({
    ...config,
    routes: {
      ...config.routes,
      login: {
        path: config.routes.login.path || '/auth/local/login',
        method: config.routes.login.method || 'POST'
      },
      logout: {
        path: config.routes.logout.path || '/auth/local/logout',
        method: config.routes.logout.method || 'POST'
      }
    }
  });
};
