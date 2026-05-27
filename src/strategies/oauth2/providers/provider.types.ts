import * as Soap from "@soapjs/soap";
import { OAuth2StrategyConfig, OAuth2Endpoints } from "../oauth2.types";

/**
 * Slim config for built-in social providers.
 *
 * `endpoints`, `grantType`, and `routes` are pre-set by each provider;
 * they can still be overridden when needed (e.g. to point at a different
 * Google API region or add extra route paths).
 */
export interface SocialProviderConfig<TUser extends Soap.AuthUser = Soap.AuthUser>
  extends Omit<
    OAuth2StrategyConfig<Soap.HttpContext, TUser>,
    "endpoints" | "grantType" | "routes"
  > {
  grantType?: "authorization_code";
  endpoints?: Partial<OAuth2Endpoints>;
  routes?: OAuth2StrategyConfig<Soap.HttpContext, TUser>["routes"];
}
