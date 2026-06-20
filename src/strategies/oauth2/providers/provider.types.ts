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

/**
 * Config for arbitrary OAuth2/OIDC providers that should work without writing a
 * custom strategy class. Provide endpoints and a `user.validateUser` mapper when
 * the provider profile shape does not match the default AuthUser fields.
 */
export interface ConfigurableOAuth2StrategyConfig<
  TUser extends Soap.AuthUser = Soap.AuthUser
> extends OAuth2StrategyConfig<Soap.HttpContext, TUser> {
  name: string;
}
