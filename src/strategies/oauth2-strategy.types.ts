import * as Soap from "@soapjs/soap";
import { SessionConfig } from "../session";
import { TokenConfig } from "../jwt";

export interface OAuth2Config {
  authenticateOptions: {
    scope?: string[];
    authType?: string;
    [key: string]: unknown;
  };
  strategyOptions: {
    authorizationURL?: string;
    tokenURL?: string;
    clientID?: string;
    clientSecret?: string;
    callbackURL?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
  verify: (
    accessToken: string,
    refreshToken: string,
    profile: any,
    ...args: unknown[]
  ) => Promise<any>;
  session?: SessionConfig;
  jwt?: TokenConfig;
  routes: {
    login: OAuth2LoginRoute;
    loginCallback: OAuth2LoginCallbackRoute;
    [name: string]: Soap.AuthRoute;
  };
}

export interface OAuth2LoginRoute extends Soap.AuthRoute {}

export interface OAuth2LoginCallbackRoute extends Soap.AuthRoute {
  failureRedirect?: string;
  successRedirect?: string;
}
