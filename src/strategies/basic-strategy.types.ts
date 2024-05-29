import * as Soap from "@soapjs/soap";
import { SessionConfig } from "../session";
import { TokenConfig } from "../jwt";

/**
 * Basic Login route configuration
 * @property {string} [failureRedirect] - Failure redirect URL.
 * @property {string} [successRedirect] - Success redirect URL.
 */
export interface BasicLoginRoute extends Soap.AuthRoute {
  failureRedirect?: string;
  successRedirect?: string;
}

/**
 * Configuration for Basic Strategy
 * @typedef {Object} BasicStrategyConfig
 * @property {function} verify - Function to verify username and password.
 * @property {SessionConfig} [session] - Session configuration for this strategy.
 * @property {TokenConfig} [jwt] - JWT configuration for this strategy.
 * @property {Object.<string, Soap.AuthRoute>} routes - Routes configuration.
 */
export interface BasicStrategyConfig {
  verify: (username: string, password: string) => Promise<any>;
  session?: SessionConfig;
  jwt?: TokenConfig;
  routes: {
    login: BasicLoginRoute;
    logout?: Soap.AuthRoute;
    [name: string]: Soap.AuthRoute;
  };
}
