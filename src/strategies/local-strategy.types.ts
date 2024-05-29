import * as Soap from "@soapjs/soap";
import { SessionConfig } from "../session";
import { TokenConfig } from "../jwt";

/**
 * Local Login route configuration
 * @property {string} [failureRedirect] - Failure redirect URL.
 * @property {string} [successRedirect] - Success redirect URL.
 */
export interface LocalLoginRoute extends Soap.AuthRoute {
  failureRedirect?: string;
  successRedirect?: string;
}

/**
 * Configuration for Local Strategy
 * @typedef {Object} LocalStrategyConfig
 * @property {function} verify - Function to verify username and password.
 * @property {SessionConfig} [session] - Session configuration.
 * @property {TokenConfig} [jwt] - JWT configuration for this strategy.
 * @property {string} [failureRedirect] - Failure redirect URL.
 * @property {string} [successRedirect] - Success redirect URL.
 * @property {Object.<string, Soap.AuthRoute>} routes - Routes configuration.
 */
export interface LocalStrategyConfig {
  verify: (username: string, password: string) => Promise<any>;
  session?: SessionConfig;
  jwt?: TokenConfig;
  routes: {
    login: LocalLoginRoute;
    logout?: Soap.AuthRoute;
    [name: string]: Soap.AuthRoute;
  };
}
