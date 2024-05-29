import * as Soap from "@soapjs/soap";
import { TokenConfig } from "../jwt";

/**
 * Configuration for Bearer Strategy
 * @typedef {Object} TokenStrategyConfig
 * @property {TokenConfig} [jwt] - JWT configuration for this strategy.
 * @property {Object.<string, Soap.AuthRoute>} routes - Routes configuration.
 */
export interface TokenStrategyConfig {
  jwt: TokenConfig;
  routes?: {
    login?: Soap.AuthRoute;
    logout?: Soap.AuthRoute;
    [key: string]: Soap.AuthRoute;
  };
}
