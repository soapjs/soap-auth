import * as Soap from "@soapjs/soap";
import { SessionConfig } from "../session";

/**
 * Configuration for Web3 Strategy
 * @typedef {Object} Web3StrategyConfig
 * @property {function} verify - Function to verify the Web3 address and signature.
 * @property {SessionConfig} [session] - Session configuration.
 * @property {string} [failureRedirect] - Failure redirect URL.
 * @property {string} [successRedirect] - Success redirect URL.
 * @property {Object.<string, Soap.AuthRoute>} routes - Routes configuration.
 */
export interface Web3StrategyConfig {
  verify: (
    address: string,
    signature: string,
    done: (error: any, user?: any) => void
  ) => void;
  session?: SessionConfig;
  failureRedirect?: string;
  successRedirect?: string;
  routes: {
    login?: Soap.AuthRoute;
    logout?: Soap.AuthRoute;
    [key: string]: Soap.AuthRoute;
  };
}
