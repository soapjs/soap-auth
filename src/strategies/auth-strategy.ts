import * as Soap from "@soapjs/soap";
import { AuthMiddlewareRegistry } from "../middlewares";

/**
 * Abstract class representing an authentication strategy.
 *
 * @implements {Soap.ApiAuthStrategy}
 */
export abstract class AuthStrategy implements Soap.ApiAuthStrategy {
  /**
   * A map of middleware used by the authentication strategy.
   * @type {Map<string, Soap.Middleware>}
   */
  middlewares = new AuthMiddlewareRegistry();

  /**
   * A map of routes used by the authentication strategy.
   * @type {AuthRouteRegistry}
   */
  routes = new Soap.AuthRouteRegistry();

  /**
   * Initializes the authentication strategy.
   * This method should be implemented by subclasses.
   */
  abstract init(): void;
}
