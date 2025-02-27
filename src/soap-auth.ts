import * as Soap from "@soapjs/soap";
import { AuthResult, AuthStrategy, SoapAuthConfig } from "./types";

/**
 * Core class for soap-auth that manages and initializes various authentication strategies.
 */
export class SoapAuth {
  private requiredStrategyMethods = ["authenticate", "init"];
  private strategies = new Map<"http" | "socket", Map<string, AuthStrategy>>();
  private logger?: Soap.Logger;
  /**
   * Constructs an instance of SoapAuth, setting up strategies based on provided configuration.
   * @param {SoapAuthConfig} config - Configuration object specifying strategies and their options.
   */
  constructor(config: SoapAuthConfig) {
    this.strategies.set("http", new Map<string, AuthStrategy>());
    this.strategies.set("socket", new Map<string, AuthStrategy>());
    this.logger = config.logger;
  }

  /**
   * Determines whether the provided object conforms to the AuthStrategy interface.
   * @param {unknown} strategy - The object to check.
   * @returns {boolean} True if the object implements required methods, otherwise false.
   */
  private isAuthStrategy(strategy: unknown) {
    return (
      typeof strategy === "object" &&
      strategy !== null &&
      this.requiredStrategyMethods.every(
        (method) => typeof strategy[method] === "function"
      )
    );
  }

  /**
   * Adds an authentication strategy to the specified strategies map.
   * @param {string} type - The identifier for the strategy type.
   * @param {AuthStrategy | undefined} strategyInstance - The strategy instance to add.
   */
  addStrategy(
    strategyInstance: AuthStrategy | undefined,
    name: string,
    type: "http" | "socket"
  ) {
    if (!this.strategies.has(type)) {
      throw new Error(
        `Invalid strategy type "${type}". Expected "http" or "socket".`
      );
    }
    if (this.isAuthStrategy(strategyInstance)) {
      this.strategies.get(type).set(name, strategyInstance);
    } else {
      this.logger?.error("Invalid authentication strategy provided.");
      throw new Error(
        "Invalid authentication strategy: does not implement required methods."
      );
    }
  }

  /**
   * Removes an authentication strategy from the registered strategies.
   * @param {string} name - The identifier for the strategy type.
   * @returns {boolean} True if the strategy was removed, otherwise false.
   */
  removeStrategy(name: string | string[], type: "http" | "socket") {
    if (!this.strategies.has(type)) {
      throw new Error(
        `Invalid strategy type "${type}". Expected "http" or "socket".`
      );
    }
    const names = Array.isArray(name) ? name : [name];
    names.forEach((n) => {
      this.strategies.get(type).delete(n);
    });
  }

  /**
   * Checks if a specific authentication strategy is registered.
   * @param {string} name - The identifier for the strategy type.
   * @returns {boolean} True if the strategy exists, otherwise false.
   */
  hasStrategy(name: string, type: "http" | "socket"): boolean {
    if (!this.strategies.has(type)) {
      throw new Error(
        `Invalid strategy type "${type}". Expected "http" or "socket".`
      );
    }
    return this.strategies.get(type).has(name);
  }

  /**
   * Retrieves an authentication strategy by name from either HTTP or WebSocket strategies.
   *
   * @param {string} name - The strategy identifier.
   * @returns {AuthStrategy} The authentication strategy or throws error if not found.
   */
  getStrategy(name: string, type: "http" | "socket"): AuthStrategy | undefined {
    if (!this.strategies.has(type)) {
      throw new Error(
        `Invalid strategy type "${type}". Expected "http" or "socket".`
      );
    }

    const strategy = this.strategies.get(type).get(name);

    if (!strategy) {
      throw new Error(`Authentication strategy "${name}" not found.`);
    }

    return strategy;
  }

  /**
   * Lists all registered authentication strategies.
   * @returns {string[]} An array containing the names of registered strategies.
   */
  listStrategies(type: "http" | "socket"): string[] {
    if (!this.strategies.has(type)) {
      throw new Error(
        `Invalid strategy type "${type}". Expected "http" or "socket".`
      );
    }

    return Array.from(this.strategies.get(type).keys());
  }

  /**
   * Initializes all registered authentication strategies.
   *
   * @param {boolean} [sequential=false] - Whether to initialize strategies sequentially.
   * @throws {Error} Throws an error if any strategy fails to initialize.
   */
  async init(sequential = false) {
    const strategies = [
      ...this.strategies.get("http").values(),
      ...this.strategies.get("socket").values(),
    ];

    if (sequential) {
      for (const strategy of strategies) {
        try {
          await strategy.init();
        } catch (error) {
          this.logger?.error(`Failed to initialize strategy: ${error.message}`);
        }
      }
    } else {
      await Promise.all(
        strategies.map((strategy) =>
          strategy
            .init()
            .catch((error) =>
              this.logger?.error(
                `Failed to initialize strategy: ${error.message}`
              )
            )
        )
      );
    }
  }

  /**
   * Authenticates a request based on the given strategy.
   *
   * @param {string} name - The authentication strategy name.
   * @param {any} context - The authentication context.
   * @returns {Promise<AuthResult<any>>} The authentication result.
   */
  async authenticate(
    type: "http" | "socket",
    name: string,
    context: any
  ): Promise<AuthResult<any>> {
    const strategy = this.getStrategy(name, type);

    if (!strategy) {
      throw new Error(`Authentication strategy "${name}" not found.`);
    }

    return strategy.authenticate(context);
  }

  /**
   * Logs out a user based on the strategy.
   *
   * @param {string} name - The authentication strategy name.
   * @param {any} context - The authentication context.
   */
  async logout(
    type: "http" | "socket",
    name: string,
    context: any
  ): Promise<void> {
    const strategy = this.getStrategy(name, type);

    if (strategy?.logout) {
      await strategy.logout(context);
    } else {
      this.logger?.error(`No "logout" implementation in strategy "${name}".`);
    }
  }
}
