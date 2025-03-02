import * as Soap from "@soapjs/soap";
import { AuthCategories, AuthStrategy, SoapAuthConfig } from "./types";

/**
 * Core class for soap-auth that manages and initializes various authentication strategies.
 */
export class SoapAuth {
  private requiredStrategyMethods = ["authenticate", "init"];
  private strategies = new Map<AuthCategories, Map<string, AuthStrategy>>();
  private logger?: Soap.Logger;
  /**
   * Constructs an instance of SoapAuth, setting up strategies based on provided configuration.
   * @param {SoapAuthConfig} config - Configuration object specifying strategies and their options.
   */
  constructor(config: SoapAuthConfig) {
    this.strategies.set("http", new Map<string, AuthStrategy>());
    this.strategies.set("socket", new Map<string, AuthStrategy>());
    this.strategies.set("event", new Map<string, AuthStrategy>());
    this.strategies.set("isa", new Map<string, AuthStrategy>());
    this.strategies.set("webhook", new Map<string, AuthStrategy>());
    this.strategies.set("grpc", new Map<string, AuthStrategy>());
    this.strategies.set("edge", new Map<string, AuthStrategy>());
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
    type: AuthCategories
  ) {
    if (!this.strategies.has(type)) {
      throw new Error(`Invalid strategy type "${type}".`);
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
  removeStrategy(name: string | string[], type: AuthCategories) {
    if (!this.strategies.has(type)) {
      throw new Error(`Invalid strategy type "${type}".`);
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
  hasStrategy(name: string, type: AuthCategories): boolean {
    if (!this.strategies.has(type)) {
      throw new Error(`Invalid strategy type "${type}".`);
    }
    return this.strategies.get(type).has(name);
  }

  /**
   * Retrieves an authentication strategy by name from either HTTP or WebSocket strategies.
   *
   * @param {string} name - The strategy identifier.
   * @returns {AuthStrategy} The authentication strategy or throws error if not found.
   */
  getStrategy<T extends AuthStrategy>(name: string, type: AuthCategories): T {
    if (!this.strategies.has(type)) {
      throw new Error(`Invalid strategy type "${type}".`);
    }

    const strategy = this.strategies.get(type).get(name);

    if (!strategy) {
      throw new Error(`Authentication strategy "${name}" not found.`);
    }

    return strategy as T;
  }

  getHttpStrategy<T extends AuthStrategy>(name: string): T {
    if (!this.strategies.has("http")) {
      throw new Error(`Invalid strategy.`);
    }

    const strategy = this.strategies.get("http").get(name);

    if (!strategy) {
      throw new Error(`Authentication strategy "${name}" not found.`);
    }

    return strategy as T;
  }

  getSocketStrategy<T extends AuthStrategy>(name: string): T {
    if (!this.strategies.has("socket")) {
      throw new Error(`Invalid strategy.`);
    }

    const strategy = this.strategies.get("socket").get(name);

    if (!strategy) {
      throw new Error(`Authentication strategy "${name}" not found.`);
    }

    return strategy as T;
  }

  getEventStrategy<T extends AuthStrategy>(name: string): T {
    if (!this.strategies.has("event")) {
      throw new Error(`Invalid strategy.`);
    }

    const strategy = this.strategies.get("event").get(name);

    if (!strategy) {
      throw new Error(`Authentication strategy "${name}" not found.`);
    }

    return strategy as T;
  }

  /**
   * Lists all registered authentication strategies.
   * @returns {string[]} An array containing the names of registered strategies.
   */
  listStrategies(type: AuthCategories): string[] {
    if (!this.strategies.has(type)) {
      throw new Error(`Invalid strategy type "${type}".`);
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
}
