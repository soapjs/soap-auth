import { HttpAuthStrategyFactory } from "./factories/http-auth-strategy.factory";
import { SocketAuthStrategyFactory } from "./factories/socket-auth-strategy.factory";
import { AuthResult, AuthStrategy, SoapAuthConfig } from "./types";

/**
 * Core class for soap-auth that manages and initializes various authentication strategies.
 */
export class SoapAuth {
  private requiredStrategyMethods = ["authenticate", "init"];
  private httpStrategies = new Map<string, AuthStrategy>();
  private socketStrategies = new Map<string, AuthStrategy>();

  /**
   * Constructs an instance of SoapAuth, setting up strategies based on provided configuration.
   * @param {SoapAuthConfig} config - Configuration object specifying strategies and their options.
   */
  constructor(config: SoapAuthConfig) {
    const httpFactory = new HttpAuthStrategyFactory(config.logger);
    this.httpStrategies = httpFactory.createStrategies(config);

    const socketFactory = new SocketAuthStrategyFactory(config.logger);
    this.socketStrategies = socketFactory.createStrategies(config);
  }

  /**
   * Determines whether the provided object conforms to the AuthStrategy interface.
   * @param {unknown} strategy - The object to check.
   * @returns {boolean} True if the object implements required methods, otherwise false.
   */
  private isAuthStrategy(strategy: unknown) {
    const isValidStrategy = this.requiredStrategyMethods.every(
      (method) => typeof strategy[method] === "function"
    );

    return isValidStrategy;
  }

  /**
   * Adds an authentication strategy to the specified strategies map.
   * @param {Map<string, AuthStrategy>} strategiesMap - The map of authentication strategies.
   * @param {string} type - The identifier for the strategy type.
   * @param {AuthStrategy | undefined} strategyInstance - The strategy instance to add.
   */
  addStrategy(
    strategiesMap: Map<string, AuthStrategy>,
    type: string,
    strategyInstance: AuthStrategy | undefined
  ) {
    if (this.isAuthStrategy(strategyInstance)) {
      strategiesMap.set(type, strategyInstance);
    }
  }

  /**
   * Removes an authentication strategy from the registered strategies.
   * @param {string} type - The identifier for the strategy type.
   * @returns {boolean} True if the strategy was removed, otherwise false.
   */
  removeStrategy(type: string): boolean {
    if (this.httpStrategies.has(type)) {
      this.httpStrategies.delete(type);
      return true;
    }

    if (this.socketStrategies.has(type)) {
      this.socketStrategies.delete(type);
      return true;
    }

    return false;
  }

  /**
   * Checks if a specific authentication strategy is registered.
   * @param {string} type - The identifier for the strategy type.
   * @returns {boolean} True if the strategy exists, otherwise false.
   */
  hasStrategy(type: string): boolean {
    return this.httpStrategies.has(type) || this.socketStrategies.has(type);
  }

  /**
   * Retrieves an authentication strategy by name from either HTTP or WebSocket strategies.
   *
   * @param {string} strategyName - The strategy identifier.
   * @returns {AuthStrategy | undefined} The authentication strategy or undefined if not found.
   */
  getStrategy(
    strategyName: string,
    layer: "http" | "socket" = "http"
  ): AuthStrategy | undefined {
    return layer === "http"
      ? this.httpStrategies.get(strategyName)
      : this.socketStrategies.get(strategyName);
  }

  /**
   * Lists all registered authentication strategies.
   * @returns {string[]} An array containing the names of registered strategies.
   */
  listStrategies(): string[] {
    return [...this.httpStrategies.keys(), ...this.socketStrategies.keys()];
  }

  /**
   * Initializes all registered authentication strategies.
   *
   * @param {boolean} [sequential=false] - Whether to initialize strategies sequentially.
   * @throws {Error} Throws an error if any strategy fails to initialize.
   */
  async init(sequential = false) {
    const strategies = [
      ...this.httpStrategies.values(),
      ...this.socketStrategies.values(),
    ];

    if (sequential) {
      for (const strategy of strategies) {
        await strategy.init();
      }
    } else {
      await Promise.all(strategies.map((strategy) => strategy.init()));
    }
  }

  /**
   * Authenticates a request based on the given strategy.
   *
   * @param {string} strategyName - The authentication strategy name.
   * @param {any} context - The authentication context.
   * @returns {Promise<AuthResult<any>>} The authentication result.
   */
  async authenticate(
    strategyName: string,
    context: any
  ): Promise<AuthResult<any>> {
    const strategy = this.getStrategy(strategyName);
    if (!strategy) {
      throw new Error(`Authentication strategy "${strategyName}" not found.`);
    }
    return strategy.authenticate(context);
  }

  /**
   * Logs out a user based on the strategy.
   *
   * @param {string} strategyName - The authentication strategy name.
   * @param {any} context - The authentication context.
   */
  async logout(strategyName: string, context: any): Promise<void> {
    const strategy = this.getStrategy(strategyName);
    if (strategy?.logout) {
      await strategy.logout(context);
    }
  }
}
