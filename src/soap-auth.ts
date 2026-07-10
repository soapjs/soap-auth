import * as Soap from "@soapjs/soap";
import { AuthCategories, SoapAuthConfig } from "./types";
import { ValidationUtils, ValidationError } from "./utils/validation";
import { SessionHandler } from "./session/session-handler";
import { JwtStrategy } from "./strategies/jwt/jwt.strategy";
import { LocalStrategy } from "./strategies/local/local.strategy";
import { BasicStrategy } from "./strategies/basic/basic.strategy";
import { ApiKeyStrategy } from "./strategies/api-key/api-key.strategy";
import { ExternalIdentityOAuth2Strategy } from "./strategies/oauth2/external-identity.oauth2.strategy";
import {
  ConfigurableHybridOAuth2Strategy,
  ConfigurableOAuth2Strategy,
  FacebookStrategy,
  GitHubStrategy,
  GoogleStrategy,
} from "./strategies/oauth2/providers";
import { oauth2ProviderEndpoints } from "./recipes/oauth2-presets";

function resolveOAuth2Endpoints(provider: string, providerConfig: any) {
  const preset =
    provider === "google"
      ? oauth2ProviderEndpoints.google()
      : provider === "github"
      ? oauth2ProviderEndpoints.github()
      : provider === "facebook"
      ? oauth2ProviderEndpoints.facebook()
      : undefined;

  return {
    ...preset,
    ...providerConfig.endpoints,
  };
}

function resolveOAuth2Scope(provider: string, providerConfig: any) {
  if (providerConfig.scope) {
    return providerConfig.scope;
  }

  if (provider === "google") {
    return ["openid", "email", "profile"];
  }

  if (provider === "github") {
    return ["read:user", "user:email"];
  }

  if (provider === "facebook") {
    return ["email", "public_profile"];
  }

  return undefined;
}

function buildOAuth2StrategyConfig(provider: string, providerConfig: any) {
  const endpoints = resolveOAuth2Endpoints(provider, providerConfig);

  if (!endpoints.authorizationUrl || !endpoints.tokenUrl) {
    throw new Error(
      `OAuth2 provider "${provider}" requires endpoints.authorizationUrl and endpoints.tokenUrl, or a custom strategy via http.custom.`
    );
  }

  return {
    ...providerConfig,
    name: provider,
    grantType: providerConfig.grantType ?? "authorization_code",
    endpoints,
    scope: resolveOAuth2Scope(provider, providerConfig),
    routes: {
      login: {
        path: `/auth/${provider}`,
        method: "GET",
      },
      callback: {
        path: `/auth/${provider}/callback`,
        method: "GET",
      },
      ...providerConfig.routes,
    },
  };
}

/**
 * Core class for soap-auth that manages and initializes various authentication strategies.
 */
export class SoapAuth {
  private requiredStrategyMethods = ["authenticate"];
  private strategies = new Map<
    AuthCategories,
    Map<string, Soap.AuthStrategy<any, any>>
  >();
  private logger?: Soap.Logger;
  /**
   * Constructs an instance of SoapAuth, setting up strategies based on provided configuration.
   * @param {SoapAuthConfig} config - Configuration object specifying strategies and their options.
   */
  constructor(config: SoapAuthConfig<any, any>) {
    // Validate configuration
    this.validateConfig(config);

    this.strategies.set("http", new Map<string, Soap.AuthStrategy<any, any>>());
    this.strategies.set("socket", new Map<string, Soap.AuthStrategy<any, any>>());
    this.strategies.set("event", new Map<string, Soap.AuthStrategy<any, any>>());
    this.strategies.set("isa", new Map<string, Soap.AuthStrategy<any, any>>());
    this.strategies.set("webhook", new Map<string, Soap.AuthStrategy<any, any>>());
    this.strategies.set("grpc", new Map<string, Soap.AuthStrategy<any, any>>());
    this.strategies.set("edge", new Map<string, Soap.AuthStrategy<any, any>>());
    this.logger = config.logger;
  }

  /**
   * Validates the SoapAuth configuration
   * @param {SoapAuthConfig} config - Configuration to validate
   * @throws {ValidationError} If configuration is invalid
   */
  private validateConfig(config: SoapAuthConfig<any, any>): void {
    try {
      ValidationUtils.required(config, "config");
      
      // Validate logger if provided
      if (config.logger) {
        ValidationUtils.object(config.logger, "config.logger");
      }

      // Validate session config if provided
      if (config.session) {
        this.validateSessionConfig(config.session);
      }

      // Validate JWT config if provided
      if (config.jwt) {
        this.validateJwtConfig(config.jwt);
      }

      // Validate HTTP strategies if provided
      if (config.http) {
        this.validateHttpStrategies(config.http);
      }

      // Validate socket strategies if provided
      if (config.socket) {
        this.validateSocketStrategies(config.socket);
      }

    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new ValidationError(`Invalid configuration: ${error.message}`);
    }
  }

  /**
   * Validates session configuration
   */
  private validateSessionConfig(session: any): void {
    ValidationUtils.required(session.secret, "session.secret");
    ValidationUtils.nonEmptyString(session.secret, "session.secret");
    
    if (session.sessionKey) {
      ValidationUtils.nonEmptyString(session.sessionKey, "session.sessionKey");
    }
    
    if (session.sessionHeader) {
      ValidationUtils.nonEmptyString(session.sessionHeader, "session.sessionHeader");
    }
  }

  /**
   * Validates JWT configuration
   */
  private validateJwtConfig(jwt: any): void {
    if (jwt.accessToken) {
      ValidationUtils.required(jwt.accessToken.issuer, "jwt.accessToken.issuer");
      ValidationUtils.required(jwt.accessToken.issuer.secretKey, "jwt.accessToken.issuer.secretKey");
      ValidationUtils.nonEmptyString(jwt.accessToken.issuer.secretKey, "jwt.accessToken.issuer.secretKey");
    }
    
    if (jwt.refreshToken) {
      ValidationUtils.required(jwt.refreshToken.issuer, "jwt.refreshToken.issuer");
      ValidationUtils.required(jwt.refreshToken.issuer.secretKey, "jwt.refreshToken.issuer.secretKey");
      ValidationUtils.nonEmptyString(jwt.refreshToken.issuer.secretKey, "jwt.refreshToken.issuer.secretKey");
    }
  }

  /**
   * Validates HTTP strategies configuration
   */
  private validateHttpStrategies(http: any): void {
    ValidationUtils.object(http, "http");
    
    if (http.custom) {
      ValidationUtils.object(http.custom, "http.custom");
      for (const [name, strategy] of Object.entries(http.custom)) {
        ValidationUtils.required(strategy, `http.custom.${name}`);
        ValidationUtils.object(strategy, `http.custom.${name}`);
      }
    }
  }

  /**
   * Validates socket strategies configuration
   */
  private validateSocketStrategies(socket: any): void {
    ValidationUtils.object(socket, "socket");
    
    if (socket.custom) {
      ValidationUtils.object(socket.custom, "socket.custom");
      for (const [name, strategy] of Object.entries(socket.custom)) {
        ValidationUtils.required(strategy, `socket.custom.${name}`);
        ValidationUtils.object(strategy, `socket.custom.${name}`);
      }
    }
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
   * @param {Soap.AuthStrategy | undefined} strategyInstance - The strategy instance to add.
   */
  addStrategy(
    strategyInstance: Soap.AuthStrategy<any, any> | undefined,
    name: string,
    type: AuthCategories
  ) {
    // Validate inputs
    ValidationUtils.required(strategyInstance, "strategyInstance");
    ValidationUtils.nonEmptyString(name, "name");
    ValidationUtils.oneOf(type, "type", ["http", "socket", "event", "isa", "webhook", "grpc", "edge"]);

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
    // Validate inputs
    ValidationUtils.required(name, "name");
    ValidationUtils.oneOf(type, "type", ["http", "socket", "event", "isa", "webhook", "grpc", "edge"]);

    if (!this.strategies.has(type)) {
      throw new Error(`Invalid strategy type "${type}".`);
    }
    const names = Array.isArray(name) ? name : [name];
    names.forEach((n) => {
      ValidationUtils.nonEmptyString(n, "strategy name");
      this.strategies.get(type).delete(n);
    });
  }

  /**
   * Checks if a specific authentication strategy is registered.
   * @param {string} name - The identifier for the strategy type.
   * @returns {boolean} True if the strategy exists, otherwise false.
   */
  hasStrategy(name: string, type: AuthCategories): boolean {
    // Validate inputs
    ValidationUtils.nonEmptyString(name, "name");
    ValidationUtils.oneOf(type, "type", ["http", "socket", "event", "isa", "webhook", "grpc", "edge"]);

    if (!this.strategies.has(type)) {
      throw new Error(`Invalid strategy type "${type}".`);
    }
    return this.strategies.get(type).has(name);
  }

  /**
   * Retrieves an authentication strategy by name from either HTTP or WebSocket strategies.
   *
   * @param {string} name - The strategy identifier.
   * @returns {Soap.AuthStrategy} The authentication strategy or throws error if not found.
   */
  getStrategy<T extends Soap.AuthStrategy>(name: string, type: AuthCategories): T {
    // Validate inputs
    ValidationUtils.nonEmptyString(name, "name");
    ValidationUtils.oneOf(type, "type", ["http", "socket", "event", "isa", "webhook", "grpc", "edge"]);

    if (!this.strategies.has(type)) {
      throw new Error(`Invalid strategy type "${type}".`);
    }

    const strategy = this.strategies.get(type).get(name);

    if (!strategy) {
      throw new Error(`Authentication strategy "${name}" not found.`);
    }

    return strategy as T;
  }

  getHttpStrategy<T extends Soap.AuthStrategy>(name: string): T {
    if (!this.strategies.has("http")) {
      throw new Error(`Invalid strategy.`);
    }

    const strategy = this.strategies.get("http").get(name);

    if (!strategy) {
      throw new Error(`Authentication strategy "${name}" not found.`);
    }

    return strategy as T;
  }

  getSocketStrategy<T extends Soap.AuthStrategy>(name: string): T {
    if (!this.strategies.has("socket")) {
      throw new Error(`Invalid strategy.`);
    }

    const strategy = this.strategies.get("socket").get(name);

    if (!strategy) {
      throw new Error(`Authentication strategy "${name}" not found.`);
    }

    return strategy as T;
  }

  getEventStrategy<T extends Soap.AuthStrategy>(name: string): T {
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
          await strategy.init?.();
        } catch (error) {
          this.logger?.error(`Failed to initialize strategy: ${error.message}`);
        }
      }
    } else {
      await Promise.all(
        strategies.map((strategy) =>
          Promise.resolve(strategy.init?.()).catch((error) =>
            this.logger?.error(
              `Failed to initialize strategy: ${error.message}`
            )
          )
        )
      );
    }
  }

  /**
   * Factory method — builds a fully initialized SoapAuth instance from config.
   *
   * Instantiates built-in strategies (local, basic, api-key, jwt, known OAuth2
   * providers) and registers any user-provided custom strategies.
   *
   * @param config - Full SoapAuth configuration.
   * @returns Initialized SoapAuth instance.
   */
  static async create<
    TContext = unknown,
    TUser extends Soap.AuthUser = Soap.AuthUser
  >(config: SoapAuthConfig<TContext, TUser>): Promise<SoapAuth> {
    const auth = new SoapAuth(config);
    const logger = config.logger;

    const sessionHandler = config.session
      ? new SessionHandler(config.session, logger)
      : undefined;

    // HTTP strategies
    if (config.http) {
      const sharedJwt = config.http.jwt
        ? new JwtStrategy(config.http.jwt, logger)
        : undefined;

      if (config.http.local) {
        auth.addStrategy(
          new LocalStrategy(config.http.local, sessionHandler, sharedJwt, logger),
          "local",
          "http"
        );
      }

      if (config.http.basic) {
        auth.addStrategy(
          new BasicStrategy(config.http.basic, sessionHandler, sharedJwt, logger),
          "basic",
          "http"
        );
      }

      if (config.http.apiKey) {
        auth.addStrategy(
          new ApiKeyStrategy(config.http.apiKey, logger),
          "api-key",
          "http"
        );
      }

      if (sharedJwt) {
        auth.addStrategy(sharedJwt, "jwt", "http");
      }

      if (config.http.oauth2) {
        for (const [provider, providerConfig] of Object.entries(
          config.http.oauth2
        )) {
          if (providerConfig.externalIdentity) {
            auth.addStrategy(
              new ExternalIdentityOAuth2Strategy(
                buildOAuth2StrategyConfig(provider, providerConfig) as any,
                sessionHandler,
                sharedJwt as any,
                logger
              ),
              provider,
              "http"
            );
            continue;
          }

          switch (provider) {
            case "google":
              auth.addStrategy(
                new GoogleStrategy(
                  providerConfig as any,
                  sessionHandler,
                  sharedJwt as any,
                  logger
                ),
                "google",
                "http"
              );
              break;
            case "github":
              auth.addStrategy(
                new GitHubStrategy(
                  providerConfig as any,
                  sessionHandler,
                  sharedJwt as any,
                  logger
                ),
                "github",
                "http"
              );
              break;
            case "facebook":
              auth.addStrategy(
                new FacebookStrategy(
                  providerConfig as any,
                  sessionHandler,
                  sharedJwt as any,
                  logger
                ),
                "facebook",
                "http"
              );
              break;
            default:
              auth.addStrategy(
                new ConfigurableOAuth2Strategy(
                  buildOAuth2StrategyConfig(provider, providerConfig) as any,
                  sessionHandler,
                  sharedJwt as any,
                  logger
                ),
                provider,
                "http"
              );
              break;
          }
        }
      }

      if (config.http.hybridOAuth2) {
        for (const [provider, providerConfig] of Object.entries(
          config.http.hybridOAuth2
        )) {
          if (
            !providerConfig.endpoints?.authorizationUrl ||
            !providerConfig.endpoints?.tokenUrl
          ) {
            throw new Error(
              `Hybrid OAuth2 provider "${provider}" requires endpoints.authorizationUrl and endpoints.tokenUrl, or a custom strategy via http.custom.`
            );
          }

          auth.addStrategy(
            new ConfigurableHybridOAuth2Strategy(
              {
                ...providerConfig,
                name: provider,
                grantType: providerConfig.grantType ?? "authorization_code",
                routes: {
                  login: {
                    path: `/auth/${provider}`,
                    method: "GET",
                  },
                  callback: {
                    path: `/auth/${provider}/callback`,
                    method: "GET",
                  },
                  ...providerConfig.routes,
                },
              } as any,
              sessionHandler,
              sharedJwt as any,
              logger
            ),
            provider,
            "http"
          );
        }
      }

      if (config.http.custom) {
        for (const [name, strategy] of Object.entries(config.http.custom)) {
          auth.addStrategy(
            strategy as Soap.AuthStrategy<any, any>,
            name,
            "http"
          );
        }
      }
    }

    // Socket strategies
    if (config.socket) {
      if (config.socket.jwt) {
        auth.addStrategy(
          new JwtStrategy(config.socket.jwt, logger),
          "jwt",
          "socket"
        );
      }

      if (config.socket.apiKey) {
        auth.addStrategy(
          new ApiKeyStrategy(config.socket.apiKey, logger),
          "api-key",
          "socket"
        );
      }

      if (config.socket.custom) {
        for (const [name, strategy] of Object.entries(config.socket.custom)) {
          auth.addStrategy(
            strategy as Soap.AuthStrategy<any, any>,
            name,
            "socket"
          );
        }
      }
    }

    await auth.init();
    return auth;
  }
}
