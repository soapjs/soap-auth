import * as Soap from "@soapjs/soap";

import { SoapAuthConfig } from "./config/config";
import { JwtTools } from "./jwt";
import { SessionTools } from "./session";
import {
  ApiKeyStrategy,
  BasicStrategy,
  BearerStrategy,
  LocalStrategy,
  OAuth2Strategy,
  OAuthStrategy,
  StrategyType,
} from "./strategies";

export class SoapAuth extends Soap.ApiAuthModule {
  private jwtTools?: JwtTools;
  private sessionTools?: SessionTools;

  constructor(private config: SoapAuthConfig) {
    super();

    this.strategies = new Map<string, Soap.ApiAuthStrategy>();
    if (config.jwt) {
      this.jwtTools = new JwtTools(config.jwt);
      this.jwtTools.initStrategy();
    }

    if (config.session) {
      this.sessionTools = new SessionTools(config.session);
      this.sessionTools.initSession();
    }

    if (this.config.strategies.local) {
      this.strategies.set(
        StrategyType.Local,
        new LocalStrategy(this.config.strategies.local)
      );
    }

    if (this.config.strategies.oauth) {
      for (const provider in this.config.strategies.oauth) {
        const strategy = new OAuthStrategy(
          provider,
          this.config.strategies.oauth[provider],
          this.jwtTools
        );
        this.strategies.set(provider, strategy);
      }
    }

    if (this.config.strategies.oauth2) {
      for (const provider in this.config.strategies.oauth2) {
        const strategy = new OAuth2Strategy(
          this.config.strategies.oauth2[provider],
          this.jwtTools
        );
        this.strategies.set(provider, strategy);
      }
    }

    if (this.config.strategies.apiKey) {
      this.strategies.set(
        StrategyType.ApiKey,
        new ApiKeyStrategy(this.config.strategies.apiKey)
      );
    }

    if (this.config.strategies.bearer) {
      this.strategies.set(
        StrategyType.Bearer,
        new BearerStrategy(this.config.strategies.bearer, this.jwtTools)
      );
    }

    if (this.config.strategies.basic) {
      this.strategies.set(
        StrategyType.Basic,
        new BasicStrategy(this.config.strategies.basic)
      );
    }

    if (this.config.strategies.web3) {
      // ...
    }
  }

  init<AuthComponent = any>(options?: any): AuthComponent[] {
    const components: AuthComponent[] = [];
    // if (this.config.sessionOptions) {
    //   components.push(passport.session());

    //   if (this.config.sessionOptions.serialize) {
    //     passport.serializeUser(this.config.sessionOptions.serialize);
    //   }

    //   if (this.config.sessionOptions.deserialize) {
    //     passport.deserializeUser(this.config.sessionOptions.deserialize);
    //   }
    // }

    // components.push(passport.initialize(options) as InitializedType);

    this.strategies.forEach((strategy) => {
      strategy.init();
    });

    return components;
  }
}
