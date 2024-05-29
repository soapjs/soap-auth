import * as Soap from "@soapjs/soap";

import { SoapAuthConfig } from "./config/config";
import { JwtRegistry, JwtTools, TokenConfig } from "./jwt";
import { SessionConfig, SessionTools } from "./session";
import {
  ApiKeyStrategy,
  BasicStrategy,
  LocalStrategy,
  OAuth2Strategy,
  StrategyType,
  TokenStrategy,
} from "./strategies";

export class SoapAuth extends Soap.ApiAuthModule {
  // private jwtRegistry?: JwtRegistry = new JwtRegistry();
  private jwtRegistry?: Map<string, JwtTools> = new Map<string, JwtTools>();
  private sessionTools?: SessionTools;

  constructor(private config: SoapAuthConfig) {
    super();
    this.strategies = new Map<string, Soap.ApiAuthStrategy>();

    if (config.local) {
      const jwtId = this.addJwtStrategy(StrategyType.Local, config.local);
      const sessionId = this.addSessionStrategy(
        StrategyType.Local,
        config.local
      );
      this.strategies.set(
        StrategyType.Local,
        new LocalStrategy(config.local, jwtId, sessionId)
      );
    }

    if (config.oauth2) {
      for (const provider in config.oauth2) {
        const jwtId = this.addJwtStrategy(provider, config.local);
        const sessionId = this.addSessionStrategy(provider, config.local);
        const strategy = new OAuth2Strategy(
          config.oauth2[provider],
          jwtId,
          sessionId
        );
        this.strategies.set(provider, strategy);
      }
    }

    if (config.apiKey) {
      const jwtId = this.addJwtStrategy(StrategyType.ApiKey, config.local);
      const sessionId = this.addSessionStrategy(
        StrategyType.ApiKey,
        config.local
      );
      this.strategies.set(
        StrategyType.ApiKey,
        new ApiKeyStrategy(config.apiKey, jwtId, sessionId)
      );
    }

    if (config.basic) {
      const jwtId = this.addJwtStrategy(StrategyType.Basic, config.local);
      const sessionId = this.addSessionStrategy(
        StrategyType.Basic,
        config.local
      );
      this.strategies.set(
        StrategyType.Basic,
        new BasicStrategy(config.basic, jwtId, sessionId)
      );
    }

    if (config.token) {
      this.strategies.set(StrategyType.Token, new TokenStrategy(config.token));
    }

    if (config.custom) {
      for (const provider in config.custom) {
        // const jwtId = this.addJwtStrategy(provider, config.local);
        // const sessionId = this.addSessionStrategy(
        //   provider,
        //   config.local
        // );
        this.strategies.set(provider, config.custom[provider]);
      }
    }

    if (config.web3) {
      // ...
    }
  }

  private addJwtStrategy(type: string, config: { jwt?: TokenConfig }) {
    if (config.jwt) {
      const id = type === "jwt" ? "jwt" : `jwt-${type}`;
      this.strategies.set(id, new TokenStrategy({ jwt: config.jwt }, id));
      return id;
    }
  }
  private addSessionStrategy(
    type: string,
    config: { session?: SessionConfig }
  ) {
    if (config.session) {
      const id = type === "session" ? "session" : `session-${type}`;
      this.strategies.set(
        id,
        new SessionStrategy({ session: config.session }, id)
      );
      return id;
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
