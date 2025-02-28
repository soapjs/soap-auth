import * as Soap from "@soapjs/soap";
import { OAuth2NonceConfig, OAuth2StrategyConfig } from "./oauth2.types";
import { generateRandomString } from "../../tools";

export class OAuth2Tools {
  static async generateState(config: OAuth2StrategyConfig): Promise<string> {
    return (await config.state?.generateState?.()) || generateRandomString();
  }

  static async generateNonce(config: OAuth2StrategyConfig): Promise<string> {
    return (await config.nonce?.generateNonce?.()) || generateRandomString();
  }

  static async validateNonce(
    expectedNonce: string,
    nonce: string,
    config: OAuth2NonceConfig
  ): Promise<boolean> {
    if (config.validateNonce) {
      return config.validateNonce(expectedNonce, nonce);
    }

    return expectedNonce === nonce;
  }

  static extractState<TContext>(context: TContext): string | null {
    return (context as any).query?.state || null;
  }

  static extractNonce(idToken: string): string | null {
    const decoded = JSON.parse(
      Buffer.from(idToken.split(".")[1], "base64").toString()
    );
    return decoded.nonce || null;
  }
}

export const prepareOAuth2Config = <TContext = any, TUser = any>(
  config: Partial<OAuth2StrategyConfig<TContext, TUser>>
): OAuth2StrategyConfig<TContext, TUser> => {
  return Soap.removeUndefinedProperties<OAuth2StrategyConfig<TContext, TUser>>({
    ...config,
    grantType: config.grantType ?? "authorization_code",
    responseType: config.responseType ?? "code",
    scope: config.scope ?? "openid profile email",
    autoLogoutOnRefreshFailure: config.autoLogoutOnRefreshFailure ?? false,

    routes: {
      login: {
        path: "/auth/oauth2/login",
        method: "GET",
        ...config.routes.login,
      },
      callback: {
        path: "/auth/oauth2/callback",
        method: "GET",
        ...config.routes.callback,
      },
      logout: config.routes?.logout
        ? {
            path: "/auth/oauth2/logout",
            method: "POST",
            ...config.routes.logout,
          }
        : undefined,
      refresh: config.routes?.refresh
        ? {
            path: "/auth/oauth2/refresh",
            method: "POST",
            ...config.routes.refresh,
          }
        : undefined,
      revoke: config.routes?.revoke
        ? {
            path: "/auth/oauth2/revoke",
            method: "POST",
            ...config.routes.revoke,
          }
        : undefined,
      ...config.routes,
    },

    pkce: config.pkce
      ? {
          challenge: {
            expiresIn: 300,
            ...config.pkce.challenge,
          },
          verifier: {
            expiresIn: 300,
            ...config.pkce.verifier,
          },
          ...config.pkce,
        }
      : undefined,

    state: config.state
      ? {
          generateState: () => Math.random().toString(36).substring(2, 15),
          validateState: (storedState, returnedState) =>
            storedState === returnedState,
          ...config.state,
        }
      : undefined,

    nonce: config.nonce
      ? {
          generateNonce: () => Math.random().toString(36).substring(2, 15),
          validateNonce: (storedNonce, returnedNonce) =>
            storedNonce === returnedNonce,
          ...config.nonce,
        }
      : undefined,

    jwks: config.jwks
      ? {
          algorithms: ["RS256"],
          ...config.jwks,
        }
      : undefined,
  });
};
