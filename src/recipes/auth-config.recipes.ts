import { ApiKeyStrategyConfig } from "../strategies/api-key/api-key.types";
import { BasicStrategyConfig } from "../strategies/basic/basic.types";
import { JwtConfig } from "../strategies/jwt/jwt.types";
import { LocalStrategyConfig } from "../strategies/local/local.types";
import { OAuth2ProviderConfig } from "../strategies/oauth2/oauth2.types";
import {
  Auth0PresetOptions,
  FacebookPresetOptions,
  KeycloakPresetOptions,
  OAuth2ProviderPreset,
  oauth2ProviderEndpoints,
} from "./oauth2-presets";
import {
  AuthRouteConfig,
  TokenIssuerConfig,
  UserConfig,
} from "../types";
import { OAuth2Endpoints } from "../strategies/oauth2/oauth2.types";

type RouteOverrides = Partial<Record<string, Partial<AuthRouteConfig>>>;

function route(
  path: string,
  method: string,
  override?: Partial<AuthRouteConfig>
): AuthRouteConfig {
  return {
    path: override?.path ?? path,
    method: override?.method ?? method,
  };
}

function credentialRoutes(
  basePath: string,
  overrides: RouteOverrides = {}
) {
  return {
    login: route(`${basePath}/login`, "POST", overrides.login),
    logout: route(`${basePath}/logout`, "POST", overrides.logout),
    resetPassword: overrides.resetPassword
      ? route(`${basePath}/password/reset`, "POST", overrides.resetPassword)
      : undefined,
    changePassword: overrides.changePassword
      ? route(`${basePath}/password/change`, "POST", overrides.changePassword)
      : undefined,
    requestPasswordReset: overrides.requestPasswordReset
      ? route(
          `${basePath}/password/reset/request`,
          "POST",
          overrides.requestPasswordReset
        )
      : undefined,
  };
}

function oauthRoutes(basePath: string, overrides: RouteOverrides = {}) {
  return {
    login: route(basePath, "GET", overrides.login),
    callback: route(`${basePath}/callback`, "GET", overrides.callback),
    logout: overrides.logout
      ? route(`${basePath}/logout`, "POST", overrides.logout)
      : undefined,
    refresh: overrides.refresh
      ? route(`${basePath}/refresh`, "POST", overrides.refresh)
      : undefined,
    revoke: overrides.revoke
      ? route(`${basePath}/revoke`, "POST", overrides.revoke)
      : undefined,
  };
}

export interface JwtAuthRecipeOptions<TContext = unknown, TUser = unknown>
  extends Omit<Partial<JwtConfig<TContext, TUser>>, "accessToken" | "refreshToken" | "routes"> {
  accessSecret: string;
  refreshSecret?: string;
  accessToken?: Partial<TokenIssuerConfig<TContext>>;
  refreshToken?: Partial<TokenIssuerConfig<TContext>>;
  user?: UserConfig<TUser>;
  routes?: RouteOverrides;
}

export function createJwtAuthConfig<TContext = unknown, TUser = unknown>(
  options: JwtAuthRecipeOptions<TContext, TUser>
): JwtConfig<TContext, TUser> {
  const {
    accessSecret,
    refreshSecret,
    accessToken,
    refreshToken,
    routes,
    ...config
  } = options;

  return {
    ...config,
    user: options.user,
    accessToken: {
      issuer: {
        secretKey: accessSecret,
        options: {
          expiresIn: "15m",
          ...(accessToken?.options ?? {}),
        },
        buildPayload: accessToken?.buildPayload,
      },
      verifier: { options: {} },
    },
    refreshToken: refreshSecret
      ? {
          issuer: {
            secretKey: refreshSecret,
            options: {
              expiresIn: "7d",
              ...(refreshToken?.options ?? {}),
            },
            buildPayload: refreshToken?.buildPayload,
          },
          verifier: { options: {} },
        }
      : undefined,
    routes: {
      login: route("/auth/jwt/login", "POST", routes?.login),
      logout: route("/auth/jwt/logout", "POST", routes?.logout),
      refresh: route("/auth/jwt/refresh", "POST", routes?.refresh),
    },
  } as JwtConfig<TContext, TUser>;
}

export interface LocalAuthRecipeOptions<TContext = unknown, TUser = unknown>
  extends Omit<LocalStrategyConfig<TContext, TUser>, "routes"> {
  basePath?: string;
  routes?: RouteOverrides;
}

export function createLocalAuthConfig<TContext = unknown, TUser = unknown>(
  options: LocalAuthRecipeOptions<TContext, TUser>
): LocalStrategyConfig<TContext, TUser> {
  const { basePath, routes, ...config } = options;

  return {
    ...config,
    routes: credentialRoutes(basePath ?? "/auth/local", routes),
  } as LocalStrategyConfig<TContext, TUser>;
}

export interface BasicAuthRecipeOptions<TContext = unknown, TUser = unknown>
  extends Omit<BasicStrategyConfig<TContext, TUser>, "routes"> {
  basePath?: string;
  routes?: RouteOverrides;
}

export function createBasicAuthConfig<TContext = unknown, TUser = unknown>(
  options: BasicAuthRecipeOptions<TContext, TUser>
): BasicStrategyConfig<TContext, TUser> {
  const { basePath, routes, ...config } = options;

  return {
    ...config,
    routes: credentialRoutes(basePath ?? "/auth/basic", routes),
  } as BasicStrategyConfig<TContext, TUser>;
}

export interface ApiKeyAuthRecipeOptions<TContext = unknown, TUser = unknown>
  extends ApiKeyStrategyConfig<TContext, TUser> {}

export function createApiKeyAuthConfig<TContext = unknown, TUser = unknown>(
  options: ApiKeyAuthRecipeOptions<TContext, TUser>
): ApiKeyStrategyConfig<TContext, TUser> {
  return {
    keyType: "long-term",
    ...options,
  };
}

export interface OAuth2AuthRecipeOptions<TUser = unknown>
  extends Omit<OAuth2ProviderConfig<any, TUser>, "endpoints" | "routes"> {
  provider: OAuth2ProviderPreset | string;
  endpoints?: OAuth2Endpoints;
  presetOptions?: Auth0PresetOptions | KeycloakPresetOptions | FacebookPresetOptions;
  routes?: RouteOverrides;
}

function resolveOAuth2Endpoints<TUser>(
  options: OAuth2AuthRecipeOptions<TUser>
): OAuth2Endpoints {
  if (options.endpoints) {
    return options.endpoints;
  }

  switch (options.provider) {
    case "auth0":
      return oauth2ProviderEndpoints.auth0(
        options.presetOptions as Auth0PresetOptions
      );
    case "keycloak":
      return oauth2ProviderEndpoints.keycloak(
        options.presetOptions as KeycloakPresetOptions
      );
    case "google":
      return oauth2ProviderEndpoints.google();
    case "github":
      return oauth2ProviderEndpoints.github();
    case "facebook":
      return oauth2ProviderEndpoints.facebook(
        options.presetOptions as FacebookPresetOptions
      );
    case "discord":
      return oauth2ProviderEndpoints.discord();
    default:
      throw new Error(
        `OAuth2 provider "${options.provider}" requires explicit endpoints.`
      );
  }
}

export function createOAuth2ProviderConfig<TUser = unknown>(
  options: OAuth2AuthRecipeOptions<TUser>
): OAuth2ProviderConfig<any, TUser> {
  const { provider, endpoints, presetOptions, routes, ...config } = options;

  return {
    ...config,
    grantType: options.grantType ?? "authorization_code",
    endpoints: resolveOAuth2Endpoints(options),
    routes: oauthRoutes(`/auth/${provider}`, routes),
  } as OAuth2ProviderConfig<any, TUser>;
}

export function createExternalIdentityOAuth2ProviderConfig<TUser = unknown>(
  options: OAuth2AuthRecipeOptions<TUser>
): OAuth2ProviderConfig<any, TUser> {
  if (!options.externalIdentity?.resolveIdentity) {
    throw new Error(
      "External identity OAuth2 config requires externalIdentity.resolveIdentity."
    );
  }

  return createOAuth2ProviderConfig(options);
}

export function createHybridOAuth2ProviderConfig<TUser = unknown>(
  options: OAuth2AuthRecipeOptions<TUser>
): OAuth2ProviderConfig<any, TUser> {
  return createOAuth2ProviderConfig(options);
}
