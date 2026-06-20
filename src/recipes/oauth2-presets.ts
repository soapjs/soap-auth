import { OAuth2Endpoints } from "../strategies/oauth2/oauth2.types";

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function ensureHttpsUrl(value: string): string {
  if (/^https?:\/\//i.test(value)) {
    return trimTrailingSlash(value);
  }
  return `https://${trimTrailingSlash(value)}`;
}

export type OAuth2ProviderPreset =
  | "auth0"
  | "keycloak"
  | "discord"
  | "google"
  | "github"
  | "facebook";

export interface Auth0PresetOptions {
  domain: string;
}

export interface KeycloakPresetOptions {
  baseUrl: string;
  realm: string;
}

export interface FacebookPresetOptions {
  version?: string;
}

export const oauth2ProviderEndpoints = {
  auth0(options: Auth0PresetOptions): OAuth2Endpoints {
    if (!options?.domain) {
      throw new Error("Auth0 OAuth2 preset requires domain.");
    }
    const baseUrl = ensureHttpsUrl(options.domain);
    return {
      authorizationUrl: `${baseUrl}/authorize`,
      tokenUrl: `${baseUrl}/oauth/token`,
      userInfoUrl: `${baseUrl}/userinfo`,
      revocationUrl: `${baseUrl}/oauth/revoke`,
      logoutUrl: `${baseUrl}/v2/logout`,
    };
  },

  keycloak(options: KeycloakPresetOptions): OAuth2Endpoints {
    if (!options?.baseUrl || !options?.realm) {
      throw new Error("Keycloak OAuth2 preset requires baseUrl and realm.");
    }
    const baseUrl = ensureHttpsUrl(options.baseUrl);
    const realmUrl = `${baseUrl}/realms/${encodeURIComponent(options.realm)}`;
    return {
      authorizationUrl: `${realmUrl}/protocol/openid-connect/auth`,
      tokenUrl: `${realmUrl}/protocol/openid-connect/token`,
      userInfoUrl: `${realmUrl}/protocol/openid-connect/userinfo`,
      revocationUrl: `${realmUrl}/protocol/openid-connect/revoke`,
      logoutUrl: `${realmUrl}/protocol/openid-connect/logout`,
    };
  },

  discord(): OAuth2Endpoints {
    return {
      authorizationUrl: "https://discord.com/oauth2/authorize",
      tokenUrl: "https://discord.com/api/oauth2/token",
      userInfoUrl: "https://discord.com/api/users/@me",
      revocationUrl: "https://discord.com/api/oauth2/token/revoke",
    };
  },

  google(): OAuth2Endpoints {
    return {
      authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth",
      tokenUrl: "https://oauth2.googleapis.com/token",
      userInfoUrl: "https://openidconnect.googleapis.com/v1/userinfo",
      revocationUrl: "https://oauth2.googleapis.com/revoke",
    };
  },

  github(): OAuth2Endpoints {
    return {
      authorizationUrl: "https://github.com/login/oauth/authorize",
      tokenUrl: "https://github.com/login/oauth/access_token",
      userInfoUrl: "https://api.github.com/user",
      revocationUrl: "https://api.github.com/applications/{client_id}/token",
    };
  },

  facebook(options: FacebookPresetOptions = {}): OAuth2Endpoints {
    const version = options.version ?? "v19.0";
    return {
      authorizationUrl: "https://www.facebook.com/dialog/oauth",
      tokenUrl: `https://graph.facebook.com/${version}/oauth/access_token`,
      userInfoUrl: `https://graph.facebook.com/${version}/me`,
      revocationUrl: `https://graph.facebook.com/${version}/me/permissions`,
    };
  },
};
