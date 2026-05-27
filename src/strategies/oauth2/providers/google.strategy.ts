import * as Soap from "@soapjs/soap";
import { SessionHandler } from "../../../session/session-handler";
import { JwtStrategy } from "../../jwt/jwt.strategy";
import { HttpOAuth2Strategy } from "./http-oauth2.strategy";
import { SocialProviderConfig } from "./provider.types";

const GOOGLE_ENDPOINTS = {
  authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth",
  tokenUrl: "https://oauth2.googleapis.com/token",
  userInfoUrl: "https://openidconnect.googleapis.com/v1/userinfo",
  revocationUrl: "https://oauth2.googleapis.com/revoke",
} as const;

export type GoogleStrategyConfig<TUser extends Soap.AuthUser = Soap.AuthUser> =
  SocialProviderConfig<TUser>;

/**
 * Google OAuth2 strategy.
 *
 * Authenticates via Google's authorization_code flow using OpenID Connect.
 * The default `fetchUser` maps `sub` → `id`, `name` → `username`, and
 * passes the raw profile through `config.user.validateUser` when provided.
 *
 * Minimal setup:
 * ```ts
 * new GoogleStrategy({
 *   clientId: process.env.GOOGLE_CLIENT_ID,
 *   clientSecret: process.env.GOOGLE_CLIENT_SECRET,
 *   redirectUri: 'https://example.com/auth/google/callback',
 * })
 * ```
 */
export class GoogleStrategy<TUser extends Soap.AuthUser = Soap.AuthUser>
  extends HttpOAuth2Strategy<TUser>
{
  readonly name = "google";

  constructor(
    config: GoogleStrategyConfig<TUser>,
    session?: SessionHandler,
    jwt?: JwtStrategy<Soap.HttpContext, TUser>,
    logger?: Soap.Logger
  ) {
    super(
      {
        grantType: "authorization_code",
        scope: config.scope ?? ["openid", "email", "profile"],
        routes: {
          login: { path: "/auth/google", method: "GET" },
          callback: { path: "/auth/google/callback", method: "GET" },
          logout: { path: "/auth/google/logout", method: "POST" },
          ...config.routes,
        },
        ...config,
        endpoints: { ...GOOGLE_ENDPOINTS, ...config.endpoints },
      },
      session,
      jwt,
      logger
    );
  }

  protected async fetchUser(accessToken: string): Promise<TUser | null> {
    try {
      const response = await fetch(GOOGLE_ENDPOINTS.userInfoUrl, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      if (!response.ok) return null;

      const profile = await response.json();

      if (this.config.user?.validateUser) {
        return this.config.user.validateUser(profile);
      }

      return {
        id: profile.sub,
        email: profile.email,
        username: profile.name,
        picture: profile.picture,
        emailVerified: profile.email_verified,
      } as unknown as TUser;
    } catch (error) {
      this.logger?.error("GoogleStrategy.fetchUser failed:", error);
      return null;
    }
  }
}
