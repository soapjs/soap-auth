import * as Soap from "@soapjs/soap";
import { SessionHandler } from "../../../session/session-handler";
import { JwtStrategy } from "../../jwt/jwt.strategy";
import { HttpOAuth2Strategy } from "./http-oauth2.strategy";
import { SocialProviderConfig } from "./provider.types";

const FACEBOOK_API_VERSION = "v19.0";

const FACEBOOK_ENDPOINTS = {
  authorizationUrl: "https://www.facebook.com/dialog/oauth",
  tokenUrl: `https://graph.facebook.com/${FACEBOOK_API_VERSION}/oauth/access_token`,
  userInfoUrl: `https://graph.facebook.com/${FACEBOOK_API_VERSION}/me`,
  revocationUrl: `https://graph.facebook.com/${FACEBOOK_API_VERSION}/me/permissions`,
} as const;

const FACEBOOK_FIELDS = "id,name,email,picture";

export type FacebookStrategyConfig<TUser extends Soap.AuthUser = Soap.AuthUser> =
  SocialProviderConfig<TUser>;

/**
 * Facebook OAuth2 strategy.
 *
 * Authenticates via Facebook's authorization_code flow using the Graph API.
 * The user info call fetches `id,name,email,picture` by default. Provide
 * `config.user.validateUser` to customise the field list or transform the
 * returned profile.
 *
 * Note: Facebook does not issue standard refresh tokens for most app types.
 * Long-lived tokens and token refresh are handled through Facebook's own
 * token exchange endpoint — override `refreshAccessToken` if needed.
 *
 * Minimal setup:
 * ```ts
 * new FacebookStrategy({
 *   clientId: process.env.FACEBOOK_APP_ID,
 *   clientSecret: process.env.FACEBOOK_APP_SECRET,
 *   redirectUri: 'https://example.com/auth/facebook/callback',
 * })
 * ```
 */
export class FacebookStrategy<TUser extends Soap.AuthUser = Soap.AuthUser>
  extends HttpOAuth2Strategy<TUser>
{
  readonly name = "facebook";

  constructor(
    config: FacebookStrategyConfig<TUser>,
    session?: SessionHandler,
    jwt?: JwtStrategy<Soap.HttpContext, TUser>,
    logger?: Soap.Logger
  ) {
    super(
      {
        grantType: "authorization_code",
        scope: config.scope ?? ["email", "public_profile"],
        routes: {
          login: { path: "/auth/facebook", method: "GET" },
          callback: { path: "/auth/facebook/callback", method: "GET" },
          logout: { path: "/auth/facebook/logout", method: "POST" },
          ...config.routes,
        },
        ...config,
        endpoints: { ...FACEBOOK_ENDPOINTS, ...config.endpoints },
      },
      session,
      jwt,
      logger
    );
  }

  protected async fetchUser(accessToken: string): Promise<TUser | null> {
    try {
      const url = new URL(FACEBOOK_ENDPOINTS.userInfoUrl);
      url.searchParams.set("fields", FACEBOOK_FIELDS);
      url.searchParams.set("access_token", accessToken);

      const response = await fetch(url.toString());

      if (!response.ok) return null;

      const profile = await response.json();

      if (profile.error) {
        this.logger?.error("Facebook API error:", profile.error);
        return null;
      }

      if (this.config.user?.validateUser) {
        return this.config.user.validateUser(profile);
      }

      return {
        id: profile.id,
        email: profile.email,
        username: profile.name,
        picture: profile.picture?.data?.url,
      } as unknown as TUser;
    } catch (error) {
      this.logger?.error("FacebookStrategy.fetchUser failed:", error);
      return null;
    }
  }
}
