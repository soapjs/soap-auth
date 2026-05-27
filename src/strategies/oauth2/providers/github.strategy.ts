import * as Soap from "@soapjs/soap";
import { SessionHandler } from "../../../session/session-handler";
import { JwtStrategy } from "../../jwt/jwt.strategy";
import { HttpOAuth2Strategy } from "./http-oauth2.strategy";
import { SocialProviderConfig } from "./provider.types";

const GITHUB_ENDPOINTS = {
  authorizationUrl: "https://github.com/login/oauth/authorize",
  tokenUrl: "https://github.com/login/oauth/access_token",
  userInfoUrl: "https://api.github.com/user",
  revocationUrl: "https://api.github.com/applications/{client_id}/token",
} as const;

export type GitHubStrategyConfig<TUser extends Soap.AuthUser = Soap.AuthUser> =
  SocialProviderConfig<TUser>;

/**
 * GitHub OAuth2 strategy.
 *
 * Authenticates via GitHub's authorization_code flow. The `id` claim is the
 * numeric GitHub user ID; `username` is the GitHub `login`. Email may be null
 * if the user has set their GitHub email to private — provide
 * `config.user.validateUser` to fetch `/user/emails` and fill it in.
 *
 * Minimal setup:
 * ```ts
 * new GitHubStrategy({
 *   clientId: process.env.GITHUB_CLIENT_ID,
 *   clientSecret: process.env.GITHUB_CLIENT_SECRET,
 *   redirectUri: 'https://example.com/auth/github/callback',
 * })
 * ```
 */
export class GitHubStrategy<TUser extends Soap.AuthUser = Soap.AuthUser>
  extends HttpOAuth2Strategy<TUser>
{
  readonly name = "github";

  constructor(
    config: GitHubStrategyConfig<TUser>,
    session?: SessionHandler,
    jwt?: JwtStrategy<Soap.HttpContext, TUser>,
    logger?: Soap.Logger
  ) {
    super(
      {
        grantType: "authorization_code",
        scope: config.scope ?? ["read:user", "user:email"],
        routes: {
          login: { path: "/auth/github", method: "GET" },
          callback: { path: "/auth/github/callback", method: "GET" },
          logout: { path: "/auth/github/logout", method: "POST" },
          ...config.routes,
        },
        ...config,
        endpoints: { ...GITHUB_ENDPOINTS, ...config.endpoints },
      },
      session,
      jwt,
      logger
    );
  }

  protected async fetchUser(accessToken: string): Promise<TUser | null> {
    try {
      const response = await fetch(GITHUB_ENDPOINTS.userInfoUrl, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      });

      if (!response.ok) return null;

      const profile = await response.json();

      if (this.config.user?.validateUser) {
        return this.config.user.validateUser(profile);
      }

      return {
        id: profile.id,
        email: profile.email,
        username: profile.login,
        name: profile.name,
        avatarUrl: profile.avatar_url,
      } as unknown as TUser;
    } catch (error) {
      this.logger?.error("GitHubStrategy.fetchUser failed:", error);
      return null;
    }
  }
}
