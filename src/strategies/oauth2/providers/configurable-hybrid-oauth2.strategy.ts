import * as Soap from "@soapjs/soap";
import { SessionHandler } from "../../../session/session-handler";
import { MissingConfigError } from "../../../errors";
import { JwtStrategy } from "../../jwt/jwt.strategy";
import { HybridOAuth2Strategy } from "../hybrid.oauth2.strategy";
import { ConfigurableOAuth2StrategyConfig } from "./provider.types";

/**
 * Concrete HTTP hybrid OAuth2 strategy for arbitrary providers.
 *
 * The strategy tries JWT/session first through `HybridOAuth2Strategy`, then
 * falls back to OAuth2. It intentionally depends only on the local strategy
 * primitives and platform `fetch`.
 */
export class ConfigurableHybridOAuth2Strategy<
  TUser extends Soap.AuthUser = Soap.AuthUser
> extends HybridOAuth2Strategy<Soap.HttpContext, TUser> {
  readonly name: string;

  constructor(
    protected config: ConfigurableOAuth2StrategyConfig<TUser>,
    session?: SessionHandler,
    jwt?: JwtStrategy<Soap.HttpContext, TUser>,
    logger?: Soap.Logger
  ) {
    super(config, session, jwt, logger);
    this.name = config.name;
  }

  protected extractAccessToken(
    ctx: Soap.HttpContext
  ): Promise<string | undefined> {
    const auth = ctx.req.headers?.authorization;
    if (typeof auth === "string" && auth.startsWith("Bearer ")) {
      return Promise.resolve(auth.slice(7));
    }
    return Promise.resolve(ctx.req.cookies?.access_token);
  }

  protected extractRefreshToken(
    ctx: Soap.HttpContext
  ): Promise<string | undefined> {
    return Promise.resolve(ctx.req.cookies?.refresh_token);
  }

  protected storeAccessToken(
    _token: string,
    _ctx: Soap.HttpContext
  ): Promise<void> {
    return Promise.resolve();
  }

  protected storeRefreshToken(
    _token: string,
    _ctx: Soap.HttpContext
  ): Promise<void> {
    return Promise.resolve();
  }

  protected embedAccessToken(token: string, ctx: Soap.HttpContext): void {
    ctx.res.setHeader("Authorization", `Bearer ${token}`);
  }

  protected embedRefreshToken(token: string, ctx: Soap.HttpContext): void {
    ctx.res.cookie("refresh_token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });
  }

  protected extractAuthorizationCode(ctx: Soap.HttpContext): string | null {
    return (ctx.req.query?.code as string) ?? null;
  }

  protected redirectUser(ctx: Soap.HttpContext, authUrl: string): void {
    if (typeof (ctx.res as any).redirect === "function") {
      (ctx.res as any).redirect(authUrl);
    } else {
      ctx.res.setHeader("Location", authUrl);
      ctx.res.status(302).json({ message: "Redirecting", location: authUrl });
    }
  }

  protected async fetchUser(accessToken: string): Promise<TUser | null> {
    try {
      if (!this.config.endpoints.userInfoUrl) {
        if (this.config.user?.fetchUser) {
          return this.config.user.fetchUser(accessToken);
        }
        throw new MissingConfigError("userInfoUrl");
      }

      const response = await fetch(this.config.endpoints.userInfoUrl, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      if (!response.ok) {
        return null;
      }

      const profile = await response.json();

      if (this.config.user?.validateUser) {
        return this.config.user.validateUser(profile);
      }

      return {
        id: profile.sub ?? profile.id,
        email: profile.email,
        username: profile.preferred_username ?? profile.username ?? profile.name,
        name: profile.name,
        picture: profile.picture ?? profile.avatar_url,
      } as unknown as TUser;
    } catch (error) {
      this.logger?.error(
        "ConfigurableHybridOAuth2Strategy.fetchUser failed:",
        error
      );
      return null;
    }
  }
}
