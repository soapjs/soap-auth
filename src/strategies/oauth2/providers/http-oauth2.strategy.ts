import * as Soap from "@soapjs/soap";
import { OAuth2Strategy } from "../oauth2.strategy";
import { OAuth2StrategyConfig } from "../oauth2.types";
import { SessionHandler } from "../../../session/session-handler";
import { JwtStrategy } from "../../jwt/jwt.strategy";

/**
 * Abstract OAuth2 strategy pre-wired for use with `HttpContext`.
 *
 * Handles all the boilerplate for extracting/embedding tokens through
 * standard HTTP headers and cookies so concrete providers only need to
 * supply their endpoints and map the provider profile to `AuthUser`.
 *
 * Concrete subclasses must still implement `name` (string literal) and
 * may override `fetchUser` to apply provider-specific field mapping on
 * top of the default `userInfoUrl` call inherited from `OAuth2Strategy`.
 */
export abstract class HttpOAuth2Strategy<
  TUser extends Soap.AuthUser = Soap.AuthUser
> extends OAuth2Strategy<Soap.HttpContext, TUser> {
  constructor(
    config: OAuth2StrategyConfig<Soap.HttpContext, TUser>,
    session?: SessionHandler,
    jwt?: JwtStrategy<Soap.HttpContext, TUser>,
    logger?: Soap.Logger
  ) {
    super(config, session, jwt, logger);
  }

  protected extractAccessToken(ctx: Soap.HttpContext): Promise<string | undefined> {
    const auth = ctx.req.headers?.authorization;
    if (typeof auth === "string" && auth.startsWith("Bearer ")) {
      return Promise.resolve(auth.slice(7));
    }
    return Promise.resolve(ctx.req.cookies?.access_token);
  }

  protected extractRefreshToken(ctx: Soap.HttpContext): Promise<string | undefined> {
    return Promise.resolve(ctx.req.cookies?.refresh_token);
  }

  protected storeAccessToken(_token: string, _ctx: Soap.HttpContext): Promise<void> {
    return Promise.resolve();
  }

  protected storeRefreshToken(_token: string, _ctx: Soap.HttpContext): Promise<void> {
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
}
