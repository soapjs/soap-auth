import * as Soap from "@soapjs/soap";
import { SessionHandler } from "../../../session/session-handler";
import { JwtStrategy } from "../../jwt/jwt.strategy";
import { HttpOAuth2Strategy } from "./http-oauth2.strategy";
import { ConfigurableOAuth2StrategyConfig } from "./provider.types";
import { MissingConfigError } from "../../../errors";

/**
 * Concrete HTTP OAuth2 strategy for arbitrary providers.
 *
 * Use this when a provider follows OAuth2/OIDC conventions and does not need a
 * dedicated strategy class. The strategy has no provider SDK dependency; it
 * exchanges tokens with `fetch` and maps the user profile through config.
 */
export class ConfigurableOAuth2Strategy<
  TUser extends Soap.AuthUser = Soap.AuthUser
> extends HttpOAuth2Strategy<TUser> {
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
      this.logger?.error("ConfigurableOAuth2Strategy.fetchUser failed:", error);
      return null;
    }
  }
}
