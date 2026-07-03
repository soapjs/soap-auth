import * as Soap from "@soapjs/soap";
import {
  MissingConfigError,
  MissingTokenError,
  UserNotFoundError,
} from "../../errors";
import { SessionHandler } from "../../session/session-handler";
import { JwtStrategy } from "../jwt/jwt.strategy";
import { HttpOAuth2Strategy } from "./providers/http-oauth2.strategy";
import { OAuth2StrategyConfig } from "./oauth2.types";
import {
  ExternalIdentity,
  ExternalIdentityConfig,
} from "./external-identity.types";

export interface ExternalIdentityOAuth2StrategyConfig<
  TUser extends Soap.AuthUser = Soap.AuthUser
> extends OAuth2StrategyConfig<Soap.HttpContext, TUser> {
  name: string;
  externalIdentity: ExternalIdentityConfig<Soap.HttpContext, TUser> & {
    issueAppTokens?: boolean;
  };
}

export class ExternalIdentityOAuth2Strategy<
  TUser extends Soap.AuthUser = Soap.AuthUser
> extends HttpOAuth2Strategy<TUser> {
  readonly name: string;

  constructor(
    protected config: ExternalIdentityOAuth2StrategyConfig<TUser>,
    session?: SessionHandler,
    jwt?: JwtStrategy<Soap.HttpContext, TUser>,
    logger?: Soap.Logger
  ) {
    super(config, session, jwt, logger);
    this.name = config.name;
  }

  async authenticate(
    context: Soap.HttpContext
  ): Promise<Soap.AuthResult<TUser> | null> {
    try {
      let refreshToken: string | undefined;
      let accessToken = await this.extractAccessToken(context);

      if (!accessToken) {
        refreshToken = await this.extractRefreshToken(context);
        if (refreshToken) {
          const newTokens = await this.refreshAccessToken(context);
          accessToken = newTokens.accessToken;
          refreshToken = newTokens.refreshToken ?? refreshToken;
        } else {
          const tokens = await this.processOAuthFlow(context);
          accessToken = tokens.accessToken;
          refreshToken = tokens.refreshToken;
        }
      } else if (this.isTokenExpired(accessToken)) {
        refreshToken = await this.extractRefreshToken(context);
        const newTokens = await this.refreshAccessToken(context);
        accessToken = newTokens.accessToken;
        refreshToken = newTokens.refreshToken ?? refreshToken;
      }

      if (!accessToken) {
        throw new MissingTokenError("Access");
      }

      const identity = await this.fetchExternalIdentity(accessToken, context);
      const user = await this.config.externalIdentity.resolveIdentity(
        identity,
        context
      );

      if (!user) {
        throw new UserNotFoundError();
      }

      await this.role?.isAuthorized(user);

      const session = this.session
        ? await this.session.issueSession(user, context)
        : undefined;
      const issueAppTokens =
        this.config.externalIdentity.issueAppTokens !== false;

      if (issueAppTokens) {
        if (!this.jwt) {
          throw new MissingConfigError("jwt");
        }

        return {
          user,
          tokens: await this.jwt.issueTokens(user, context),
          session,
        };
      }

      return {
        user,
        tokens: { accessToken, refreshToken },
        session,
      };
    } catch (error) {
      await this.onFailure("authenticate", {
        context,
        error,
      });
      throw error;
    }
  }

  protected async fetchExternalIdentity(
    accessToken: string,
    context: Soap.HttpContext
  ): Promise<ExternalIdentity> {
    const profile = await this.fetchProviderProfile(accessToken);

    if (this.config.externalIdentity.mapProfile) {
      return this.config.externalIdentity.mapProfile(profile, this.name, context);
    }

    return mapOAuth2ProfileToExternalIdentity(profile, this.name);
  }

  protected async fetchProviderProfile(accessToken: string): Promise<unknown> {
    if (!this.config.endpoints.userInfoUrl) {
      throw new MissingConfigError("userInfoUrl");
    }

    const response = await fetch(this.config.endpoints.userInfoUrl, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) {
      throw new Error(`User info request failed: ${response.status}`);
    }

    return response.json();
  }
}

export function mapOAuth2ProfileToExternalIdentity(
  profile: any,
  provider: string
): ExternalIdentity {
  const providerUserId = profile?.sub ?? profile?.id;

  if (providerUserId === undefined || providerUserId === null) {
    throw new MissingConfigError("provider user id");
  }

  return {
    provider,
    providerUserId: String(providerUserId),
    email: profile.email,
    emailVerified: profile.email_verified ?? profile.emailVerified,
    username: profile.preferred_username ?? profile.username ?? profile.login,
    name: profile.name,
    picture: profile.picture ?? profile.avatar_url,
    raw: profile,
  };
}
