import * as Soap from "@soapjs/soap";
import axios from "axios";
import {
  AuthError,
  MissingTokenError,
  MissingAuthorizationCodeError,
  UserNotFoundError,
} from "../../errors";
import { TokenConfig, AuthResult } from "../../types";
import { TokenBasedAuthStrategy } from "../token-based-auth.strategy";
import { OAuth2StrategyConfig } from "./oauth2.types";
import { OAuth2Tools } from "./oauth2.tools";
import { SessionHandler } from "../../session/session-handler";

/**
 * Generic OAuth 2.0 authentication strategy.
 *
 * @template TContext - The type of the authentication context.
 * @template TUser - The type of the authenticated user.
 */
export class OAuth2Strategy<
  TContext = unknown,
  TUser = unknown
> extends TokenBasedAuthStrategy<TContext, TUser> {
  constructor(
    protected config: OAuth2StrategyConfig<TContext, TUser>,
    protected accessTokenConfig: TokenConfig,
    protected refreshTokenConfig?: TokenConfig,
    protected session?: SessionHandler,
    protected logger?: Soap.Logger
  ) {
    super(config, accessTokenConfig, refreshTokenConfig, session, logger);
    this.config.scope = this.config.scope ?? "email";
  }

  /**
   * Authenticates the user using OAuth2 token-based authentication.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<AuthResult<TUser>>}
   */
  async authenticate(context: TContext): Promise<AuthResult<TUser>> {
    try {
      let user;
      let refreshToken;
      let accessToken = await this.accessTokenConfig.retrieve?.(context);

      if (!accessToken) {
        this.logger?.info("No access token found, checking for refresh token.");
        refreshToken = await this.refreshTokenConfig?.retrieve?.(context);

        if (refreshToken) {
          this.logger?.info(
            "Found refresh token, attempting to refresh access token."
          );
          const newTokens = await this.refreshAccessToken(context);
          accessToken = newTokens.accessToken;

          this.accessTokenConfig.embed?.(context, accessToken);
          if (newTokens.refreshToken) {
            refreshToken = newTokens.refreshToken;
            this.refreshTokenConfig?.embed?.(context, newTokens.refreshToken);
          }
        } else {
          this.logger?.info(
            "No refresh token found, attempting authentication using grant type."
          );

          switch (this.config.grantType) {
            case "authorization_code":
              const authorizationCode = this.extractAuthorizationCode(context);
              this.verifyAuthorizationCode(context, authorizationCode);
              const tokenResult = await this.exchangeCodeForToken(
                context,
                authorizationCode
              );
              accessToken = tokenResult.accessToken;
              refreshToken = tokenResult.refreshToken;
              break;

            case "client_credentials":
              this.logger?.info("Using client credentials grant.");
              const clientCredResult = await this.exchangeClientCredentials();
              accessToken = clientCredResult.accessToken;
              break;

            case "password":
              this.logger?.info("Using password grant.");
              if (!this.config.credentials) {
                throw new Error("Missing credentials for password grant.");
              }
              const passwordResult = await this.exchangePasswordGrant();
              accessToken = passwordResult.accessToken;
              break;

            default:
              throw new Error(
                `Unsupported grant type: ${this.config.grantType}`
              );
          }

          this.accessTokenConfig.embed?.(context, accessToken);

          if (refreshToken) {
            this.refreshTokenConfig?.embed?.(context, refreshToken);
          }
        }
      } else if (accessToken && (await this.isTokenExpired(accessToken))) {
        this.logger?.info("Access token expired, attempting refresh.");

        refreshToken = await this.refreshTokenConfig?.retrieve?.(context);
        if (!refreshToken) {
          throw new MissingTokenError("Refresh");
        }

        const newTokens = await this.refreshAccessToken(context);
        accessToken = newTokens.accessToken;
        this.accessTokenConfig.embed?.(context, accessToken);

        if (newTokens.refreshToken && newTokens.refreshToken !== refreshToken) {
          refreshToken = newTokens.refreshToken;
          this.refreshTokenConfig?.embed?.(context, newTokens.refreshToken);
        }
      }

      if (!accessToken) {
        throw new MissingTokenError("Access");
      }

      user = await this.retrieveUser(accessToken);
      if (!user) {
        throw new UserNotFoundError();
      }

      // await this.config.storeUserSession?.(user, context);
      await this.isAuthorized(user);

      return { user, tokens: { accessToken, refreshToken } };
    } catch (error) {
      this.logger?.error("OAuth2 authentication failed:", error);
      throw new AuthError(error, "OAuth2 authentication failed.");
    }
  }

  /**
   * Verifies if an authorization code is present in the authentication context.
   * If the code is missing, redirects the user to the authorization URL.
   *
   * @param {TContext} context - The authentication context.
   * @param {string} code - The authorization code to verify.
   * @throws {MissingAuthorizationCodeError} If the authorization code is missing.
   */
  protected verifyAuthorizationCode(context: TContext, code: string) {
    if (!code) {
      this.logger?.warn("Authorization code missing, redirecting user.");
      const authUrl = this.buildAuthorizationUrl(context);
      this.redirectUser(context, authUrl);
      throw new MissingAuthorizationCodeError();
    }
  }

  /**
   * Extracts the authorization code from the request context.
   *
   * @param {TContext} context - The authentication context.
   * @returns {string | null} The extracted authorization code or null if not found.
   */
  protected extractAuthorizationCode(context: TContext): string | null {
    if (typeof context === "object" && "query" in context) {
      return (context as any).query.code || null;
    }
    return null;
  }

  /**
   * Redirects the user to the specified authorization URL.
   *
   * @param {TContext} context - The authentication context.
   * @param {string} authUrl - The URL to redirect the user to.
   */
  protected redirectUser(context: TContext, authUrl: string): void {
    if (typeof context === "object" && "response" in context) {
      (context as any).response.redirect(authUrl);
    } else {
      this.logger?.warn("Redirect attempted in unsupported context.");
    }
  }

  /**
   * Builds the OAuth2 authorization URL based on the provided configuration.
   *
   * @param {TContext} context - The authentication context.
   * @returns {string} The constructed authorization URL.
   */
  protected buildAuthorizationUrl(context: TContext): string {
    let authorizationUrl = `${
      this.config.endpoints.authorizationUrl
    }?client_id=${this.config.clientId}&redirect_uri=${encodeURIComponent(
      this.config.redirectUri
    )}&response_type=code&scope=${this.config.scope ?? ""}`;

    if (this.config.pkce) {
      const codeVerifier = this.config.pkce.generateCodeVerifier
        ? this.config.pkce.generateCodeVerifier()
        : OAuth2Tools.generateCodeVerifier();

      const codeChallenge = OAuth2Tools.generateCodeChallenge(codeVerifier);

      // Store the code verifier in the provided storage function or default to session
      this.config.pkce.storeCodeVerifier?.(context, codeVerifier);

      authorizationUrl += `&code_challenge=${codeChallenge}&code_challenge_method=S256`;
    }

    return authorizationUrl;
  }

  /**
   * Exchanges an authorization code for an access token using the token endpoint.
   *
   * @param {TContext} context - The authentication context.
   * @param {string} code - The authorization code obtained from the provider.
   * @returns {Promise<{ accessToken: string; refreshToken?: string }>}
   * An object containing the access and optional refresh token.
   * @throws {Error} If token exchange fails.
   */
  protected async exchangeCodeForToken(
    context: TContext,
    code: string
  ): Promise<{ accessToken: string; refreshToken?: string }> {
    const data: Record<string, any> = {
      grant_type: "authorization_code",
      client_id: this.config.clientId,
      code,
      redirect_uri: this.config.redirectUri,
    };

    if (this.config.pkce) {
      const codeVerifier = this.config.pkce.retrieveCodeVerifier?.(context);
      if (!codeVerifier) {
        throw new Error("Missing PKCE code verifier in context.");
      }
      data.code_verifier = codeVerifier;
    } else if (this.config.clientSecret) {
      data.client_secret = this.config.clientSecret;
    }

    const response = await fetch(this.config.endpoints.tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(data).toString(),
    });

    if (!response.ok) {
      throw new Error(`Token exchange failed with status: ${response.status}`);
    }

    const tokenData = await response.json();
    return {
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
    };
  }

  /**
   * Handles authorization redirection by building the authorization URL
   * and redirecting the user to the OAuth provider.
   *
   * @param {TContext} context - The authentication context.
   * @throws {AuthError} If redirection fails.
   */
  handleAuthorizationRedirect(context: TContext) {
    try {
      const authUrl = this.buildAuthorizationUrl(context);
      this.redirectUser(context, authUrl);
    } catch (error) {
      this.logger?.error("Authorization redirect failed:", error);
      throw new AuthError(error, "Authorization redirect failed.");
    }
  }

  /**
   * Fetches user information using the user info endpoint.
   *
   * @param {string} accessToken - The access token to retrieve user data.
   * @returns {Promise<TUser | null>}
   */
  protected async retrieveUser(accessToken: string): Promise<TUser | null> {
    try {
      if (!this.config.endpoints.userInfoUrl) {
        throw new Error("User info endpoint not configured.");
      }

      const response = await axios.get(this.config.endpoints.userInfoUrl, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      return (await this.config.validateUser?.(response.data)) || null;
    } catch (error) {
      this.logger?.error("Failed to fetch user information:", error);
      return null;
    }
  }

  /**
   * Exchanges client credentials for an access token.
   *
   * @returns {Promise<{ accessToken: string }>}
   */
  protected async exchangeClientCredentials(): Promise<{
    accessToken: string;
  }> {
    const response = await axios.post(this.config.endpoints.tokenUrl, {
      grant_type: "client_credentials",
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
    });

    return { accessToken: response.data.access_token };
  }

  /**
   * Exchanges username and password for an access token.
   *
   * @returns {Promise<{ accessToken: string }>}
   */
  protected async exchangePasswordGrant(): Promise<{ accessToken: string }> {
    if (!this.config.credentials) {
      throw new Error("Missing credentials for password grant.");
    }

    const response = await axios.post(this.config.endpoints.tokenUrl, {
      grant_type: "password",
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      username: this.config.credentials.username,
      password: this.config.credentials.password,
    });

    return { accessToken: response.data.access_token };
  }

  /**
   * Refreshes an access token using a refresh token.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<{ accessToken: string; refreshToken?: string }>}
   */
  async refreshAccessToken(
    context: TContext
  ): Promise<{ accessToken: string; refreshToken?: string }> {
    try {
      const refreshToken = await this.refreshTokenConfig?.retrieve?.(context);
      if (!refreshToken) {
        throw new MissingTokenError("Refresh");
      }

      const response = await axios.post(this.config.endpoints.tokenUrl, {
        grant_type: "refresh_token",
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        refresh_token: refreshToken,
      });

      const refreshedTokens = {
        accessToken: response.data.access_token,
        refreshToken: response.data.refresh_token,
      };

      // Embed new tokens in context
      await this.accessTokenConfig.embed?.(
        context,
        refreshedTokens.accessToken
      );
      if (refreshedTokens.refreshToken) {
        await this.refreshTokenConfig?.embed?.(
          context,
          refreshedTokens.refreshToken
        );
      }

      return refreshedTokens;
    } catch (error) {
      this.logger?.error("Token refresh failed:", error);
      throw new AuthError(error, "Token refresh failed.");
    }
  }

  /**
   * Revokes a given token.
   *
   * @param {string} token - The token to be revoked.
   */
  async revokeToken(token: string): Promise<void> {
    if (!this.config.endpoints.revocationUrl) return;

    try {
      await axios.post(this.config.endpoints.revocationUrl, {
        token,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
      });
      this.logger?.info("Token revoked successfully.");
    } catch (error) {
      this.logger?.error("Failed to revoke token:", error);
    }
  }
}
