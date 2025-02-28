import * as Soap from "@soapjs/soap";
import axios from "axios";
import {
  MissingTokenError,
  MissingAuthorizationCodeError,
  UserNotFoundError,
  MissingConfigError,
  MissingCredentialsError,
} from "../../errors";
import { AuthResult } from "../../types";
import { OAuth2StrategyConfig } from "./oauth2.types";
import { OAuth2Tools, prepareOAuth2Config } from "./oauth2.tools";
import { SessionHandler } from "../../session/session-handler";
import { BaseAuthStrategy } from "../base-auth.strategy";
import { JwtStrategy } from "../jwt/jwt.strategy";
import { JwtService } from "../../services/jwks.service";
import { PKCEService } from "../../services/pkce.service";
import {
  InvalidNonceError,
  MissingCodeVerifierError,
  UnsupportedGrantTypeError,
} from "./oauth2.errors";

/**
 * Generic OAuth 2.0 authentication strategy.
 *
 * @template TContext - The type of the authentication context.
 * @template TUser - The type of the authenticated user.
 */
export abstract class OAuth2Strategy<
  TContext = unknown,
  TUser = unknown
> extends BaseAuthStrategy<TContext, TUser> {
  protected jwks: JwtService;
  protected pkce: PKCEService<TContext>;

  /**
   * Retrieves an access token from the context.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<string | undefined>} The retrieved access token or undefined if not found.
   */
  protected abstract extractAccessToken(
    context: TContext
  ): Promise<string | undefined>;

  /**
   * Retrieves a refresh token from the context.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<string | undefined>} The retrieved refresh token or undefined if not found.
   */
  protected abstract extractRefreshToken(
    context: TContext
  ): Promise<string | undefined>;

  /**
   * Stores an access token in the designated storage (e.g., database, session, cookies).
   *
   * @param {string} token - The access token to store.
   * @param {TContext} context - The authentication context.
   */
  protected abstract storeAccessToken(
    token: string,
    context: TContext
  ): Promise<void>;

  /**
   * Stores a refresh token in the designated storage.
   *
   * @param {string} token - The refresh token to store.
   * @param {TContext} context - The authentication context.
   */
  protected abstract storeRefreshToken(
    token: string,
    context: TContext
  ): Promise<void>;

  /**
   * Embeds an access token into the response context.
   *
   * @param {string} token - The access token.
   * @param {TContext} context - The authentication context.
   */
  protected abstract embedAccessToken(token: string, context: TContext);

  /**
   * Embeds a refresh token into the response context.
   *
   * @param {string} token - The refresh token.
   * @param {TContext} context - The authentication context.
   */
  protected abstract embedRefreshToken(token: string, context: TContext);

  /**
   * Extracts the authorization code from the request context.
   *
   * @param {TContext} context - The authentication context.
   * @returns {string | null} The extracted authorization code or null if not found.
   */
  protected abstract extractAuthorizationCode(context: TContext): string | null;

  /**
   * Redirects the user to the specified authorization URL.
   *
   * @param {TContext} context - The authentication context.
   * @param {string} authUrl - The URL to redirect the user to.
   */
  protected abstract redirectUser(context: TContext, authUrl: string): void;

  constructor(
    protected config: OAuth2StrategyConfig<TContext, TUser>,
    protected session?: SessionHandler,
    protected jwt?: JwtStrategy<TContext, TUser>,
    protected logger?: Soap.Logger
  ) {
    super(prepareOAuth2Config(config), session, logger);

    if (config.jwks) {
      this.jwks = new JwtService({ ...config.jwks, audience: config.clientId });
    }

    if (config.pkce) {
      this.pkce = new PKCEService(config.pkce);
    }
  }

  async logout(context: TContext): Promise<void> {
    try {
      await this.storeAccessToken("", context);
      await this.storeRefreshToken("", context);

      if (this.config.endpoints.logoutUrl) {
        this.logger?.info("Redirecting to OAuth2 logout endpoint.");
        this.redirectUser(context, this.config.endpoints.logoutUrl);
      }
    } catch (error) {
      await this.onFailure("logout", {
        context,
        error,
      });
      throw error;
    }
  }

  /**
   * Extracts user credentials from the authentication context.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<{ identifier: string; password: string }>} The extracted credentials.
   */
  protected async getCredentialsForPasswordGrant(
    context: TContext
  ): Promise<{ identifier: string; password: string }> {
    if (this.config.credentials?.extractCredentials) {
      return this.config.credentials.extractCredentials(context);
    } else if (typeof context === "object" && "body" in context) {
      const body = (context as any).body;
      if (body.username && body.password) {
        return {
          identifier: body.username,
          password: body.password,
        };
      }
    }
    throw new MissingCredentialsError();
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
      let session;
      let refreshToken;
      let accessToken = await this.extractAccessToken(context);

      if (!accessToken) {
        this.logger?.info("No access token found, checking for refresh token.");
        refreshToken = await this.extractRefreshToken(context);

        if (refreshToken) {
          this.logger?.info(
            "Found refresh token, attempting to refresh access token."
          );
          const newTokens = await this.refreshAccessToken(context);
          accessToken = newTokens.accessToken;

          this.embedAccessToken(accessToken, context);
          if (newTokens.refreshToken) {
            refreshToken = newTokens.refreshToken;
            this.embedRefreshToken(newTokens.refreshToken, context);
          }
        } else {
          this.logger?.info(
            "No refresh token found, attempting authentication using grant type."
          );

          const tokens = await this.processOAuthFlow(context);
          accessToken = tokens.accessToken;
          refreshToken = tokens.refreshToken;

          this.embedAccessToken(accessToken, context);

          if (refreshToken) {
            this.embedRefreshToken(refreshToken, context);
          }
        }
      } else if (accessToken && this.isTokenExpired(accessToken)) {
        this.logger?.info("Access token expired, attempting refresh.");

        refreshToken = await this.extractRefreshToken(context);
        if (!refreshToken) {
          throw new MissingTokenError("Refresh");
        }

        const newTokens = await this.refreshAccessToken(context);
        accessToken = newTokens.accessToken;
        this.embedAccessToken(accessToken, context);

        if (newTokens.refreshToken && newTokens.refreshToken !== refreshToken) {
          refreshToken = newTokens.refreshToken;
          this.embedRefreshToken(newTokens.refreshToken, context);
        }
      }

      if (!accessToken) {
        throw new MissingTokenError("Access");
      }

      user = await this.fetchUser(accessToken);
      if (!user) {
        this.logger?.error(
          "User retrieval failed: No user found for access token."
        );
        throw new UserNotFoundError();
      }

      if (this.session) {
        session = await this.session.issueSession(user, context);
      }

      await this.role.isAuthorized(user);

      return { user: user, tokens: { accessToken, refreshToken }, session };
    } catch (error) {
      await this.onFailure("authenticate", {
        context,
        error,
      });
      throw error;
    }
  }

  protected async processOAuthFlow(context: TContext): Promise<{
    accessToken: string;
    refreshToken?: string;
  }> {
    if (this.config.grantType === "authorization_code") {
      const authorizationCode = this.extractAuthorizationCode(context);
      await this.verifyAuthorizationCode(context, authorizationCode);
      const tokenResult = await this.exchangeCodeForToken(
        context,
        authorizationCode
      );
      return tokenResult;
    }

    if (this.config.grantType === "client_credentials") {
      this.logger?.info("Using client credentials grant.");
      const clientCredResult = await this.exchangeClientCredentials();
      return { accessToken: clientCredResult.accessToken };
    }

    if (this.config.grantType === "password") {
      this.logger?.info("Using password grant.");
      const credentials = await this.getCredentialsForPasswordGrant(context);
      if (!credentials) {
        throw new MissingCredentialsError();
      }
      const passwordResult = await this.exchangePasswordGrant(
        credentials.identifier,
        credentials.password
      );
      return { accessToken: passwordResult.accessToken };
    }

    throw new UnsupportedGrantTypeError(this.config.grantType);
  }

  /**
   * Verifies if an authorization code is present in the authentication context.
   * If the code is missing, redirects the user to the authorization URL.
   *
   * @param {TContext} context - The authentication context.
   * @param {string} code - The authorization code to verify.
   * @throws {MissingAuthorizationCodeError} If the authorization code is missing.
   */
  protected async verifyAuthorizationCode(context: TContext, code: string) {
    if (!code) {
      this.logger?.warn("Authorization code missing, redirecting user.");
      const authUrl = await this.buildAuthorizationUrl(context);
      this.redirectUser(context, authUrl);
      throw new MissingAuthorizationCodeError();
    }
  }

  /**
   * Builds the OAuth2 authorization URL based on the provided configuration.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<string>} The constructed authorization URL.
   */
  protected async buildAuthorizationUrl(context: TContext): Promise<string> {
    let authorizationUrl = `${
      this.config.endpoints.authorizationUrl
    }?client_id=${this.config.clientId}&redirect_uri=${encodeURIComponent(
      this.config.redirectUri
    )}&response_type=code&scope=${this.config.scope ?? ""}`;

    if (this.pkce) {
      const codeVerifier = await this.pkce.generateCodeVerifier(context);
      const codeChallenge = this.pkce.generateCodeChallenge(
        codeVerifier,
        context
      );
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
  ): Promise<{ accessToken: string; idToken?: string; refreshToken?: string }> {
    const data: Record<string, any> = {
      grant_type: "authorization_code",
      client_id: this.config.clientId,
      code,
      redirectUri: this.config.redirectUri,
    };

    if (this.pkce) {
      const codeVerifier = this.pkce.extractCodeVerifier(context);
      if (!codeVerifier) {
        throw new MissingCodeVerifierError();
      }
      data.code_verifier = codeVerifier;
    } else if (this.config.clientSecret) {
      data.client_secret = this.config.clientSecret;
    }

    const response = await axios.post(this.config.endpoints.tokenUrl, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(data).toString(),
    });

    const tokenData = await response.data();

    return {
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      idToken: tokenData.id_token,
    };
  }

  /**
   * Handles authorization redirection by building the authorization URL
   * and redirecting the user to the OAuth provider.
   *
   * @param {TContext} context - The authentication context.
   * @throws {AuthError} If redirection fails.
   */
  async login(context: TContext) {
    try {
      const state = await OAuth2Tools.generateState(this.config);
      const nonce = await OAuth2Tools.generateNonce(this.config);

      await this.config.state?.persistence?.store?.(state);
      await this.config.nonce?.persistence?.store?.(nonce);

      const authUrl = await this.buildAuthorizationUrl(context);
      this.redirectUser(context, authUrl);
    } catch (error) {
      await this.onFailure("login", {
        context,
        error,
      });
      throw error;
    }
  }

  /**
   * Fetches user information using the user info endpoint.
   *
   * @param {string} accessToken - The access token to retrieve user data.
   * @returns {Promise<TUser | null>}
   */
  protected async fetchUser(accessToken: string): Promise<TUser | null> {
    try {
      if (!this.config.endpoints.userInfoUrl) {
        throw new MissingConfigError("userInfoUrl");
      }

      const response = await axios.get(this.config.endpoints.userInfoUrl, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      return (await this.config.user.validateUser(response.data)) || null;
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
  protected async exchangePasswordGrant(
    username: string,
    password: string
  ): Promise<{ accessToken: string }> {
    if (!username || !password) {
      throw new MissingCredentialsError();
    }

    const response = await axios.post(this.config.endpoints.tokenUrl, {
      grant_type: "password",
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      username,
      password,
    });

    return { accessToken: response.data.access_token };
  }

  /**
   * Refreshes an access token using a refresh token.
   *
   * @param {TContext} context - The authentication context.
   * @returns {Promise<{ accessToken: string; refreshToken?: string; idToken?: string }>}
   */
  async refreshAccessToken(context: TContext): Promise<{
    accessToken: string;
    refreshToken?: string;
    idToken?: string;
  }> {
    try {
      const refreshToken = await this.extractRefreshToken(context);
      if (!refreshToken) {
        throw new MissingTokenError("Refresh");
      }

      const response = await axios.post(this.config.endpoints.tokenUrl, {
        grant_type: "refresh_token",
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        refresh_token: refreshToken,
      });

      if (response.data.error) {
        this.logger?.warn(
          `OAuth2 error: ${
            response.data.error_description || response.data.error
          }`
        );
      }

      if (response.status !== 200 || !response.data.access_token) {
        throw new Error("Failed to refresh token");
      }

      const refreshedTokens = {
        accessToken: response.data.access_token,
        refreshToken: response.data.refresh_token,
        idToken: response.data.id_token,
      };

      await this.storeAccessToken(refreshedTokens.accessToken, context);
      await this.embedAccessToken(refreshedTokens.accessToken, context);

      if (refreshedTokens.refreshToken) {
        await this.storeRefreshToken(refreshedTokens.refreshToken, context);
        await this.embedRefreshToken(refreshedTokens.refreshToken, context);
      }

      return refreshedTokens;
    } catch (error) {
      await this.handleTokenRefreshFailure(context);
      await this.onFailure("refresh_access_token", {
        error,
      });

      throw error;
    }
  }

  protected async handleTokenRefreshFailure(context: TContext) {
    try {
      if (this.config.refreshToken) {
        await this.storeRefreshToken("", context);
      }

      if (this.config.autoLogoutOnRefreshFailure) {
        await this.logout(context);
      }
    } catch (e) {
      this.logger?.error(e);
    }
  }

  protected async verifyIdToken(idToken: string): Promise<TUser | null> {
    const storedNonce = await this.config?.nonce?.persistence?.read?.();

    if (storedNonce) {
      const decodedToken = await this.jwks.verify(idToken);

      if (decodedToken.nonce) {
        if (
          (await OAuth2Tools.validateNonce(
            storedNonce,
            decodedToken.nonce,
            this.config.nonce
          )) === false
        ) {
          throw new InvalidNonceError("Invalid nonce value");
        }
      }

      if (decodedToken) {
        return this.config.user?.validateUser?.(decodedToken);
      }
    }

    return null;
  }

  /**
   * Revokes a given token.
   *
   * @param {string} token - The token to be revoked.
   */
  async revokeToken(token: string): Promise<void> {
    if (!this.config.endpoints?.revocationUrl) {
      throw new MissingConfigError("revocationUrl");
    }

    try {
      await axios.post(this.config.endpoints.revocationUrl, {
        token,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
      });
      this.logger?.info("Token revoked successfully.");
    } catch (error) {
      await this.onFailure("revoke_token", {
        error,
      });

      throw error;
    }
  }

  protected isTokenExpired(token: string): boolean {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) {
        this.logger?.warn(
          "Non-JWT token provided, cannot determine expiration."
        );
        return false;
      }

      const decoded = JSON.parse(Buffer.from(parts[1], "base64").toString());
      if (!decoded.exp) return false;

      const currentTime = Math.floor(Date.now() / 1000);
      return decoded.exp < currentTime;
    } catch (error) {
      this.logger?.warn("Failed to decode token:", error);
      return false;
    }
  }
}
