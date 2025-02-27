import axios from "axios";
import {
  MissingAuthorizationCodeError,
  UserNotFoundError,
} from "../../errors";
import { AuthResult } from "../../types";
import { OAuth2Strategy } from "./oauth2.strategy";
import { InvalidStateError } from "./oauth2.errors";
import { OAuth2Tools } from "./oauth2.tools";

/**
 * A hybrid authentication strategy that extends a base OAuth2 strategy
 * with additional fallbacks for JWT-based authentication and session-based authentication.
 *
 * @template TContext - The type representing the request or application context.
 * @template TUser - The user object type returned after successful authentication.
 */
export abstract class HybridOAuth2Strategy<
  TContext = unknown,
  TUser = unknown
> extends OAuth2Strategy<TContext, TUser> {
  /**
   * Authenticates the user by attempting multiple authentication mechanisms in sequence:
   * 1. **JWT**: If a valid JWT is present, use it directly.
   * 2. **Session**: If a valid user session is found, use it.
   * 3. **OAuth2**: If neither JWT nor session is available/valid, proceed with the OAuth2 flow:
   *    - Attempt to refresh the access token using a refresh token (if present).
   *    - If no valid access token can be obtained, attempt the authorization code exchange.
   *
   * @param {TContext} context - The current request or application context.
   * @returns {Promise<AuthResult<TUser>>} The result of the authentication, including the user object,
   *     tokens (if any), and session (if a session strategy is used).
   *
   * @throws {MissingAuthorizationCodeError} If the strategy needs an authorization code but none is present,
   *     and a redirect to the OAuth provider is triggered.
   * @throws {UserNotFoundError} If no user can be retrieved from the access token or ID token.
   */
  async authenticate(context: TContext): Promise<AuthResult<TUser>> {
    try {
      let tokens;
      let session;
      let accessToken, idToken, refreshToken;

      if (this.jwt) {
        try {
          const jwtResult = await this.jwt.authenticate(context);
          if (jwtResult.user) {
            this.logger?.info("Authenticated using JWT.");
            return jwtResult;
          }
        } catch (e) {
          this.logger?.warn(
            "JWT authentication failed, proceeding with OAuth2 flow."
          );
        }
      }

      if (this.session) {
        try {
          const sessionResult = await this.authenticateWithSession(context);
          if (sessionResult.user) {
            this.logger?.info("Authenticated using session.");
            return sessionResult;
          }
        } catch (e) {
          this.logger?.warn(
            "Session authentication failed, proceeding with OAuth2 flow."
          );
        }
      }

      refreshToken = await this.extractRefreshToken(context);
      if (refreshToken) {
        this.logger?.info("Refreshing expired access token...");
        try {
          const refreshedTokens = await this.refreshAccessToken(context);
          accessToken = refreshedTokens.accessToken;
          idToken = refreshedTokens.idToken;
        } catch (error) {
          this.logger?.warn(
            "Failed to refresh access token, clearing refresh token."
          );
          await this.storeRefreshToken("", context);
        }
      }

      if (!accessToken) {
        const code = this.extractAuthorizationCode(context);
        if (!code) {
          this.login(context);
          throw new MissingAuthorizationCodeError();
        }

        const returnedState = OAuth2Tools.extractState(context);
        if (!(await this.config.state?.validateState(context, returnedState))) {
          throw new InvalidStateError();
        }

        const exchangedTokens = await this.exchangeCodeForToken(context, code);
        accessToken = exchangedTokens.accessToken;
        refreshToken = exchangedTokens.refreshToken;
        idToken = exchangedTokens.idToken;
      }

      const user = idToken
        ? await this.verifyIdToken(idToken)
        : await this.fetchUser(accessToken);

      if (!user) throw new UserNotFoundError();

      if (this.jwt) {
        tokens = await this.jwt.issueTokens(user, context);
      }

      if (this.session) {
        session = await this.session.issueSession(user, context);
      }

      return {
        user,
        tokens: tokens ?? { accessToken, idToken, refreshToken },
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
}
