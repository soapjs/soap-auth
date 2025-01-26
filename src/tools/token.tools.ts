import {
  BodyStorageOptions,
  CookieStorageOptions,
  HeaderStorageOptions,
  SessionStorageOptions,
} from "../types";

export class TokenTools {
  /**
   * Stores the provided token in the request headers.
   *
   * @param {TContext} context - The request context.
   * @param {string} token - The token to store.
   * @param {HeaderStorageOptions} [options] - Optional configuration for header storage.
   */
  static storeInHeader<TContext = unknown>(
    context: TContext,
    token: string,
    options?: HeaderStorageOptions
  ): void {
    const headerName = options?.headerName ?? "Authorization";
    (context as any).setHeader(headerName, token);
  }

  /**
   * Stores the provided token in cookies.
   *
   * @param {TContext} context - The request context.
   * @param {string} token - The token to store.
   * @param {CookieStorageOptions} [options] - Optional configuration for cookie storage.
   * @param {boolean} [isAccessToken=true] - Indicates whether the token is an access token or refresh token.
   */
  static storeInCookie<TContext = unknown>(
    context: TContext,
    token: string,
    options?: CookieStorageOptions,
    isAccessToken: boolean = true
  ): void {
    const cookieName =
      options?.cookieName ?? (isAccessToken ? "AccessToken" : "RefreshToken");

    const ctx = context as any;
    ctx.res.cookie(cookieName, token, {
      httpOnly: options?.httpOnly ?? true,
      secure: options?.secure ?? true,
      sameSite: options?.sameSite ?? "Lax",
      maxAge: options?.maxAge ?? 3600000, // Default 1 hour
    });
  }

  /**
   * Stores the provided token in the response body.
   *
   * @param {TContext} context - The request context.
   * @param {string} token - The token to store.
   * @param {BodyStorageOptions} [options] - Optional configuration for body storage.
   * @param {boolean} [isAccessToken=true] - Indicates whether the token is an access token or refresh token.
   */
  static storeInBody<TContext = unknown>(
    context: TContext,
    token: string,
    options?: BodyStorageOptions,
    isAccessToken: boolean = true
  ): void {
    const ctx = context as any;
    ctx.body = ctx.body || {};

    const fieldName =
      options?.name ?? (isAccessToken ? "accessToken" : "refreshToken");
    ctx.body[fieldName] = token;
  }

  /**
   * Stores the provided token in the session storage.
   *
   * @param {TContext} context - The request context.
   * @param {string} token - The token to store.
   * @param {SessionStorageOptions} [options] - Optional configuration for session storage.
   * @param {boolean} [isAccessToken=true] - Indicates whether the token is an access token or refresh token.
   */
  static storeInSession<TContext = unknown>(
    context: TContext,
    token: string,
    options?: SessionStorageOptions,
    isAccessToken: boolean = true
  ): void {
    const ctx = context as any;
    ctx.session = ctx.session || {};

    const sessionKey =
      options?.name ?? (isAccessToken ? "accessToken" : "refreshToken");
    ctx.session[sessionKey] = token;
  }
}
