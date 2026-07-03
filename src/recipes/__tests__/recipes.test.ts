import {
  createApiKeyAuthConfig,
  createExternalIdentityOAuth2ProviderConfig,
  createHybridOAuth2ProviderConfig,
  createJwtAuthConfig,
  createLocalAuthConfig,
  createOAuth2ProviderConfig,
  extractBearerToken,
  getCookie,
  oauth2ProviderEndpoints,
  redirect,
  setBearerToken,
  setCookie,
} from "../index";

describe("auth config recipes", () => {
  it("creates JWT config with access and refresh token defaults", () => {
    const config = createJwtAuthConfig({
      accessSecret: "access-secret",
      refreshSecret: "refresh-secret",
      user: { fetchUser: async () => ({ id: "u1" }) },
    });

    expect(config.accessToken.issuer.secretKey).toBe("access-secret");
    expect(config.accessToken.issuer.options.expiresIn).toBe("15m");
    expect(config.refreshToken.issuer.secretKey).toBe("refresh-secret");
    expect(config.refreshToken.issuer.options.expiresIn).toBe("7d");
    expect(config.routes.refresh.path).toBe("/auth/jwt/refresh");
  });

  it("creates local config with default credential routes", () => {
    const config = createLocalAuthConfig({
      credentials: {
        extractCredentials: (ctx: any) => ctx.body,
        verifyCredentials: async () => true,
      },
      user: { fetchUser: async () => ({ id: "u1" }) },
    });

    expect(config.routes.login).toEqual({
      path: "/auth/local/login",
      method: "POST",
    });
    expect(config.routes.logout).toEqual({
      path: "/auth/local/logout",
      method: "POST",
    });
  });

  it("creates API key config with long-term default", () => {
    const config = createApiKeyAuthConfig({
      extractApiKey: () => "key",
      retrieveUserByApiKey: async () => ({ id: "u1" }),
    } as any);

    expect(config.keyType).toBe("long-term");
  });

  it("creates configurable OAuth2 config from Auth0 preset", () => {
    const config = createOAuth2ProviderConfig({
      provider: "auth0",
      clientId: "client-id",
      clientSecret: "client-secret",
      redirectUri: "https://app.example/callback",
      presetOptions: { domain: "tenant.auth0.com" },
    });

    expect(config.endpoints.authorizationUrl).toBe(
      "https://tenant.auth0.com/authorize"
    );
    expect(config.routes.callback.path).toBe("/auth/auth0/callback");
  });

  it("creates external identity OAuth2 config from Google preset", () => {
    const config = createExternalIdentityOAuth2ProviderConfig({
      provider: "google",
      clientId: "client-id",
      clientSecret: "client-secret",
      redirectUri: "https://app.example/callback",
      externalIdentity: {
        resolveIdentity: async () => ({ id: "u1" }),
      },
    });

    expect(config.endpoints.userInfoUrl).toBe(
      "https://openidconnect.googleapis.com/v1/userinfo"
    );
    expect(config.externalIdentity.resolveIdentity).toEqual(expect.any(Function));
  });

  it("creates configurable hybrid OAuth2 config from Discord preset", () => {
    const config = createHybridOAuth2ProviderConfig({
      provider: "discord",
      clientId: "client-id",
      clientSecret: "client-secret",
      redirectUri: "https://app.example/callback",
    });

    expect(config.endpoints.userInfoUrl).toBe(
      "https://discord.com/api/users/@me"
    );
  });
});

describe("OAuth2 endpoint presets", () => {
  it("creates Keycloak realm endpoints", () => {
    const endpoints = oauth2ProviderEndpoints.keycloak({
      baseUrl: "https://idp.example.com/",
      realm: "master",
    });

    expect(endpoints.tokenUrl).toBe(
      "https://idp.example.com/realms/master/protocol/openid-connect/token"
    );
  });
});

describe("HTTP context helpers", () => {
  it("extracts and sets bearer token", () => {
    const ctx: any = {
      headers: { authorization: "Bearer abc" },
      setHeader: jest.fn(),
    };

    expect(extractBearerToken(ctx)).toBe("abc");
    setBearerToken(ctx, "new-token");
    expect(ctx.setHeader).toHaveBeenCalledWith(
      "Authorization",
      "Bearer new-token"
    );
  });

  it("gets and sets cookies", () => {
    const ctx: any = {
      cookies: { sid: "123" },
      cookie: jest.fn(),
    };

    expect(getCookie(ctx, "sid")).toBe("123");
    setCookie(ctx, "sid", "456", { httpOnly: true });
    expect(ctx.cookie).toHaveBeenCalledWith("sid", "456", { httpOnly: true });
  });

  it("redirects with a generic redirect function", () => {
    const ctx: any = { redirect: jest.fn() };
    redirect(ctx, "https://example.com");
    expect(ctx.redirect).toHaveBeenCalledWith("https://example.com");
  });
});
