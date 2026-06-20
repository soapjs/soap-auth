import { GoogleStrategy } from "../google.strategy";
import { GitHubStrategy } from "../github.strategy";
import { FacebookStrategy } from "../facebook.strategy";
import { ConfigurableOAuth2Strategy } from "../configurable-oauth2.strategy";
import { ConfigurableHybridOAuth2Strategy } from "../configurable-hybrid-oauth2.strategy";

const mockFetch = jest.fn();
(global as any).fetch = mockFetch;

const baseConfig = {
  clientId: "client-id",
  clientSecret: "client-secret",
  redirectUri: "https://example.com/callback",
};

const genericConfig = {
  ...baseConfig,
  name: "auth0",
  grantType: "authorization_code",
  endpoints: {
    authorizationUrl: "https://tenant.example/authorize",
    tokenUrl: "https://tenant.example/oauth/token",
    userInfoUrl: "https://tenant.example/userinfo",
  },
  routes: {
    login: { path: "/auth/auth0", method: "GET" },
    callback: { path: "/auth/auth0/callback", method: "GET" },
  },
};

function makeMockCtx() {
  return {
    req: {
      method: "GET",
      path: "/callback",
      headers: { authorization: "Bearer test-token" },
      query: { code: "auth-code", state: "csrf-state" },
      cookies: {},
    },
    res: {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      setHeader: jest.fn().mockReturnThis(),
      cookie: jest.fn().mockReturnThis(),
      redirect: jest.fn(),
    },
    next: jest.fn(),
  } as any;
}

function mockFetchOk(body: object) {
  mockFetch.mockResolvedValueOnce({
    ok: true,
    json: async () => body,
  });
}

describe("GoogleStrategy", () => {
  afterEach(() => jest.clearAllMocks());

  it("has name 'google'", () => {
    const strategy = new GoogleStrategy(baseConfig as any);
    expect(strategy.name).toBe("google");
  });

  it("maps Google profile to AuthUser", async () => {
    const strategy = new GoogleStrategy(baseConfig as any);

    const googleProfile = {
      sub: "google-sub-123",
      email: "user@gmail.com",
      name: "Test User",
      picture: "https://example.com/pic.jpg",
      email_verified: true,
    };

    mockFetchOk(googleProfile);

    const user = await (strategy as any).fetchUser("test-access-token");
    expect(user).toMatchObject({
      id: "google-sub-123",
      email: "user@gmail.com",
      username: "Test User",
      picture: "https://example.com/pic.jpg",
      emailVerified: true,
    });
  });

  it("calls validateUser when provided", async () => {
    const validateUser = jest.fn().mockResolvedValue({ id: "custom-id", email: "x@x.com" });
    const strategy = new GoogleStrategy({ ...baseConfig, user: { fetchUser: jest.fn(), validateUser } } as any);

    mockFetchOk({ sub: "sub123", email: "raw@gmail.com" });

    const user = await (strategy as any).fetchUser("token");
    expect(validateUser).toHaveBeenCalledWith(expect.objectContaining({ sub: "sub123" }));
    expect(user).toMatchObject({ id: "custom-id" });
  });

  it("returns null when fetch fails", async () => {
    const strategy = new GoogleStrategy(baseConfig as any);
    mockFetch.mockResolvedValueOnce({ ok: false, status: 401 });

    const user = await (strategy as any).fetchUser("bad-token");
    expect(user).toBeNull();
  });

  it("uses openid+email+profile scope by default", () => {
    const strategy = new GoogleStrategy(baseConfig as any);
    expect((strategy as any).config.scope).toContain("openid");
  });

  it("respects custom scope", () => {
    const strategy = new GoogleStrategy({ ...baseConfig, scope: ["openid"] } as any);
    expect((strategy as any).config.scope).toEqual(["openid"]);
  });
});

describe("GitHubStrategy", () => {
  afterEach(() => jest.clearAllMocks());

  it("has name 'github'", () => {
    expect(new GitHubStrategy(baseConfig as any).name).toBe("github");
  });

  it("maps GitHub profile to AuthUser", async () => {
    const strategy = new GitHubStrategy(baseConfig as any);

    mockFetchOk({
      id: 12345,
      login: "octocat",
      email: "octocat@github.com",
      name: "The Octocat",
      avatar_url: "https://github.com/avatar.png",
    });

    const user = await (strategy as any).fetchUser("token");
    expect(user).toMatchObject({
      id: 12345,
      email: "octocat@github.com",
      username: "octocat",
      name: "The Octocat",
      avatarUrl: "https://github.com/avatar.png",
    });
  });

  it("returns null when fetch fails", async () => {
    const strategy = new GitHubStrategy(baseConfig as any);
    mockFetch.mockResolvedValueOnce({ ok: false, status: 403 });
    expect(await (strategy as any).fetchUser("bad")).toBeNull();
  });
});

describe("FacebookStrategy", () => {
  afterEach(() => jest.clearAllMocks());

  it("has name 'facebook'", () => {
    expect(new FacebookStrategy(baseConfig as any).name).toBe("facebook");
  });

  it("maps Facebook profile to AuthUser", async () => {
    const strategy = new FacebookStrategy(baseConfig as any);

    mockFetchOk({
      id: "fb-id-456",
      name: "FB User",
      email: "fb@facebook.com",
      picture: { data: { url: "https://fb.com/pic.jpg" } },
    });

    const user = await (strategy as any).fetchUser("token");
    expect(user).toMatchObject({
      id: "fb-id-456",
      email: "fb@facebook.com",
      username: "FB User",
      picture: "https://fb.com/pic.jpg",
    });
  });

  it("returns null on Facebook API error", async () => {
    const strategy = new FacebookStrategy(baseConfig as any);
    mockFetchOk({ error: { message: "Invalid token", code: 190 } });
    expect(await (strategy as any).fetchUser("token")).toBeNull();
  });

  it("returns null when fetch fails", async () => {
    const strategy = new FacebookStrategy(baseConfig as any);
    mockFetch.mockResolvedValueOnce({ ok: false, status: 401 });
    expect(await (strategy as any).fetchUser("bad")).toBeNull();
  });
});

describe("HttpOAuth2Strategy — HTTP plumbing", () => {
  afterEach(() => jest.clearAllMocks());

  it("extracts access token from Authorization header", async () => {
    const strategy = new GoogleStrategy(baseConfig as any);
    const ctx = makeMockCtx();
    const token = await (strategy as any).extractAccessToken(ctx);
    expect(token).toBe("test-token");
  });

  it("extracts access token from cookie when no header", async () => {
    const strategy = new GoogleStrategy(baseConfig as any);
    const ctx = makeMockCtx();
    ctx.req.headers = {};
    ctx.req.cookies = { access_token: "cookie-token" };
    const token = await (strategy as any).extractAccessToken(ctx);
    expect(token).toBe("cookie-token");
  });

  it("extracts refresh token from cookie", async () => {
    const strategy = new GoogleStrategy(baseConfig as any);
    const ctx = makeMockCtx();
    ctx.req.cookies = { refresh_token: "rt-abc" };
    const rt = await (strategy as any).extractRefreshToken(ctx);
    expect(rt).toBe("rt-abc");
  });

  it("extracts authorization code from query", () => {
    const strategy = new GoogleStrategy(baseConfig as any);
    const ctx = makeMockCtx();
    expect((strategy as any).extractAuthorizationCode(ctx)).toBe("auth-code");
  });

  it("embeds access token as Authorization header", () => {
    const strategy = new GoogleStrategy(baseConfig as any);
    const ctx = makeMockCtx();
    (strategy as any).embedAccessToken("new-token", ctx);
    expect(ctx.res.setHeader).toHaveBeenCalledWith("Authorization", "Bearer new-token");
  });

  it("embeds refresh token as httpOnly cookie", () => {
    const strategy = new GoogleStrategy(baseConfig as any);
    const ctx = makeMockCtx();
    (strategy as any).embedRefreshToken("rt-new", ctx);
    expect(ctx.res.cookie).toHaveBeenCalledWith(
      "refresh_token",
      "rt-new",
      expect.objectContaining({ httpOnly: true, secure: true })
    );
  });

  it("redirects via res.redirect when available", () => {
    const strategy = new GoogleStrategy(baseConfig as any);
    const ctx = makeMockCtx();
    (strategy as any).redirectUser(ctx, "https://accounts.google.com/auth");
    expect(ctx.res.redirect).toHaveBeenCalledWith("https://accounts.google.com/auth");
  });

  it("falls back to Location header when res.redirect is missing", () => {
    const strategy = new GoogleStrategy(baseConfig as any);
    const ctx = makeMockCtx();
    delete ctx.res.redirect;
    (strategy as any).redirectUser(ctx, "https://accounts.google.com/auth");
    expect(ctx.res.setHeader).toHaveBeenCalledWith("Location", "https://accounts.google.com/auth");
    expect(ctx.res.status).toHaveBeenCalledWith(302);
  });
});

describe("Configurable OAuth2 strategies", () => {
  afterEach(() => jest.clearAllMocks());

  it("maps a generic provider profile without provider SDKs", async () => {
    const strategy = new ConfigurableOAuth2Strategy(genericConfig as any);
    mockFetchOk({
      sub: "auth0|123",
      email: "user@example.com",
      preferred_username: "user",
      picture: "https://example.com/avatar.png",
    });

    const user = await (strategy as any).fetchUser("access-token");

    expect(strategy.name).toBe("auth0");
    expect(user).toMatchObject({
      id: "auth0|123",
      email: "user@example.com",
      username: "user",
      picture: "https://example.com/avatar.png",
    });
  });

  it("uses validateUser mapper for generic providers", async () => {
    const validateUser = jest.fn(async (profile: any) => ({
      id: profile.custom_id,
      email: profile.mail,
    }));
    const strategy = new ConfigurableOAuth2Strategy({
      ...genericConfig,
      user: { fetchUser: jest.fn(), validateUser },
    } as any);
    mockFetchOk({ custom_id: "u-1", mail: "u@example.com" });

    const user = await (strategy as any).fetchUser("access-token");

    expect(validateUser).toHaveBeenCalledWith({
      custom_id: "u-1",
      mail: "u@example.com",
    });
    expect(user).toMatchObject({ id: "u-1", email: "u@example.com" });
  });

  it("exposes a configurable hybrid strategy name", () => {
    const strategy = new ConfigurableHybridOAuth2Strategy(genericConfig as any);
    expect(strategy.name).toBe("auth0");
  });
});
