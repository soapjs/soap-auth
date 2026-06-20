import { OAuth2Strategy } from "../oauth2.strategy";
import { OAuth2StrategyConfig } from "../oauth2.types";
import { InvalidStateError } from "../oauth2.errors";
import { MissingAuthorizationCodeError } from "../../../errors";

const mockFetch = jest.fn();
(global as any).fetch = mockFetch;

function mockFetchOk(body: object) {
  mockFetch.mockResolvedValueOnce({
    ok: true,
    status: 200,
    statusText: "OK",
    json: async () => body,
  });
}

function mockFetchFail(status = 400) {
  mockFetch.mockResolvedValueOnce({
    ok: false,
    status,
    statusText: "Bad Request",
    json: async () => ({}),
  });
}

type MockCtx = {
  tokens: { access?: string; refresh?: string };
  query: Record<string, string>;
  redirectTo?: string;
};

class TestOAuth2Strategy extends OAuth2Strategy<MockCtx> {
  readonly name = "test-oauth2";

  protected async extractAccessToken(ctx: MockCtx) {
    return ctx.tokens.access;
  }
  protected async extractRefreshToken(ctx: MockCtx) {
    return ctx.tokens.refresh;
  }
  protected async storeAccessToken(token: string, ctx: MockCtx) {
    ctx.tokens.access = token;
  }
  protected async storeRefreshToken(token: string, ctx: MockCtx) {
    ctx.tokens.refresh = token;
  }
  protected embedAccessToken(token: string, ctx: MockCtx) {
    ctx.tokens.access = token;
  }
  protected embedRefreshToken(token: string, ctx: MockCtx) {
    ctx.tokens.refresh = token;
  }
  protected extractAuthorizationCode(ctx: MockCtx) {
    return ctx.query.code ?? null;
  }
  protected redirectUser(ctx: MockCtx, url: string) {
    ctx.redirectTo = url;
  }
}

const baseConfig: any = {
  clientId: "client-id",
  clientSecret: "client-secret",
  redirectUri: "https://example.com/callback",
  grantType: "authorization_code",
  scope: ["openid", "email"],
  endpoints: {
    authorizationUrl: "https://provider.example/auth",
    tokenUrl: "https://provider.example/token",
    userInfoUrl: "https://provider.example/userinfo",
  },
  routes: {
    login: { path: "/login", method: "GET" },
    callback: { path: "/callback", method: "GET" },
  },
  user: {
    fetchUser: jest.fn(),
    validateUser: jest.fn(async (p: any) => ({ id: p.sub ?? p.id, email: p.email })),
  },
};

function makeCtx(overrides: Partial<MockCtx> = {}): MockCtx {
  return { tokens: {}, query: {}, ...overrides };
}

describe("OAuth2Strategy — state / CSRF", () => {
  afterEach(() => jest.clearAllMocks());

  it("validateState passes when stored === returned state", async () => {
    let stored: string | null = "csrf-abc";
    const config = {
      ...baseConfig,
      state: {
        persistence: {
          store: jest.fn(async (s: string) => { stored = s; }),
          read: jest.fn(async () => stored),
          remove: jest.fn(async () => { stored = null; }),
        },
      },
    };
    const strategy = new TestOAuth2Strategy(config);
    const ctx = makeCtx({ query: { code: "auth-code", state: "csrf-abc" } });

    await expect((strategy as any).validateState(ctx)).resolves.toBeUndefined();
    expect(config.state.persistence.remove).toHaveBeenCalled();
  });

  it("validateState throws InvalidStateError on mismatch", async () => {
    const config = {
      ...baseConfig,
      state: {
        persistence: {
          read: jest.fn(async () => "stored-state"),
          remove: jest.fn(),
        },
      },
    };
    const strategy = new TestOAuth2Strategy(config);
    const ctx = makeCtx({ query: { state: "wrong-state" } });

    await expect((strategy as any).validateState(ctx)).rejects.toThrow(InvalidStateError);
  });

  it("validateState is a no-op when config.state is absent", async () => {
    const strategy = new TestOAuth2Strategy({ ...baseConfig, state: undefined });
    await expect((strategy as any).validateState(makeCtx())).resolves.toBeUndefined();
  });

  it("startAuthorizationFlow generates state, stores it, and redirects", async () => {
    const stored: string[] = [];
    const config = {
      ...baseConfig,
      state: {
        generateState: jest.fn(async () => "gen-state"),
        persistence: {
          store: jest.fn(async (s: string) => stored.push(s)),
        },
      },
    };
    const strategy = new TestOAuth2Strategy(config);
    const ctx = makeCtx();

    await (strategy as any).startAuthorizationFlow(ctx);

    expect(stored).toContain("gen-state");
    expect(ctx.redirectTo).toContain("https://provider.example/auth");
    expect(ctx.redirectTo).toContain("state=gen-state");
  });
});

describe("OAuth2Strategy — buildAuthorizationUrl", () => {
  afterEach(() => jest.clearAllMocks());

  it("includes client_id, redirect_uri, response_type, scope", async () => {
    const strategy = new TestOAuth2Strategy(baseConfig);
    const url = await (strategy as any).buildAuthorizationUrl(makeCtx());
    expect(url).toContain("client_id=client-id");
    expect(url).toContain("redirect_uri=");
    expect(url).toContain("response_type=code");
    expect(url).toContain("scope=openid+email");
  });

  it("embeds state when provided", async () => {
    const strategy = new TestOAuth2Strategy(baseConfig);
    const url = await (strategy as any).buildAuthorizationUrl(makeCtx(), "my-state");
    expect(url).toContain("state=my-state");
  });

  it("embeds nonce when provided", async () => {
    const strategy = new TestOAuth2Strategy(baseConfig);
    const url = await (strategy as any).buildAuthorizationUrl(makeCtx(), undefined, "my-nonce");
    expect(url).toContain("nonce=my-nonce");
  });

  it("awaits and embeds PKCE code challenge", async () => {
    const config = {
      ...baseConfig,
      pkce: {
        verifier: {
          generate: jest.fn(() => "verifier-123"),
          embed: jest.fn(),
          extract: jest.fn(),
        },
        challenge: {
          generate: jest.fn(() => "challenge-456"),
          embed: jest.fn(),
          extract: jest.fn(),
        },
      },
    };
    const strategy = new TestOAuth2Strategy(config);

    const url = await (strategy as any).buildAuthorizationUrl(makeCtx());

    expect(url).toContain("code_challenge=challenge-456");
    expect(url).not.toContain("[object+Promise]");
    expect(url).toContain("code_challenge_method=S256");
  });
});

describe("OAuth2Strategy — verifyAuthorizationCode", () => {
  afterEach(() => jest.clearAllMocks());

  it("does nothing when code is present", async () => {
    const strategy = new TestOAuth2Strategy(baseConfig);
    const ctx = makeCtx();
    await expect(
      (strategy as any).verifyAuthorizationCode(ctx, "valid-code")
    ).resolves.toBeUndefined();
  });

  it("redirects and throws MissingAuthorizationCodeError when code is absent", async () => {
    const strategy = new TestOAuth2Strategy(baseConfig);
    const ctx = makeCtx();
    await expect(
      (strategy as any).verifyAuthorizationCode(ctx, null)
    ).rejects.toThrow(MissingAuthorizationCodeError);
    expect(ctx.redirectTo).toBeDefined();
  });
});

describe("OAuth2Strategy — exchangeCodeForToken", () => {
  afterEach(() => jest.clearAllMocks());

  it("sends correct POST body and returns tokens", async () => {
    mockFetchOk({ access_token: "at-123", refresh_token: "rt-456" });
    const strategy = new TestOAuth2Strategy(baseConfig);

    const result = await (strategy as any).exchangeCodeForToken(makeCtx(), "auth-code");

    expect(result.accessToken).toBe("at-123");
    expect(result.refreshToken).toBe("rt-456");
    expect(mockFetch).toHaveBeenCalledWith(
      "https://provider.example/token",
      expect.objectContaining({ method: "POST" })
    );
    const [, request] = mockFetch.mock.calls[0];
    expect(request.body).toContain("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback");
    expect(request.body).not.toContain("redirectUri=");
  });

  it("throws when token endpoint returns non-ok status", async () => {
    mockFetchFail(401);
    const strategy = new TestOAuth2Strategy(baseConfig);
    await expect(
      (strategy as any).exchangeCodeForToken(makeCtx(), "bad-code")
    ).rejects.toThrow();
  });
});

describe("OAuth2Strategy — isTokenExpired", () => {
  afterEach(() => jest.clearAllMocks());

  it("returns false for non-JWT tokens", () => {
    const strategy = new TestOAuth2Strategy(baseConfig);
    expect((strategy as any).isTokenExpired("opaque-token")).toBe(false);
  });

  it("returns true for an expired JWT", () => {
    const strategy = new TestOAuth2Strategy(baseConfig);
    const pastExp = Math.floor(Date.now() / 1000) - 3600;
    const payload = Buffer.from(JSON.stringify({ exp: pastExp })).toString("base64");
    const jwt = `header.${payload}.sig`;
    expect((strategy as any).isTokenExpired(jwt)).toBe(true);
  });

  it("returns false for a non-expired JWT", () => {
    const strategy = new TestOAuth2Strategy(baseConfig);
    const futureExp = Math.floor(Date.now() / 1000) + 3600;
    const payload = Buffer.from(JSON.stringify({ exp: futureExp })).toString("base64");
    const jwt = `header.${payload}.sig`;
    expect((strategy as any).isTokenExpired(jwt)).toBe(false);
  });

  it("returns false when JWT payload has no exp", () => {
    const strategy = new TestOAuth2Strategy(baseConfig);
    const payload = Buffer.from(JSON.stringify({ sub: "user" })).toString("base64");
    const jwt = `header.${payload}.sig`;
    expect((strategy as any).isTokenExpired(jwt)).toBe(false);
  });
});

describe("OAuth2Strategy — authenticate", () => {
  afterEach(() => jest.clearAllMocks());

  it("exchanges code and returns AuthResult when no token in context", async () => {
    let stored: string | null = "state-xyz";
    const config = {
      ...baseConfig,
      state: {
        persistence: {
          read: jest.fn(async () => stored),
          remove: jest.fn(async () => { stored = null; }),
        },
      },
    };
    const strategy = new TestOAuth2Strategy(config);

    // token exchange
    mockFetchOk({ access_token: "at-new", refresh_token: "rt-new" });
    // user info
    mockFetchOk({ sub: "u1", email: "user@example.com" });

    const ctx = makeCtx({ query: { code: "auth-code", state: "state-xyz" } });
    const result = await strategy.authenticate(ctx);

    expect(result?.user).toMatchObject({ id: "u1", email: "user@example.com" });
    expect(result?.tokens?.accessToken).toBe("at-new");
  });

  it("fetches user when valid access token already in context", async () => {
    const strategy = new TestOAuth2Strategy(baseConfig);
    const futureExp = Math.floor(Date.now() / 1000) + 3600;
    const payload = Buffer.from(JSON.stringify({ exp: futureExp })).toString("base64");
    const validJwt = `h.${payload}.s`;

    mockFetchOk({ sub: "u2", email: "other@example.com" });

    const ctx = makeCtx({ tokens: { access: validJwt } });
    const result = await strategy.authenticate(ctx);

    expect(result?.user).toMatchObject({ id: "u2" });
  });
});
