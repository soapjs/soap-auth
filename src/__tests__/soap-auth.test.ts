import { jest } from "@jest/globals";
import { SoapAuth } from "../soap-auth";
import { MemorySessionStore } from "../session/memory.session-store";

describe("SoapAuth", () => {
  let soapAuth;
  const mockLogger: any = { error: jest.fn(), info: jest.fn() };
  const mockStrategy: any = {
    authenticate: jest.fn(),
    init: jest.fn(),
    logout: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    soapAuth = new SoapAuth({ logger: mockLogger });
  });

  test("addStrategy should add a valid strategy", () => {
    expect(() =>
      soapAuth.addStrategy(mockStrategy, "jwt", "http")
    ).not.toThrow();
    expect(soapAuth.hasStrategy("jwt", "http")).toBe(true);
  });

  test("addStrategy should throw error if strategy is invalid", () => {
    expect(() => soapAuth.addStrategy({}, "invalid", "http")).toThrow(
      "Invalid authentication strategy: does not implement required methods."
    );
  });

  test("removeStrategy should remove an existing strategy", () => {
    soapAuth.addStrategy(mockStrategy, "jwt", "http");
    expect(soapAuth.hasStrategy("jwt", "http")).toBe(true);
    soapAuth.removeStrategy("jwt", "http");
    expect(soapAuth.hasStrategy("jwt", "http")).toBe(false);
  });

  test("getStrategy should return an existing strategy", () => {
    soapAuth.addStrategy(mockStrategy, "jwt", "http");
    expect(soapAuth.getStrategy("jwt", "http")).toBe(mockStrategy);
  });

  test("getStrategy should throw an error if strategy does not exist", () => {
    expect(() => soapAuth.getStrategy("nonexistent", "http")).toThrow(
      'Authentication strategy "nonexistent" not found.'
    );
  });

  test("listStrategies should return all registered strategy names", () => {
    soapAuth.addStrategy(mockStrategy, "jwt", "http");
    soapAuth.addStrategy(mockStrategy, "oauth", "http");
    expect(soapAuth.listStrategies("http")).toEqual(["jwt", "oauth"]);
  });
});

describe("SoapAuth.create()", () => {
  const mockLogger: any = { error: jest.fn(), info: jest.fn(), warn: jest.fn() };

  const apiKeyConfig: any = {
    keyType: "session",
    extractApiKey: (ctx: any) => ctx?.headers?.["x-api-key"],
    retrieveUserByApiKey: async (_key: string) => ({ id: "1", email: "test@test.com" }),
  };

  const jwtConfig: any = {
    accessToken: {
      issuer: {
        secretKey: "test-secret-key-for-tests",
        options: { expiresIn: "1h" },
      },
      verifier: { options: {} },
    },
    routes: {
      login: { path: "/auth/jwt/login", method: "POST" },
      logout: { path: "/auth/jwt/logout", method: "POST" },
    },
  };

  const localConfig: any = {
    credentials: {
      extractCredentials: (ctx: any) => ({
        identifier: ctx?.body?.username,
        password: ctx?.body?.password,
      }),
      verifyCredentials: async (_id: string, _pwd: string) => true,
    },
    user: { fetchUser: async (_id: any) => ({ id: "1", email: "u@test.com" }) },
    routes: {
      login: { path: "/auth/login", method: "POST" },
      logout: { path: "/auth/logout", method: "POST" },
    },
  };

  test("registers api-key strategy from config", async () => {
    const auth = await SoapAuth.create({
      http: { apiKey: apiKeyConfig },
      logger: mockLogger,
    });
    expect(auth.hasStrategy("api-key", "http")).toBe(true);
  });

  test("registers jwt as standalone HTTP strategy from http.jwt", async () => {
    const auth = await SoapAuth.create({
      http: { jwt: jwtConfig },
      logger: mockLogger,
    });
    expect(auth.hasStrategy("jwt", "http")).toBe(true);
  });

  test("registers local strategy from config", async () => {
    const auth = await SoapAuth.create({
      http: { local: localConfig },
      logger: mockLogger,
    });
    expect(auth.hasStrategy("local", "http")).toBe(true);
  });

  test("registers multiple HTTP strategies simultaneously", async () => {
    const auth = await SoapAuth.create({
      http: { apiKey: apiKeyConfig, jwt: jwtConfig, local: localConfig },
      logger: mockLogger,
    });
    expect(auth.hasStrategy("api-key", "http")).toBe(true);
    expect(auth.hasStrategy("jwt", "http")).toBe(true);
    expect(auth.hasStrategy("local", "http")).toBe(true);
  });

  test("registers built-in OAuth2 providers from config", async () => {
    const auth = await SoapAuth.create({
      http: {
        oauth2: {
          google: {
            clientId: "client-id",
            clientSecret: "client-secret",
            redirectUri: "https://example.com/auth/google/callback",
          },
        },
      },
      logger: mockLogger,
    });
    expect(auth.hasStrategy("google", "http")).toBe(true);
  });

  test("external identity OAuth2 resolves app user and issues app JWT", async () => {
    const fetchMock = jest
      .spyOn(global, "fetch" as any)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: "google-access-token" }),
      } as any)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          sub: "google-user-id",
          email: "user@example.com",
          name: "Google User",
          email_verified: true,
        }),
      } as any);

    const auth = await SoapAuth.create({
      http: {
        jwt: jwtConfig,
        oauth2: {
          google: {
            clientId: "client-id",
            clientSecret: "client-secret",
            redirectUri: "https://example.com/auth/google/callback",
            externalIdentity: {
              resolveIdentity: jest.fn(async (identity: any) => ({
                id: `app:${identity.providerUserId}`,
                email: identity.email,
                roles: ["user"],
              })),
            },
          },
        },
      },
      logger: mockLogger,
    });

    const strategy = auth.getStrategy<any>("google", "http");
    const context: any = {
      req: {
        query: { code: "callback-code" },
        headers: {},
        cookies: {},
      },
      res: {
        setHeader: jest.fn(),
        cookie: jest.fn(),
      },
    };

    const result = await strategy.authenticate(context);

    expect(result.user).toEqual({
      id: "app:google-user-id",
      email: "user@example.com",
      roles: ["user"],
    });
    expect(result.tokens.accessToken).toEqual(expect.any(String));
    expect(result.tokens.accessToken).not.toBe("google-access-token");
    expect(fetchMock).toHaveBeenCalledTimes(2);

    fetchMock.mockRestore();
  });

  test("registers configurable OAuth2 providers from config", async () => {
    const auth = await SoapAuth.create({
      http: {
        oauth2: {
          auth0: {
            clientId: "client-id",
            clientSecret: "client-secret",
            redirectUri: "https://example.com/auth/auth0/callback",
            endpoints: {
              authorizationUrl: "https://tenant.auth0.com/authorize",
              tokenUrl: "https://tenant.auth0.com/oauth/token",
              userInfoUrl: "https://tenant.auth0.com/userinfo",
            },
            user: {
              fetchUser: jest.fn(async () => null),
              validateUser: jest.fn(async (profile: any) => ({
                id: profile.sub,
                email: profile.email,
              })),
            },
          },
        },
      },
      logger: mockLogger,
    });
    expect(auth.hasStrategy("auth0", "http")).toBe(true);
  });

  test("registers configurable hybrid OAuth2 providers from config", async () => {
    const auth = await SoapAuth.create({
      http: {
        jwt: jwtConfig,
        hybridOAuth2: {
          enterprise: {
            clientId: "client-id",
            clientSecret: "client-secret",
            redirectUri: "https://example.com/auth/enterprise/callback",
            endpoints: {
              authorizationUrl: "https://idp.example.com/authorize",
              tokenUrl: "https://idp.example.com/token",
              userInfoUrl: "https://idp.example.com/userinfo",
            },
          },
        },
      },
      logger: mockLogger,
    });
    expect(auth.hasStrategy("enterprise", "http")).toBe(true);
  });

  test("rejects incomplete configurable OAuth2 provider configs", async () => {
    await expect(
      SoapAuth.create({
        http: {
          oauth2: {
            customProvider: {
              clientId: "client-id",
              clientSecret: "client-secret",
              redirectUri: "https://example.com/callback",
            },
          },
        },
        logger: mockLogger,
      } as any)
    ).rejects.toThrow(
      'OAuth2 provider "customProvider" requires endpoints.authorizationUrl and endpoints.tokenUrl'
    );
  });

  test("registers custom strategies from config", async () => {
    const customStrategy: any = { name: "custom", authenticate: jest.fn() };
    const auth = await SoapAuth.create({
      http: { custom: { myStrategy: customStrategy } },
      logger: mockLogger,
    });
    expect(auth.hasStrategy("myStrategy", "http")).toBe(true);
  });

  test("registers socket JWT strategy from config", async () => {
    const auth = await SoapAuth.create({
      socket: { jwt: jwtConfig },
      logger: mockLogger,
    });
    expect(auth.hasStrategy("jwt", "socket")).toBe(true);
  });

  test("returns empty SoapAuth when no strategy configs provided", async () => {
    const auth = await SoapAuth.create({ logger: mockLogger });
    expect(auth.listStrategies("http")).toEqual([]);
  });

  test("uses session handler when session config provided", async () => {
    const store = new MemorySessionStore();
    const auth = await SoapAuth.create({
      session: { secret: "test-secret", store, getSessionId: () => "sid" },
      http: { local: localConfig },
      logger: mockLogger,
    });
    expect(auth.hasStrategy("local", "http")).toBe(true);
  });
});
