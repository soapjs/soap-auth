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
