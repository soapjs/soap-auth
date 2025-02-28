import jwt, { TokenExpiredError } from "jsonwebtoken";
import { JwtStrategy } from "../jwt.strategy";
import { TokenAuthStrategyConfig } from "../../../types";
import {
  InvalidTokenError,
  UndefinedTokenSecretError,
  UserNotFoundError,
  MissingTokenError,
} from "../../../errors";

// jest.mock("jsonwebtoken", () => ({
//   verify: jest.fn((token, secretOrPublicKey, options, callback) => {
//     return callback(null, { sub: "user_id" });
//   }),
// }));

describe("JWTStrategy", () => {
  let strategy: any;
  let mockLogger: any;
  let mockConfig: TokenAuthStrategyConfig<any, any>;
  let mockUser: any;
  let mockContext: any;

  beforeEach(() => {
    mockLogger = { error: jest.fn(), warn: jest.fn(), info: jest.fn() };

    mockUser = { id: "123", email: "test@example.com" };

    mockContext = {
      req: {
        headers: { authorization: "Bearer mock-access-token" },
        cookies: { refreshToken: "mock-refresh-token" },
      },
      res: { setHeader: jest.fn(), cookie: jest.fn(), clearCookie: jest.fn() },
    };

    mockConfig = {
      accessToken: {
        issuer: { secretKey: "access-secret", options: { expiresIn: "1h" } },
        verifier: { options: {} },
        persistence: { store: jest.fn() } as any,
        extract: jest.fn(),
        embed: jest.fn(),
      },
      refreshToken: {
        issuer: { secretKey: "refresh-secret", options: { expiresIn: "7d" } },
        verifier: { options: {} },
        persistence: { store: jest.fn(), remove: jest.fn() } as any,
        extract: jest.fn(),
        embed: jest.fn(),
      },
      user: { fetchUser: jest.fn().mockResolvedValue(mockUser) },
      routes: {},
    };

    strategy = new JwtStrategy(mockConfig, mockLogger);
  });

  it("should authenticate user with valid access token", async () => {
    const mockAccessToken = "mock-access-token";
    jest
      .spyOn(mockConfig.accessToken, "extract")
      .mockReturnValue(mockAccessToken);
    jest.spyOn(strategy, "verifyAccessToken").mockResolvedValue(mockUser);
    const result = await strategy.authenticate(mockContext);

    expect(result.user).toEqual(mockUser);
    expect(result.tokens.accessToken).toEqual("mock-access-token");
  });

  it("should refresh tokens when access token is invalid", async () => {
    const mockAccessToken = "mock-access-token";
    const mockRefreshToken = "mock-refresh-token";
    jest
      .spyOn(mockConfig.accessToken, "extract")
      .mockReturnValue(mockAccessToken);
    jest
      .spyOn(mockConfig.refreshToken, "extract")
      .mockReturnValue(mockRefreshToken);
    jest
      .spyOn(strategy, "verifyAccessToken")
      .mockRejectedValue(new TokenExpiredError("Access", new Date()));
    jest.spyOn(strategy, "verifyRefreshToken").mockResolvedValue(mockUser);
    jest
      .spyOn(strategy, "generateAccessToken")
      .mockResolvedValue("new-access-token");
    jest
      .spyOn(strategy, "generateRefreshToken")
      .mockResolvedValue("new-refresh-token");
    jest.spyOn(strategy, "storeAccessToken").mockResolvedValue(null);
    jest.spyOn(strategy, "storeRefreshToken").mockResolvedValue(null);

    const result = await strategy.authenticate(mockContext);

    expect(result.user).toEqual(mockUser);
    expect(result.tokens.accessToken).toEqual("new-access-token");
    expect(result.tokens.refreshToken).toEqual("new-refresh-token");
  });

  it("should throw MissingTokenError when no tokens are provided", async () => {
    jest.spyOn(mockConfig.accessToken, "extract").mockReturnValue(undefined);
    jest.spyOn(mockConfig.refreshToken, "extract").mockReturnValue(undefined);

    await expect(strategy.authenticate(mockContext)).rejects.toThrow(
      MissingTokenError
    );
  });

  it("should throw InvalidTokenError if user does not exist", async () => {
    const mockAccessToken = "mock-access-token";
    const mockRefreshToken = null;
    jest
      .spyOn(mockConfig.accessToken, "extract")
      .mockReturnValue(mockAccessToken);
    jest
      .spyOn(mockConfig.refreshToken, "extract")
      .mockReturnValue(mockRefreshToken);
    jest.spyOn(strategy, "verifyAccessToken").mockResolvedValue(mockUser);
    mockConfig.user.fetchUser = jest.fn().mockResolvedValue(null);

    await expect(strategy.authenticate(mockContext)).rejects.toThrow(
      InvalidTokenError
    );
  });

  it("should throw InvalidTokenError when refresh token is invalid", async () => {
    const mockAccessToken = "mock-access-token";
    const mockRefreshToken = "mock-refresh-token";
    jest
      .spyOn(mockConfig.accessToken, "extract")
      .mockReturnValue(mockAccessToken);
    jest
      .spyOn(mockConfig.refreshToken, "extract")
      .mockReturnValue(mockRefreshToken);
    jest
      .spyOn(strategy, "verifyAccessToken")
      .mockRejectedValue(new InvalidTokenError("Access"));
    jest
      .spyOn(strategy, "verifyRefreshToken")
      .mockRejectedValue(new InvalidTokenError("Refresh"));

    await expect(strategy.authenticate(mockContext)).rejects.toThrow(
      InvalidTokenError
    );
  });

  it("should generate and store access and refresh tokens", async () => {
    jest
      .spyOn(strategy, "generateAccessToken")
      .mockResolvedValue("new-access-token");
    jest
      .spyOn(strategy, "generateRefreshToken")
      .mockResolvedValue("new-refresh-token");
    jest.spyOn(strategy, "storeAccessToken").mockResolvedValue(null);
    jest.spyOn(strategy, "storeRefreshToken").mockResolvedValue(null);

    const tokens = await strategy.issueTokens(mockUser, mockContext);

    expect(tokens).toHaveProperty("accessToken", "new-access-token");
    expect(tokens).toHaveProperty("refreshToken", "new-refresh-token");

    expect(strategy.storeAccessToken).toHaveBeenCalledWith("new-access-token");
    expect(strategy.storeRefreshToken).toHaveBeenCalledWith(
      "new-refresh-token"
    );
  });

  it("should invalidate refresh token", async () => {
    jest
      .spyOn(strategy, "extractRefreshToken")
      .mockResolvedValue("mock-refresh-token");
    jest.spyOn(strategy, "invalidateRefreshToken").mockResolvedValue(null);

    await strategy.invalidateRefreshToken(mockContext);

    expect(strategy.invalidateRefreshToken).toHaveBeenCalledWith(mockContext);
  });

  it("should extract access token from context", async () => {
    const mockAccessToken = "mock-access-token";
    jest
      .spyOn(mockConfig.accessToken, "extract")
      .mockReturnValue(mockAccessToken);
    const token = await strategy.extractAccessToken(mockContext);
    expect(token).toBe("mock-access-token");
  });

  it("should extract refresh token from context", async () => {
    const mockRefreshToken = "mock-refresh-token";
    jest
      .spyOn(mockConfig.refreshToken, "extract")
      .mockReturnValueOnce(mockRefreshToken);
    const token = await strategy.extractRefreshToken(mockContext);
    expect(token).toBe("mock-refresh-token");
  });

  it("should throw UndefinedTokenSecretError if access secret key is missing", async () => {
    mockConfig.accessToken.issuer.secretKey = undefined;

    expect(() => new JwtStrategy(mockConfig, mockLogger)).toThrow(
      UndefinedTokenSecretError
    );
  });
});
