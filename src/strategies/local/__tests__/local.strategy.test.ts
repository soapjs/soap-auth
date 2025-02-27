import { LocalStrategy } from "../local.strategy";
import { SessionHandler } from "../../../session/session-handler";
import { JwtStrategy } from "../../jwt/jwt.strategy";
import { LocalStrategyConfig } from "../local.types";
import {
  MissingCredentialsError,
  InvalidCredentialsError,
  UserNotFoundError,
} from "../../../errors";

describe("LocalStrategy", () => {
  let strategy: LocalStrategy<any, any>;
  let mockConfig: any; // jest.Mocked<LocalStrategyConfig<any, any>>;
  let mockSession: jest.Mocked<SessionHandler<any>>;
  let mockJwt: jest.Mocked<JwtStrategy<any, any>>;

  beforeEach(() => {
    mockConfig = {
      credentials: {
        extractCredentials: jest.fn(),
        verifyCredentials: jest.fn(),
      },
      user: {
        fetchUser: jest.fn(),
      },
      routes: {
        login: {},
        logout: {},
      },
    } as unknown as jest.Mocked<LocalStrategyConfig<any, any>>;

    mockSession = {
      issueSession: jest.fn(),
    } as unknown as jest.Mocked<SessionHandler<any>>;

    mockJwt = {
      issueTokens: jest.fn(),
    } as unknown as jest.Mocked<JwtStrategy<any, any>>;

    strategy = new LocalStrategy(mockConfig, mockSession, mockJwt);
  });

  describe("extractCredentials", () => {
    it("should extract credentials from context", async () => {
      const mockContext = { body: { username: "test", password: "pass123" } };
      mockConfig.credentials.extractCredentials.mockResolvedValue({
        identifier: "test",
        password: "pass123",
      });

      const credentials = await (strategy as any).extractCredentials(
        mockContext
      );
      expect(credentials).toEqual({ identifier: "test", password: "pass123" });
      expect(mockConfig.credentials.extractCredentials).toHaveBeenCalledWith(
        mockContext
      );
    });

    it("should throw MissingCredentialsError if no credentials are provided", async () => {
      mockConfig.credentials.extractCredentials.mockRejectedValue(
        new MissingCredentialsError()
      );

      await expect((strategy as any).extractCredentials({})).rejects.toThrow(
        MissingCredentialsError
      );
    });
  });

  describe("verifyCredentials", () => {
    it("should verify credentials successfully", async () => {
      mockConfig.credentials.verifyCredentials.mockResolvedValue(true);

      const result = await (strategy as any).verifyCredentials(
        "test",
        "pass123"
      );
      expect(result).toBe(true);
      expect(mockConfig.credentials.verifyCredentials).toHaveBeenCalledWith(
        "test",
        "pass123"
      );
    });

    it("should return false if credentials are invalid", async () => {
      mockConfig.credentials.verifyCredentials.mockResolvedValue(false);

      const result = await (strategy as any).verifyCredentials(
        "test",
        "wrongpass"
      );
      expect(result).toBe(false);
      expect(mockConfig.credentials.verifyCredentials).toHaveBeenCalledWith(
        "test",
        "wrongpass"
      );
    });
  });

  describe("fetchUser", () => {
    it("should fetch user data", async () => {
      const mockUser = { id: 1, username: "test" };
      mockConfig.user.fetchUser.mockResolvedValue(mockUser);

      const user = await (strategy as any).fetchUser({
        identifier: "test",
        password: "pass123",
      });

      expect(user).toEqual(mockUser);
      expect(mockConfig.user.fetchUser).toHaveBeenCalledWith("test");
    });

    it("should return null if user is not found", async () => {
      mockConfig.user.fetchUser.mockResolvedValue(null);

      const user = await (strategy as any).fetchUser({
        identifier: "unknown",
        password: "pass123",
      });

      expect(user).toBeNull();
      expect(mockConfig.user.fetchUser).toHaveBeenCalledWith("unknown");
    });
  });

  describe("login", () => {
    const mockContext = { body: { username: "test", password: "pass123" } };
    const mockUser = { id: 1, username: "test" };
    const mockTokens = { accessToken: "access", refreshToken: "refresh" };
    const mockSessionData = { sessionId: "session123", data: mockUser };

    beforeEach(() => {
      mockConfig.credentials.extractCredentials.mockResolvedValue({
        identifier: "test",
        password: "pass123",
      });

      mockConfig.credentials.verifyCredentials.mockResolvedValue(true);
      mockConfig.user.fetchUser.mockResolvedValue(mockUser);
      mockJwt.issueTokens.mockResolvedValue(mockTokens);
      mockSession.issueSession.mockResolvedValue(mockSessionData);
    });

    it("should login and return user with tokens and session", async () => {
      const result = await strategy.login(mockContext);

      expect(result.user).toEqual(mockUser);
      expect(result.tokens).toEqual(mockTokens);
      expect(result.session).toEqual(mockSessionData);
      expect(mockJwt.issueTokens).toHaveBeenCalledWith(mockUser, mockContext);
      expect(mockSession.issueSession).toHaveBeenCalledWith(
        mockUser,
        mockContext
      );
    });

    it("should throw InvalidCredentialsError if credentials are incorrect", async () => {
      mockConfig.credentials.verifyCredentials.mockResolvedValue(false);

      await expect(strategy.login(mockContext)).rejects.toThrow(
        InvalidCredentialsError
      );
    });

    it("should throw UserNotFoundError if user is not found", async () => {
      mockConfig.user.fetchUser.mockResolvedValue(null);

      await expect(strategy.login(mockContext)).rejects.toThrow(
        UserNotFoundError
      );
    });
  });
});
