import { BasicStrategy } from "../basic.strategy";
import {
  InvalidCredentialsError,
  MissingCredentialsError,
} from "../../../errors";
import { BasicStrategyConfig } from "../basic.types";
import { SessionHandler } from "../../../session/session-handler";
import { JwtStrategy } from "../../jwt/jwt.strategy";

describe("BasicStrategy", () => {
  let strategy: BasicStrategy<any, any>;
  let mockConfig: any; // jest.Mocked<BasicStrategyConfig<any, any>>;
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
    } as unknown as jest.Mocked<BasicStrategyConfig<any, any>>;

    mockSession = {
      issueSession: jest.fn(),
    } as unknown as jest.Mocked<SessionHandler<any>>;

    mockJwt = {
      issueTokens: jest.fn(),
    } as unknown as jest.Mocked<JwtStrategy<any, any>>;

    strategy = new BasicStrategy(mockConfig, mockSession, mockJwt);
  });

  describe("extractCredentials", () => {
    it("should extract credentials from Authorization header", () => {
      mockConfig.credentials.extractCredentials = null;
      const username = "testuser";
      const password = "securepassword";
      const encoded = Buffer.from(`${username}:${password}`).toString("base64");
      const context = { headers: { authorization: `Basic ${encoded}` } };

      const credentials = (strategy as any).extractCredentials(context);

      expect(credentials).toEqual({ identifier: username, password });
    });

    it("should throw MissingCredentialsError if Authorization header is missing", () => {
      const context = { headers: {} };

      expect(() => (strategy as any).extractCredentials(context)).toThrow(
        MissingCredentialsError
      );
    });

    it("should throw InvalidCredentialsError if Authorization header is malformed", () => {
      const context = { headers: { authorization: "Bearer token" } };
      mockConfig.credentials.extractCredentials = null;
      expect(() => (strategy as any).extractCredentials(context)).toThrow(
        InvalidCredentialsError
      );
    });

    it("should throw InvalidCredentialsError if Authorization header is not base64-encoded properly", () => {
      const context = { headers: { authorization: "Basic not_base64_data" } };
      mockConfig.credentials.extractCredentials = null;
      expect(() => (strategy as any).extractCredentials(context)).toThrow(
        InvalidCredentialsError
      );
    });

    it("should throw InvalidCredentialsError if decoded credentials are invalid", () => {
      const encoded = Buffer.from(`username`).toString("base64");
      const context = { headers: { authorization: `Basic ${encoded}` } };
      mockConfig.credentials.extractCredentials = null;
      expect(() => (strategy as any).extractCredentials(context)).toThrow(
        InvalidCredentialsError
      );
    });
  });

  describe("verifyCredentials", () => {
    it("should verify valid credentials", async () => {
      mockConfig.credentials.verifyCredentials.mockResolvedValue(true);

      const result = await (strategy as any).verifyCredentials(
        "testuser",
        "password"
      );

      expect(result).toBe(true);
      expect(mockConfig.credentials.verifyCredentials).toHaveBeenCalledWith(
        "testuser",
        "password"
      );
    });

    it("should return false if credentials are invalid", async () => {
      mockConfig.credentials.verifyCredentials.mockResolvedValue(false);

      const result = await (strategy as any).verifyCredentials(
        "testuser",
        "wrongpass"
      );

      expect(result).toBe(false);
      expect(mockConfig.credentials.verifyCredentials).toHaveBeenCalledWith(
        "testuser",
        "wrongpass"
      );
    });
  });

  describe("fetchUser", () => {
    it("should retrieve user data when credentials are valid", async () => {
      const mockUser = { id: 1, username: "testuser" };
      mockConfig.user.fetchUser.mockResolvedValue(mockUser);

      const user = await (strategy as any).fetchUser({
        identifier: "testuser",
        password: "securepassword",
      });

      expect(user).toEqual(mockUser);
      expect(mockConfig.user.fetchUser).toHaveBeenCalledWith({
        identifier: "testuser",
        password: "securepassword",
      });
    });

    it("should return null if user is not found", async () => {
      mockConfig.user.fetchUser.mockResolvedValue(null);

      const user = await (strategy as any).fetchUser({
        identifier: "unknownuser",
        password: "securepassword",
      });

      expect(user).toBeNull();
      expect(mockConfig.user.fetchUser).toHaveBeenCalledWith({
        identifier: "unknownuser",
        password: "securepassword",
      });
    });
  });
});
