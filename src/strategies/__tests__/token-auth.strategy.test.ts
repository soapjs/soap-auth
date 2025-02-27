import * as Soap from "@soapjs/soap";
import { TokenAuthStrategy } from "../token-auth.strategy";
import { SessionHandler } from "../../session";
import { TokenAuthStrategyConfig } from "../../../src/types";

import {
  MissingTokenError,
  InvalidTokenError,
  UserNotFoundError,
  TokenRotationLimitReachedError,
} from "../../../src/errors";

export interface MockUser {
  id: string;
  name: string;
}

export interface MockContext {
  // You can include whatever fields your app needs.
  accessToken?: string;
  refreshToken?: string;
  // Possibly more fields to simulate an HTTP request, etc.
}

/**
 * A minimal concrete class for testing TokenAuthStrategy.
 * We implement the abstract methods trivially or via mocks in tests.
 */
export class TestTokenAuthStrategy extends TokenAuthStrategy<
  MockContext,
  MockUser
> {
  protected async invalidateAccessToken(
    token: string,
    context?: MockContext
  ): Promise<void> {
    context.accessToken = undefined;
  }
  protected async invalidateRefreshToken(
    token: string,
    context?: MockContext
  ): Promise<void> {
    context.refreshToken = undefined;
  }
  constructor(
    config: TokenAuthStrategyConfig<MockContext, MockUser>,
    session?: SessionHandler,
    logger?: Soap.Logger
  ) {
    super(config, session, logger);
  }

  protected async fetchUser(payload: any): Promise<MockUser | null> {
    // Minimal default: just return a mock user
    return { id: "testUserId", name: "Test User" };
  }

  protected extractAccessToken(context: MockContext): string | undefined {
    return context.accessToken;
  }

  protected extractRefreshToken(context: MockContext): string | undefined {
    return context.refreshToken;
  }

  protected async verifyAccessToken(token: string): Promise<any> {
    // In tests, we’ll mock or spy on this method to return desired results
    return { userId: "testUserId" };
  }

  protected async verifyRefreshToken(token: string): Promise<any> {
    // Same as above – can be mocked or spied on
    return { userId: "testUserId" };
  }

  protected async generateAccessToken(
    user: MockUser,
    context: MockContext
  ): Promise<string> {
    return "newAccessToken";
  }

  protected async generateRefreshToken(
    user: MockUser,
    context: MockContext
  ): Promise<string> {
    return "newRefreshToken";
  }

  protected async storeAccessToken(token: string): Promise<void> {
    // No-op for tests
  }

  protected async storeRefreshToken(token: string): Promise<void> {
    // No-op for tests
  }

  protected embedAccessToken(token: string, context: MockContext): void {
    // Just store it somewhere in context for the test
    context.accessToken = token;
  }

  protected embedRefreshToken(token: string, context: MockContext): void {
    context.refreshToken = token;
  }
}

// We'll mock or spy on the inherited properties from BaseAuthStrategy:
import { RateLimitService } from "../../../src/services/rate-limit.service";
import { RoleService } from "../../../src/services/role.service";
import { AuthThrottleService } from "../../../src/services/auth-throttle.service";
import { AccountLockService } from "../../../src/services/account-lock.service";
import { MfaService } from "../../../src/services/mfa.service";
import { TokenExpiredError } from "jsonwebtoken";

describe("TokenAuthStrategy", () => {
  let config: TokenAuthStrategyConfig<MockContext, MockUser>;
  let strategy: TestTokenAuthStrategy;
  let mockSession: Partial<SessionHandler>;
  let mockLogger: Partial<Soap.Logger>;

  let mockRateLimitService: Partial<RateLimitService>;
  let mockRoleService: Partial<RoleService<MockUser>>;
  let mockThrottleService: Partial<AuthThrottleService>;
  let mockAccountLockService: Partial<AccountLockService<MockContext>>;
  let mockMfaService: Partial<MfaService<MockContext, MockUser>>;

  let context: MockContext;

  beforeEach(() => {
    config = {
      refreshToken: {
        enabled: true,
      },
    } as any;

    mockSession = {
      logoutSession: jest.fn().mockResolvedValue(undefined),
    };

    mockLogger = {
      warn: jest.fn(),
      error: jest.fn(),
      info: jest.fn(),
    };

    mockRateLimitService = {
      checkRateLimit: jest.fn().mockResolvedValue(undefined),
    };
    mockRoleService = {
      isAuthorized: jest.fn().mockResolvedValue(true),
    };
    mockThrottleService = {};
    mockAccountLockService = {};
    mockMfaService = {};

    context = {
      accessToken: undefined,
      refreshToken: undefined,
    };

    strategy = new TestTokenAuthStrategy(
      config,
      mockSession as SessionHandler,
      mockLogger as Soap.Logger
    );

    (strategy as any).rateLimit = mockRateLimitService;
    (strategy as any).role = mockRoleService;
    (strategy as any).throttle = mockThrottleService;
    (strategy as any).accountLock = mockAccountLockService;
    (strategy as any).mfa = mockMfaService;
  });

  describe("authenticate", () => {
    it("should throw MissingTokenError if no access token and refreshToken is disabled in config", async () => {
      config.refreshToken = undefined;

      await expect(strategy.authenticate(context)).rejects.toThrowError(
        MissingTokenError
      );
      expect(mockRateLimitService.checkRateLimit).toHaveBeenCalledWith(context);
    });

    it("should verify access token if present and return user + tokens if valid", async () => {
      context.accessToken = "validAccessToken";

      const result = await strategy.authenticate(context);
      expect(result.user).toEqual({ id: "testUserId", name: "Test User" });
      expect(result.tokens).toEqual({ accessToken: "validAccessToken" });
      expect(mockRoleService.isAuthorized).toHaveBeenCalledWith({
        id: "testUserId",
        name: "Test User",
      });
      expect(mockLogger.warn).not.toHaveBeenCalled();
    });

    it("should fallback to refresh token if access token is invalid or expired", async () => {
      context.accessToken = "invalidAccessToken";
      context.refreshToken = "validRefreshToken";

      jest
        .spyOn(strategy as any, "verifyAccessToken")
        .mockRejectedValue(new TokenExpiredError("expired", new Date()));

      const refreshSpy = jest
        .spyOn(strategy, "refreshTokens")
        .mockResolvedValue({
          user: { id: "testUserId", name: "Refreshed User" },
          tokens: {
            accessToken: "refreshedAccess",
            refreshToken: "refreshedRefresh",
          },
        });

      const result = await strategy.authenticate(context);

      expect(mockLogger.warn).toHaveBeenCalledWith(
        "Access token expired, attempting refresh..."
      );
      expect(refreshSpy).toHaveBeenCalledWith(context);
      expect(result).toEqual({
        user: { id: "testUserId", name: "Refreshed User" },
        tokens: {
          accessToken: "refreshedAccess",
          refreshToken: "refreshedRefresh",
        },
      });
    });

    it("should throw MissingTokenError if no access token and no refresh token provided", async () => {
      context.accessToken = undefined;
      context.refreshToken = undefined;

      await expect(strategy.authenticate(context)).rejects.toThrow(
        MissingTokenError
      );
    });
  });

  describe("refreshTokens", () => {
    it("should throw an error if refresh tokens are not enabled in config", async () => {
      config.refreshToken = undefined;

      await expect(strategy.refreshTokens(context)).rejects.toThrowError(
        "Refresh tokens are not enabled."
      );
    });

    it("should throw MissingTokenError if no refresh token is provided", async () => {
      config.refreshToken = {};

      await expect(strategy.refreshTokens(context)).rejects.toThrow(
        MissingTokenError
      );
    });

    it("should throw InvalidTokenError if refresh token is invalid", async () => {
      context.refreshToken = "invalidRefreshToken";
      jest
        .spyOn(strategy as any, "verifyRefreshToken")
        .mockRejectedValue(new InvalidTokenError("Refresh"));

      await expect(strategy.refreshTokens(context)).rejects.toThrow(
        InvalidTokenError
      );
    });

    it("should throw UserNotFoundError if user retrieval returns null", async () => {
      context.refreshToken = "validRefresh";
      jest.spyOn(strategy as any, "fetchUser").mockResolvedValueOnce(null);

      await expect(strategy.refreshTokens(context)).rejects.toThrow(
        UserNotFoundError
      );
    });

    it("should return new access token (and refresh token) on success", async () => {
      context.refreshToken = "validRefresh";

      jest
        .spyOn(strategy as any, "verifyRefreshToken")
        .mockResolvedValueOnce({ userId: "testUserId" });
      jest
        .spyOn(strategy as any, "generateAccessToken")
        .mockResolvedValueOnce("newAccessToken");
      jest
        .spyOn(strategy as any, "generateRefreshToken")
        .mockResolvedValueOnce("newRefreshToken");
      const storeAccessSpy = jest.spyOn(strategy as any, "storeAccessToken");
      const storeRefreshSpy = jest.spyOn(strategy as any, "storeRefreshToken");

      const result = await strategy.refreshTokens(context);

      expect(storeAccessSpy).toHaveBeenCalledWith("newAccessToken");
      expect(storeRefreshSpy).toHaveBeenCalledWith("newRefreshToken");
      expect(result).toEqual({
        user: { id: "testUserId", name: "Test User" },
        tokens: {
          accessToken: "newAccessToken",
          refreshToken: "newRefreshToken",
        },
      });
    });

    describe("absoluteExpiry", () => {
      it("should log a warning and throw InvalidTokenError if absolute expiry is exceeded (onExpiry=error)", async () => {
        config.refreshToken = {
          absoluteExpiry: {
            payloadField: "absoluteExp",
            onExpiry: "error",
          },
        };
        context.refreshToken = "validRefresh";

        jest
          .spyOn(strategy as any, "verifyRefreshToken")
          .mockResolvedValueOnce({
            userId: "testUserId",
            absoluteExp: Math.floor(Date.now() / 1000) - 1000,
          });

        await expect(strategy.refreshTokens(context)).rejects.toThrow(
          InvalidTokenError
        );
        expect(mockLogger.warn).toHaveBeenCalledWith(
          "Absolute expiry exceeded for refresh token."
        );
      });

      it("should call logoutSession and throw if onExpiry=logout", async () => {
        config.refreshToken = {
          absoluteExpiry: {
            payloadField: "absoluteExp",
            onExpiry: "logout",
          },
        };
        context.refreshToken = "validRefresh";

        jest
          .spyOn(strategy as any, "verifyRefreshToken")
          .mockResolvedValueOnce({
            userId: "testUserId",
            absoluteExp: Math.floor(Date.now() / 1000) - 1000,
          });

        await expect(strategy.refreshTokens(context)).rejects.toThrow(
          InvalidTokenError
        );
        expect(mockSession.logoutSession).toHaveBeenCalledWith(context);
      });
    });

    describe("rotation", () => {
      beforeEach(() => {
        config.refreshToken = {
          enabled: true,
          rotation: {
            maxRotations: 3,
            getRotationCount: jest.fn().mockResolvedValue(1),
            isLimitReached: jest
              .fn()
              .mockImplementation((count: number, max: number) => count >= max),
            rotateToken: jest.fn().mockResolvedValue({
              newToken: "rotatedRefreshToken",
            }),
            afterRotation: jest.fn(),
          },
        } as any;
        context.refreshToken = "someOldRefreshToken";
      });

      it("should throw TokenRotationLimitReachedError if limit is reached", async () => {
        (
          config.refreshToken.rotation.getRotationCount as jest.Mock
        ).mockResolvedValueOnce(3);

        await expect(strategy.refreshTokens(context)).rejects.toThrow(
          TokenRotationLimitReachedError
        );
      });

      it("should rotate the refresh token and call afterRotation if limit not reached", async () => {
        (
          config.refreshToken.rotation.getRotationCount as jest.Mock
        ).mockResolvedValueOnce(2);

        jest
          .spyOn(strategy as any, "verifyRefreshToken")
          .mockResolvedValueOnce({ userId: "testUserId" });
        jest
          .spyOn(strategy as any, "generateAccessToken")
          .mockResolvedValueOnce("newAccessToken");

        const afterRotationSpy = config.refreshToken.rotation
          .afterRotation as jest.Mock;

        const result = await strategy.refreshTokens(context);

        expect(config.refreshToken.rotation.rotateToken).toHaveBeenCalledWith(
          "someOldRefreshToken",
          { id: "testUserId", name: "Test User" },
          context
        );
        expect(afterRotationSpy).toHaveBeenCalledWith(
          "someOldRefreshToken",
          "rotatedRefreshToken",
          { id: "testUserId", name: "Test User" },
          context,
          3
        );

        expect(result).toEqual({
          user: { id: "testUserId", name: "Test User" },
          tokens: {
            accessToken: "newAccessToken",
            refreshToken: "rotatedRefreshToken",
          },
        });
      });

      it("should warn if rotation is enabled but rotateToken is not provided", async () => {
        config.refreshToken.rotation.rotateToken = undefined;

        jest
          .spyOn(strategy as any, "verifyRefreshToken")
          .mockResolvedValueOnce({ userId: "testUserId" });
        jest
          .spyOn(strategy as any, "generateAccessToken")
          .mockResolvedValueOnce("newAccessToken");

        const result = await strategy.refreshTokens(context);
        expect(mockLogger.warn).toHaveBeenCalledWith(
          "Rotation enabled but rotateToken not provided."
        );
        expect(result).toEqual({
          user: { id: "testUserId", name: "Test User" },
          tokens: { accessToken: "newAccessToken" },
        });
      });
    });
  });

  describe("error handling", () => {
    it("should call onFailure", async () => {
      const onFailureSpy = jest.spyOn(strategy as any, "onFailure");
      jest
        .spyOn(strategy as any, "verifyAccessToken")
        .mockRejectedValue(new Error());

      context.accessToken = "someToken";
      await expect(strategy.authenticate(context)).rejects.toThrow(
        InvalidTokenError
      );
      expect(onFailureSpy).toHaveBeenCalledWith("authenticate", {
        error: expect.any(Error),
      });
    });
  });
});
