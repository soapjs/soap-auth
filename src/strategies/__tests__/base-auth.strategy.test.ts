import { AuthResult, BaseAuthStrategyConfig } from "../../../src/types";
import { SessionHandler } from "../../../src/session/session-handler";
import {
  MissingSessionIdError,
  InvalidSessionError,
} from "../../../src/session/session.errors";
import * as Soap from "@soapjs/soap";

import { AccountLockService } from "../../../src/services/account-lock.service";
import { MfaService } from "../../../src/services/mfa.service";
import { RateLimitService } from "../../../src/services/rate-limit.service";
import { RoleService } from "../../../src/services/role.service";
import { AuthThrottleService } from "../../../src/services/auth-throttle.service";
import { BaseAuthStrategy } from "../base-auth.strategy";

/**
 * Minimal TUser and TContext for testing
 */
export interface MockUser {
  id: string;
  name: string;
}

export interface MockContext {}

/**
 * A concrete subclass of BaseAuthStrategy for testing purposes.
 * We only implement the abstract authenticate method trivially.
 */
export class TestBaseAuthStrategy extends BaseAuthStrategy<
  MockContext,
  MockUser
> {
  constructor(
    config: BaseAuthStrategyConfig<MockContext, MockUser>,
    session?: SessionHandler,
    logger?: Soap.Logger
  ) {
    super(config, session, logger);
  }

  async authenticate(context?: MockContext): Promise<AuthResult<MockUser>> {
    return { user: null };
  }
}

describe("BaseAuthStrategy", () => {
  let config: BaseAuthStrategyConfig<MockContext, MockUser>;
  let mockSessionHandler: Partial<SessionHandler>;
  let mockLogger: Partial<Soap.Logger>;

  let mockAccountLock: Partial<AccountLockService<MockContext>>;
  let mockMfa: Partial<MfaService<MockContext, MockUser>>;
  let mockRateLimit: Partial<RateLimitService>;
  let mockRole: Partial<RoleService<MockUser>>;
  let mockThrottle: Partial<AuthThrottleService>;

  let strategy: TestBaseAuthStrategy;
  let context: MockContext;

  beforeEach(() => {
    config = {
      onSuccess: jest.fn(),
      onFailure: jest.fn(),
    };

    mockSessionHandler = {
      getSessionId: jest.fn().mockReturnValue("session-id"),
      getSessionData: jest
        .fn()
        .mockResolvedValue({ user: { id: "123", name: "TestUser" } }),
    };

    mockLogger = {
      error: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
    };

    mockAccountLock = {};
    mockMfa = {};
    mockRateLimit = {
      checkRateLimit: jest.fn().mockResolvedValue(undefined),
    };
    mockRole = {
      isAuthorized: jest.fn().mockResolvedValue(true),
    };
    mockThrottle = {};

    strategy = new TestBaseAuthStrategy(
      config,
      mockSessionHandler as SessionHandler,
      mockLogger as Soap.Logger
    );

    (strategy as any).accountLock = mockAccountLock;
    (strategy as any).mfa = mockMfa;
    (strategy as any).rateLimit = mockRateLimit;
    (strategy as any).role = mockRole;
    (strategy as any).throttle = mockThrottle;

    context = {};
  });

  describe("constructor & init", () => {
    it("should instantiate services and allow optional init override", async () => {
      expect(strategy).toBeDefined();

      await expect(strategy.init()).resolves.toBeUndefined();
    });
  });

  describe("onSuccess", () => {
    it("should call config.onSuccess if defined and log errors if it fails", async () => {
      const spy = jest.spyOn(config, "onSuccess");
      await (strategy as any).onSuccess("someAction", {
        user: { id: "1", name: "Bob" },
        context,
      });
      expect(spy).toHaveBeenCalledWith("someAction", {
        user: { id: "1", name: "Bob" },
        context,
      });
    });

    it("should log error if config.onSuccess throws", async () => {
      const error = new Error("onSuccess error");
      config.onSuccess = jest.fn().mockRejectedValue(error);

      await (strategy as any).onSuccess("someAction", {
        user: { id: "1", name: "Bob" },
        context,
      });
      expect(mockLogger.error).toHaveBeenCalledWith(error);
    });
  });

  describe("onFailure", () => {
    it("should call config.onFailure if defined and log with logger.error", async () => {
      const spy = jest.spyOn(config, "onFailure");
      await (strategy as any).onFailure("someAction", {
        context,
        error: new Error("Failure reason"),
      });
      expect(mockLogger.error).toHaveBeenCalledWith(
        "someAction failed:",
        expect.any(Error)
      );
      expect(spy).toHaveBeenCalledWith("someAction", {
        context,
        error: expect.any(Error),
      });
    });

    it("should log error if config.onFailure throws", async () => {
      config.onFailure = jest
        .fn()
        .mockRejectedValue(new Error("onFailure error"));
      await (strategy as any).onFailure("someAction", {
        context,
        error: new Error("boom"),
      });

      expect(mockLogger.error).toHaveBeenCalledWith(
        "someAction failed:",
        expect.any(Error)
      );

      expect(mockLogger.error).toHaveBeenCalledWith(expect.any(Error));
    });
  });

  describe("authenticateWithSession", () => {
    it("should throw MissingSessionIdError if getSessionId returns undefined", async () => {
      (mockSessionHandler.getSessionId as jest.Mock).mockReturnValueOnce(
        undefined
      );

      await expect(
        (strategy as any).authenticateWithSession(context)
      ).rejects.toThrow(MissingSessionIdError);
    });

    it("should throw InvalidSessionError if getSessionData returns null/undefined", async () => {
      (mockSessionHandler.getSessionData as jest.Mock).mockResolvedValueOnce(
        null
      );

      await expect(
        (strategy as any).authenticateWithSession(context)
      ).rejects.toThrow(InvalidSessionError);
    });

    it("should call rateLimit.checkRateLimit, role.isAuthorized, and return user from session", async () => {
      const result = await (strategy as any).authenticateWithSession(context);

      expect(mockRateLimit.checkRateLimit).toHaveBeenCalledWith(context);
      expect(mockRole.isAuthorized).toHaveBeenCalledWith({
        id: "123",
        name: "TestUser",
      });
      expect(result).toEqual({ user: { id: "123", name: "TestUser" } });
    });
  });

  describe("authenticate", () => {
    it("should be implemented by the concrete class", async () => {
      const res = await strategy.authenticate(context);
      expect(res).toEqual({ user: null });
    });
  });
});
