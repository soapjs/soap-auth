import { CredentialAuthStrategyConfig } from "../../../src/types";
import { SessionHandler } from "../../../src/session/session-handler";
import { JwtStrategy } from "../../../src/strategies/jwt/jwt.strategy";
import * as Soap from "@soapjs/soap";
import {
  ExpiredPasswordError,
  ExpiredResetTokenError,
  InvalidCredentialsError,
  MissingCredentialsError,
  UserNotFoundError,
} from "../../../src/errors";
import { CredentialAuthStrategy } from "../credential-auth.strategy";

jest.mock("../../session/session-handler");
jest.mock("../jwt/jwt.strategy");

export class TestCredentialAuthStrategy extends CredentialAuthStrategy<
  any,
  any
> {
  constructor(
    config: CredentialAuthStrategyConfig<any, any>,
    session?: SessionHandler,
    jwt?: JwtStrategy<any, any>,
    logger?: Soap.Logger
  ) {
    super(config, session, jwt, logger);
  }

  protected async verifyCredentials(
    identifier: string,
    password: string
  ): Promise<boolean> {
    return true;
  }

  protected async extractCredentials(
    context: any
  ): Promise<{ identifier: string; password: string }> {
    return { identifier: "testUser", password: "testPass" };
  }

  protected async fetchUser(credentials: any): Promise<any | null> {
    return { id: "1", name: "Test User" };
  }
}

describe("CredentialAuthStrategy", () => {
  let strategy: CredentialAuthStrategy<any, any>;
  let config: any;
  let mockSession: jest.Mocked<SessionHandler<any, any, any>>;
  let mockJwt: jest.Mocked<JwtStrategy<any, any>>;
  let mockLogger: any;
  const mockUser = { id: "user123", username: "testuser" };
  const context = { headers: {}, body: {} };

  beforeEach(() => {
    mockLogger = {
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    };

    mockSession = {
      logoutSession: jest.fn().mockResolvedValue(undefined),
      issueSession: jest.fn().mockResolvedValue("session-id"),
      getSessionId: jest.fn().mockReturnValue("session-id"),
      getSessionData: jest
        .fn()
        .mockResolvedValue({ user: { id: "1", name: "Test" } }),
    } as any;

    mockJwt = {
      authenticate: jest.fn(),
      issueTokens: jest.fn().mockResolvedValue({
        accessToken: "fakeAccess",
        refreshToken: "fakeRefresh",
      }),
    } as any;

    config = {
      failedAttempts: {
        incrementFailedAttempts: jest.fn(),
        resetFailedAttempts: jest.fn(),
        getFailedAttempts: jest.fn(),
      },
      role: {
        authorizeByRoles: jest.fn().mockResolvedValue(true),
        roles: ["user"],
      },
      rateLimit: {
        checkRateLimit: jest.fn().mockResolvedValue(false),
      },
      mfa: {
        isMfaRequired: jest.fn().mockReturnValue(false),
      },
      passwordPolicy: {
        updatePassword: jest.fn(),
        generateResetToken: jest.fn(),
        validateResetToken: jest.fn(),
        sendResetEmail: jest.fn(),
      },
      security: {
        maxFailedLoginAttempts: 3,
        lockoutDuration: 10,
        notifyOnLockout: jest.fn(),
      },
      lock: {
        isAccountLocked: jest.fn(),
      },
      user: {
        fetchUser: jest.fn(),
      },
    } as any;

    strategy = new TestCredentialAuthStrategy(
      config,
      mockSession as SessionHandler,
      mockJwt as JwtStrategy,
      mockLogger as Soap.Logger
    );
  });

  describe("authenticate", () => {
    it("should use JWT if available and return its result", async () => {
      (mockJwt.authenticate as jest.Mock).mockResolvedValue({
        user: { id: "1", name: "JWT User" },
      });

      const result = await strategy.authenticate(context);

      expect(mockJwt.authenticate).toHaveBeenCalledWith(context);
      expect(result).toEqual({
        user: { id: "1", name: "JWT User" },
      });
    });

    it("should fall back to authenticateWithSession if JWT throws an error", async () => {
      (mockJwt.authenticate as jest.Mock).mockRejectedValue(
        new Error("JWT error")
      );

      const result = await strategy.authenticate(context);

      expect(mockLogger.warn).toHaveBeenCalledWith(
        "JWT authentication failed, falling back to session."
      );

      expect(result.user).toEqual({ id: "1", name: "Test" });
    });

    it("should use session if JWT is not defined but session is available", async () => {
      strategy = new TestCredentialAuthStrategy(
        config,
        mockSession as SessionHandler,
        undefined,
        mockLogger as Soap.Logger
      );

      const result = await strategy.authenticate(context);
      expect(result.user).toEqual({ id: "1", name: "Test" });
    });

    it("should return user=null if no JWT/session and allowGuest = true", async () => {
      config.allowGuest = true;
      strategy = new TestCredentialAuthStrategy(
        config,
        undefined,
        undefined,
        mockLogger as Soap.Logger
      );

      const result = await strategy.authenticate(context);
      expect(mockLogger.warn).toHaveBeenCalledWith(
        "No authentication method found. Proceeding as guest."
      );
      expect(result.user).toBeNull();
    });

    it("should throw UserNotFoundError if no JWT/session and allowGuest = false", async () => {
      config.allowGuest = false;
      strategy = new TestCredentialAuthStrategy(
        config,
        undefined,
        undefined,
        mockLogger as Soap.Logger
      );

      await expect(strategy.authenticate(context)).rejects.toThrow(
        UserNotFoundError
      );
    });
  });

  describe("login", () => {
    it("should throw MissingCredentialsError if credentials are missing", async () => {
      jest
        .spyOn(strategy as any, "extractCredentials")
        .mockResolvedValueOnce(undefined);

      await expect(strategy.login(context)).rejects.toThrow(
        MissingCredentialsError
      );
    });

    it("should throw InvalidCredentialsError if verifyCredentials returns false", async () => {
      jest
        .spyOn(strategy as any, "verifyCredentials")
        .mockResolvedValueOnce(false);

      await expect(strategy.login(context)).rejects.toThrow(
        InvalidCredentialsError
      );
    });

    it("should throw ExpiredPasswordError if the password is expired", async () => {
      jest
        .spyOn((strategy as any).password, "isPasswordChangeRequired")
        .mockResolvedValueOnce(true);

      await expect(strategy.login(context)).rejects.toThrow(
        ExpiredPasswordError
      );
    });

    it("should return user, tokens, and session on success", async () => {
      const result = await strategy.login(context);

      expect(result.user).toBeDefined();
      expect(result.tokens).toBeDefined();
      expect(result.session).toBeDefined();
    });
  });

  describe("logout", () => {
    it("should call session.logoutSession and onSuccess", async () => {
      const onSuccessSpy = jest.spyOn(strategy as any, "onSuccess");
      await strategy.logout(context);

      expect(mockSession.logoutSession).toHaveBeenCalledWith(context);
      expect(onSuccessSpy).toHaveBeenCalledWith("logout", context);
    });

    it("should call onFailure and rethrow the error if session.logoutSession fails", async () => {
      const onFailureSpy = jest.spyOn(strategy as any, "onFailure");
      (mockSession.logoutSession as jest.Mock).mockRejectedValueOnce(
        new Error("Session error")
      );

      await expect(strategy.logout(context)).rejects.toThrow("Session error");
      expect(onFailureSpy).toHaveBeenCalledWith("logout", {
        error: expect.any(Error),
      });
    });
  });

  describe("requestPasswordReset", () => {
    it("should throw NotImplementedError if generateResetToken is not configured", async () => {
      config.passwordPolicy.generateResetToken = undefined;
      await expect(strategy.requestPasswordReset("testUser")).rejects.toThrow(
        Soap.NotImplementedError
      );
    });

    it("should call generateResetToken and sendResetEmail (if email is provided)", async () => {
      config.passwordPolicy.generateResetToken = jest
        .fn()
        .mockResolvedValue("mockToken");
      config.passwordPolicy.sendResetEmail = jest
        .fn()
        .mockResolvedValue(undefined);

      await strategy.requestPasswordReset("testUser", "test@example.com");

      expect(config.passwordPolicy.generateResetToken).toHaveBeenCalledWith(
        "testUser"
      );
      expect(config.passwordPolicy.sendResetEmail).toHaveBeenCalledWith(
        "test@example.com",
        "mockToken"
      );
    });

    it("should call onSuccess with the correct data", async () => {
      config.passwordPolicy.generateResetToken = jest
        .fn()
        .mockResolvedValue("mockToken");
      const onSuccessSpy = jest.spyOn(strategy as any, "onSuccess");

      await strategy.requestPasswordReset("testUser");

      expect(onSuccessSpy).toHaveBeenCalledWith("request_password_reset", {
        identifier: "testUser",
        tokens: { reset: "mockToken" },
      });
    });
  });

  describe("resetPassword", () => {
    it("should throw NotImplementedError if validateResetToken or updatePassword are not configured", async () => {
      config.passwordPolicy.updatePassword = undefined;
      await expect(
        strategy.resetPassword("testUser", "token", "newPass")
      ).rejects.toThrow(Soap.NotImplementedError);
    });

    it("should throw ExpiredResetTokenError if validateResetToken returns false", async () => {
      config.passwordPolicy.validateResetToken = jest
        .fn()
        .mockResolvedValue(false);
      config.passwordPolicy.updatePassword = jest.fn();

      await expect(
        strategy.resetPassword("testUser", "token", "newPass")
      ).rejects.toThrow(ExpiredResetTokenError);
    });

    it("should call updatePassword if the token is valid", async () => {
      config.passwordPolicy.validateResetToken = jest
        .fn()
        .mockResolvedValue(true);
      config.passwordPolicy.updatePassword = jest
        .fn()
        .mockResolvedValue(undefined);

      await strategy.resetPassword("testUser", "validToken", "newPass");
      expect(config.passwordPolicy.updatePassword).toHaveBeenCalledWith(
        "testUser",
        "newPass"
      );
    });
  });

  describe("changePassword", () => {
    it("should throw NotImplementedError if updatePassword is not configured", async () => {
      config.passwordPolicy.updatePassword = undefined;
      await expect(
        strategy.changePassword("testUser", "oldPass", "newPass")
      ).rejects.toThrow(Soap.NotImplementedError);
    });

    it("should throw InvalidCredentialsError if verifyCredentials returns false", async () => {
      config.passwordPolicy.updatePassword = jest
        .fn()
        .mockResolvedValue(undefined);
      jest
        .spyOn(strategy as any, "verifyCredentials")
        .mockResolvedValueOnce(false);

      await expect(
        strategy.changePassword("testUser", "oldPass", "newPass")
      ).rejects.toThrow(InvalidCredentialsError);
    });

    it("should call updatePassword with new password if old credentials are correct", async () => {
      config.passwordPolicy.updatePassword = jest
        .fn()
        .mockResolvedValue(undefined);
      jest
        .spyOn(strategy as any, "verifyCredentials")
        .mockResolvedValueOnce(true);

      await strategy.changePassword("testUser", "oldPass", "newPass");
      expect(config.passwordPolicy.updatePassword).toHaveBeenCalledWith(
        "testUser",
        "newPass"
      );
    });
  });
});
