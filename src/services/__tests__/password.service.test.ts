import { PasswordService } from "../password.service";
import { NotImplementedError } from "@soapjs/soap";
import { jest } from "@jest/globals";

describe("PasswordService", () => {
  let service;
  let mockConfig;

  const mockLogger: any = { error: jest.fn() };
  const mockIdentifier = "user123";
  const mockPassword = "SecurePass123!";

  beforeEach(() => {
    jest.clearAllMocks();
    mockConfig = {
      validatePassword: jest.fn(),
      getPasswordPasswordInfo: jest.fn(),
      generateResetToken: jest.fn(),
      sendPasswordResetEmail: jest.fn(),
      validatePasswordResetToken: jest.fn(),
      updatePassword: jest.fn(),
      passwordExpirationDays: 30,
    };
    service = new PasswordService(mockConfig, mockLogger);
  });

  it("validatePassword calls config method", async () => {
    mockConfig.validatePassword.mockReturnValue(true);
    await expect(service.validatePassword(mockPassword)).resolves.toBe(true);
    expect(mockConfig.validatePassword).toHaveBeenCalledWith(mockPassword, undefined);
  });

  it("getPasswordPasswordInfo calls config method", async () => {
    const mockPasswordInfo = { type: "default" as const };
    mockConfig.getPasswordPasswordInfo.mockReturnValue(mockPasswordInfo);
    await expect(service.getPasswordPasswordInfo(mockIdentifier)).resolves.toBe(
      mockPasswordInfo
    );
    expect(mockConfig.getPasswordPasswordInfo).toHaveBeenCalledWith(
      mockIdentifier
    );
  });

  it("generateResetToken calls config method", async () => {
    mockConfig.generateResetToken.mockResolvedValue("mock-token");
    await expect(service.generateResetToken(mockIdentifier)).resolves.toBe(
      "mock-token"
    );
  });

  it("sendResetEmail calls config method", async () => {
    await expect(
      service.sendResetEmail(mockIdentifier, "mock-token")
    ).resolves.not.toThrow();
    expect(mockConfig.sendPasswordResetEmail).toHaveBeenCalledWith(
      mockIdentifier,
      "mock-token"
    );
  });

  it("validateResetToken calls config method", async () => {
    mockConfig.validatePasswordResetToken.mockResolvedValue(true);
    await expect(service.validateResetToken("mock-token")).resolves.toBeUndefined();
  });

  it("updatePassword calls config method", async () => {
    await expect(
      service.updatePassword(mockIdentifier, mockPassword)
    ).resolves.not.toThrow();
    expect(mockConfig.updatePassword).toHaveBeenCalledWith(
      mockIdentifier,
      mockPassword,
      undefined
    );
  });

  it("isPasswordChangeRequired returns true if password is expired", async () => {
    const pastDate = new Date(Date.now() - 31 * 86400000);
    mockConfig.getPasswordPasswordInfo.mockResolvedValue({
      type: "temporary",
      lastChangeDate: pastDate,
      expiresIn: 30 * 86400000
    });
    await expect(
      service.isPasswordChangeRequired(mockIdentifier)
    ).resolves.toBe(true);
  });

  it("isPasswordChangeRequired returns false if password is within expiration period", async () => {
    const recentDate = new Date(Date.now() - 15 * 86400000);
    mockConfig.getPasswordPasswordInfo.mockResolvedValue({
      type: "temporary",
      lastChangeDate: recentDate,
      expiresIn: 30 * 86400000
    });
    await expect(
      service.isPasswordChangeRequired(mockIdentifier)
    ).resolves.toBe(false);
  });

  it("isPasswordChangeRequired returns false if getPasswordPasswordInfo is not defined", async () => {
    service = new PasswordService({ passwordExpirationDays: 30 }, mockLogger);
    await expect(
      service.isPasswordChangeRequired(mockIdentifier)
    ).resolves.toBe(false);
  });
});
