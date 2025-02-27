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
      getLastPasswordChange: jest.fn(),
      generateResetToken: jest.fn(),
      sendResetEmail: jest.fn(),
      validateResetToken: jest.fn(),
      updatePassword: jest.fn(),
      passwordExpirationDays: 30,
    };
    service = new PasswordService(mockConfig, mockLogger);
  });

  it("validatePassword calls config method", async () => {
    mockConfig.validatePassword.mockReturnValue(true);
    await expect(service.validatePassword(mockPassword)).resolves.toBe(true);
    expect(mockConfig.validatePassword).toHaveBeenCalledWith(mockPassword);
  });

  it("getLastPasswordChange calls config method", async () => {
    const mockDate = new Date();
    mockConfig.getLastPasswordChange.mockReturnValue(mockDate);
    await expect(service.getLastPasswordChange(mockIdentifier)).resolves.toBe(
      mockDate
    );
    expect(mockConfig.getLastPasswordChange).toHaveBeenCalledWith(
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
    expect(mockConfig.sendResetEmail).toHaveBeenCalledWith(
      mockIdentifier,
      "mock-token"
    );
  });

  it("validateResetToken calls config method", async () => {
    mockConfig.validateResetToken.mockResolvedValue(true);
    await expect(service.validateResetToken("mock-token")).resolves.toBe(true);
  });

  it("updatePassword calls config method", async () => {
    await expect(
      service.updatePassword(mockIdentifier, mockPassword)
    ).resolves.not.toThrow();
    expect(mockConfig.updatePassword).toHaveBeenCalledWith(
      mockIdentifier,
      mockPassword
    );
  });

  it("isPasswordChangeRequired returns true if password is expired", async () => {
    const pastDate = new Date(Date.now() - 31 * 86400000);
    mockConfig.getLastPasswordChange.mockResolvedValue(pastDate);
    await expect(
      service.isPasswordChangeRequired(mockIdentifier)
    ).resolves.toBe(true);
  });

  it("isPasswordChangeRequired returns false if password is within expiration period", async () => {
    const recentDate = new Date(Date.now() - 15 * 86400000);
    mockConfig.getLastPasswordChange.mockResolvedValue(recentDate);
    await expect(
      service.isPasswordChangeRequired(mockIdentifier)
    ).resolves.toBe(false);
  });

  it("isPasswordChangeRequired throws NotImplementedError if getLastPasswordChange is not defined", async () => {
    service = new PasswordService({ passwordExpirationDays: 30 }, mockLogger);
    await expect(
      service.isPasswordChangeRequired(mockIdentifier)
    ).rejects.toThrow(NotImplementedError);
  });
});
