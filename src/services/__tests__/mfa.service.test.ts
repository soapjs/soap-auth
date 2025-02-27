import { MfaService } from "../mfa.service";

const mockConfig = {
  isMfaRequired: jest.fn(),
  extractMfaCode: jest.fn(),
  sendMfaCode: jest.fn(),
  validateMfaCode: jest.fn(),
  maxMfaAttempts: 3,
  getMfaAttempts: jest.fn(),
  incrementMfaAttempts: jest.fn(),
  resetMfaAttempts: jest.fn(),
  lockMfaOnFailure: jest.fn(),
};

const mockLogger = {
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

describe("MfaService", () => {
  let service;
  const mockUser = { id: "user123" };
  const mockContext = { token: "mock-token" };

  beforeEach(() => {
    jest.clearAllMocks();
    service = new MfaService(mockConfig, mockLogger as any);
  });

  it("checkMfa sends code if required and no code provided", async () => {
    mockConfig.isMfaRequired.mockReturnValue(true);
    mockConfig.extractMfaCode.mockReturnValue(null);

    await expect(service.checkMfa(mockUser, mockContext)).rejects.toThrow(
      "2FA required. A verification code has been sent."
    );
    expect(mockConfig.sendMfaCode).toHaveBeenCalledWith(mockUser, mockContext);
  });

  it("checkMfa locks account after too many failed attempts", async () => {
    mockConfig.isMfaRequired.mockReturnValue(true);
    mockConfig.extractMfaCode.mockReturnValue("wrong-code");
    mockConfig.getMfaAttempts.mockResolvedValue(3);

    await expect(service.checkMfa(mockUser, mockContext)).rejects.toThrow(
      "Your account has been temporarily locked due to too many failed 2FA attempts."
    );
    expect(mockLogger.warn).toHaveBeenCalledWith(
      `User ${mockUser} exceeded maximum MFA attempts.`
    );
    expect(mockConfig.lockMfaOnFailure).toHaveBeenCalledWith(mockUser);
  });

  it("checkMfa rejects invalid MFA codes", async () => {
    mockConfig.isMfaRequired.mockReturnValue(true);
    mockConfig.extractMfaCode.mockReturnValue("invalid-code");
    mockConfig.getMfaAttempts.mockResolvedValue(1);
    mockConfig.validateMfaCode.mockResolvedValue(false);

    await expect(service.checkMfa(mockUser, mockContext)).rejects.toThrow(
      "Invalid 2FA code provided."
    );
    expect(mockLogger.warn).toHaveBeenCalledWith(
      `Invalid MFA code attempt for user: ${mockUser}`
    );
    expect(mockConfig.incrementMfaAttempts).toHaveBeenCalledWith(mockUser);
  });

  it("checkMfa resets attempts on successful MFA validation", async () => {
    mockConfig.isMfaRequired.mockReturnValue(true);
    mockConfig.extractMfaCode.mockReturnValue("valid-code");
    mockConfig.validateMfaCode.mockResolvedValue(true);

    await expect(
      service.checkMfa(mockUser, mockContext)
    ).resolves.not.toThrow();
    expect(mockConfig.resetMfaAttempts).toHaveBeenCalledWith(mockUser);
    expect(mockLogger.info).toHaveBeenCalledWith(
      `2FA successfully validated for user: ${mockUser}`
    );
  });

  it("lockMfaOnFailure logs error if an exception occurs", async () => {
    mockConfig.lockMfaOnFailure.mockImplementation(() => {
      throw new Error("Lock failed");
    });
    service.lockMfaOnFailure(mockUser);
    expect(mockLogger.error).toHaveBeenCalledWith(expect.any(Error));
  });
});
