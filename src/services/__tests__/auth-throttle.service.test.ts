import { AccountLockedError } from "../../errors";
import { AuthThrottleService } from "../auth-throttle.service";

const mockConfig = {
  getFailedAttempts: jest.fn(),
  incrementFailedAttempts: jest.fn(),
  resetFailedAttempts: jest.fn(),
  maxFailedAttempts: 3,
};

const mockLogger = {
  warn: jest.fn(),
  error: jest.fn(),
};

describe("AuthThrottleService", () => {
  let service;
  const mockIdentifier = "user123";

  beforeEach(() => {
    jest.clearAllMocks();
    service = new AuthThrottleService(mockConfig, mockLogger as any);
  });

  it("checkFailedAttempts throws error if max failed attempts reached", async () => {
    mockConfig.getFailedAttempts.mockResolvedValue(3);
    await expect(service.checkFailedAttempts(mockIdentifier)).rejects.toThrow(
      AccountLockedError
    );
    expect(mockLogger.warn).toHaveBeenCalledWith(
      `User ${mockIdentifier} is temporarily locked out.`
    );
  });

  it("checkFailedAttempts does not throw error if failed attempts are below threshold", async () => {
    mockConfig.getFailedAttempts.mockResolvedValue(2);
    await expect(
      service.checkFailedAttempts(mockIdentifier)
    ).resolves.not.toThrow();
  });

  it("checkFailedAttempts logs error if an exception occurs", async () => {
    mockConfig.getFailedAttempts.mockRejectedValue(new Error("DB error"));
    await service.checkFailedAttempts(mockIdentifier);
    expect(mockLogger.error).toHaveBeenCalledWith(
      "Check failed attempts:",
      expect.any(Error)
    );
  });

  it("incrementFailedAttempts increments counter and throws if max reached", async () => {
    mockConfig.getFailedAttempts.mockResolvedValue(3);
    await expect(
      service.incrementFailedAttempts(mockIdentifier)
    ).rejects.toThrow(AccountLockedError);
  });

  it("incrementFailedAttempts increments counter without throwing if below threshold", async () => {
    mockConfig.getFailedAttempts.mockResolvedValue(2);
    await expect(
      service.incrementFailedAttempts(mockIdentifier)
    ).resolves.not.toThrow();
  });

  it("resetFailedAttempts calls the correct method", async () => {
    await service.resetFailedAttempts(mockIdentifier);
    expect(mockConfig.resetFailedAttempts).toHaveBeenCalledWith(mockIdentifier);
  });
});
