import { RateLimitExceededError } from "../../errors";
import { RateLimitService } from "../rate-limit.service";

const mockConfig = {
  incrementRequestCount: jest.fn(),
  checkRateLimit: jest.fn(),
};

const mockLogger = {
  error: jest.fn(),
};

describe("RateLimitService", () => {
  let service;
  const mockData = { userId: "user123" };

  beforeEach(() => {
    jest.clearAllMocks();
    service = new RateLimitService(mockConfig as any, mockLogger as any);
  });

  it("incrementRequestCount calls config method and handles errors", async () => {
    mockConfig.incrementRequestCount.mockResolvedValue(undefined);
    await expect(
      service.incrementRequestCount(mockData)
    ).resolves.not.toThrow();
    expect(mockConfig.incrementRequestCount).toHaveBeenCalledWith(mockData);
  });

  it("incrementRequestCount logs error if an exception occurs", async () => {
    mockConfig.incrementRequestCount.mockRejectedValue(
      new Error("Increment failed")
    );
    await expect(
      service.incrementRequestCount(mockData)
    ).resolves.not.toThrow();
    expect(mockLogger.error).toHaveBeenCalledWith(expect.any(Error));
  });

  it("checkRateLimit throws RateLimitExceededError if limit is exceeded", async () => {
    mockConfig.checkRateLimit.mockResolvedValue(true);
    await expect(service.checkRateLimit(mockData)).rejects.toThrow(
      RateLimitExceededError
    );
  });

  it("checkRateLimit does not throw error if limit is not exceeded", async () => {
    mockConfig.checkRateLimit.mockResolvedValue(false);
    await expect(service.checkRateLimit(mockData)).resolves.not.toThrow();
  });
});
