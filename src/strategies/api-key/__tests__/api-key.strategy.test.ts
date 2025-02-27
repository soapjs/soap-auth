import { ApiKeyStrategy } from "../api-key.strategy";
import {
  AccountLockedError,
  RateLimitExceededError,
  UnauthorizedRoleError,
} from "../../../errors";
import {
  ExpiredApiKeyError,
  InvalidApiKeyError,
  MissingApiKeyError,
} from "../api-key.errors";

describe("ApiKeyStrategy", () => {
  let strategy: ApiKeyStrategy<any, any>;
  let mockConfig: any;
  let mockLogger: any;

  beforeEach(() => {
    mockLogger = {
      error: jest.fn(),
      warn: jest.fn(),
      info: jest.fn(),
    };

    mockConfig = {
      extractApiKey: jest.fn(),
      retrieveUserByApiKey: jest.fn(),
      lock: {
        isAccountLocked: jest.fn(),
        logFailedAttempt: jest.fn(),
      },
      isApiKeyExpired: jest.fn(),
      rateLimit: {
        checkRateLimit: jest.fn(),
        incrementRequestCount: jest.fn(),
      },
      role: { authorizeByRoles: jest.fn() },
      revokeApiKey: jest.fn(),
      trackApiKeyUsage: jest.fn(),
      keyType: "long-term",
    };

    strategy = new ApiKeyStrategy(mockConfig, mockLogger);
  });

  it("should authenticate a user with a valid API key", async () => {
    mockConfig.extractApiKey.mockReturnValue("valid-api-key");
    mockConfig.retrieveUserByApiKey.mockResolvedValue({
      id: 1,
      name: "John Doe",
    });

    const result = await strategy.authenticate({});

    expect(result).toEqual({ user: { id: 1, name: "John Doe" } });
    expect(mockConfig.trackApiKeyUsage).toHaveBeenCalledWith("valid-api-key");
    expect(mockConfig.rateLimit.incrementRequestCount).toHaveBeenCalledWith(
      "valid-api-key"
    );
  });

  it("should throw MissingApiKeyError if no API key is provided", async () => {
    mockConfig.extractApiKey.mockReturnValue(null);

    await expect(strategy.authenticate({})).rejects.toThrow(MissingApiKeyError);
    expect(mockConfig.lock.logFailedAttempt).toHaveBeenCalled();
  });

  it("should throw InvalidApiKeyError if the API key is invalid", async () => {
    mockConfig.extractApiKey.mockReturnValue("invalid-api-key");
    mockConfig.retrieveUserByApiKey.mockResolvedValue(null);

    await expect(strategy.authenticate({})).rejects.toThrow(InvalidApiKeyError);
    expect(mockConfig.lock.logFailedAttempt).toHaveBeenCalledWith(
      "invalid-api-key",
      {}
    );
  });

  it("should throw AccountLockedError if account is locked", async () => {
    mockConfig.extractApiKey.mockReturnValue("valid-api-key");
    mockConfig.lock.isAccountLocked.mockResolvedValue(true);

    await expect(strategy.authenticate({})).rejects.toThrow(AccountLockedError);
  });

  it("should throw ExpiredApiKeyError if API key is expired", async () => {
    mockConfig.extractApiKey.mockReturnValue("valid-api-key");
    mockConfig.isApiKeyExpired.mockResolvedValue(true);

    await expect(strategy.authenticate({})).rejects.toThrow(ExpiredApiKeyError);
  });

  it("should throw RateLimitExceededError if API key exceeds rate limit", async () => {
    mockConfig.extractApiKey.mockReturnValue("valid-api-key");
    mockConfig.rateLimit.checkRateLimit.mockResolvedValue(true);

    await expect(strategy.authenticate({})).rejects.toThrow(
      RateLimitExceededError
    );
  });

  it("should throw UnauthorizedRoleError if user has no access", async () => {
    mockConfig.role.roles = ["admin", "user"];
    mockConfig.extractApiKey.mockReturnValue("valid-api-key");
    mockConfig.retrieveUserByApiKey.mockResolvedValue({ id: 1, role: "guest" });
    mockConfig.role.authorizeByRoles.mockResolvedValue(false);

    await expect(strategy.authenticate({})).rejects.toThrow(
      UnauthorizedRoleError
    );
  });

  it("should revoke one-time API keys after authentication", async () => {
    mockConfig.keyType = "one-time";
    mockConfig.extractApiKey.mockReturnValue("one-time-key");
    mockConfig.retrieveUserByApiKey.mockResolvedValue({ id: 1 });

    await strategy.authenticate({});

    expect(mockConfig.revokeApiKey).toHaveBeenCalledWith("one-time-key");
  });

  it("should retry retrieving user on failure", async () => {
    mockConfig.retrieveUserMaxRetries = 1;
    mockConfig.extractApiKey.mockReturnValue("valid-api-key");
    mockConfig.retrieveUserByApiKey
      .mockRejectedValueOnce(new Error("Temporary failure"))
      .mockResolvedValueOnce({ id: 1, name: "John Doe" });

    const result = await strategy.authenticate({});

    expect(result).toEqual({ user: { id: 1, name: "John Doe" } });
    expect(mockConfig.retrieveUserByApiKey).toHaveBeenCalledTimes(2);
  });

  it("should log failed authentication attempts", async () => {
    mockConfig.extractApiKey.mockReturnValue("invalid-api-key");
    mockConfig.retrieveUserByApiKey.mockResolvedValue(null);
    const ctx = {};
    await expect(strategy.authenticate(ctx)).rejects.toThrow(
      InvalidApiKeyError
    );

    expect(mockConfig.lock.logFailedAttempt).toHaveBeenCalledWith(
      "invalid-api-key",
      ctx
    );
  });
});
