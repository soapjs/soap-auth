import { AccountLockedError } from "../../errors";
import { AccountLockService } from "../account-lock.service";

const mockConfig = {
  isAccountLocked: jest.fn(),
  lockAccount: jest.fn(),
  hasAccountLockExpired: jest.fn(),
  removeAccountLock: jest.fn(),
  logFailedAttempt: jest.fn(),
  notifyOnLockout: jest.fn(),
};

const mockLogger = {
  error: jest.fn(),
};

describe("AccountLockService", () => {
  let service;
  const mockAccount = { id: "123" };

  beforeEach(() => {
    jest.clearAllMocks();
    service = new AccountLockService(mockConfig, mockLogger as any);
  });

  it("isAccountLocked throws error if account is locked", async () => {
    mockConfig.isAccountLocked.mockResolvedValue(true);
    await expect(service.isAccountLocked(mockAccount)).rejects.toThrow(
      AccountLockedError
    );
  });

  it("isAccountLocked returns false if account is not locked", async () => {
    mockConfig.isAccountLocked.mockResolvedValue(false);
    await expect(service.isAccountLocked(mockAccount)).resolves.toBe(false);
  });

  it("lockAccount locks the account and notifies if enabled", async () => {
    mockConfig.notifyOnLockout = jest.fn();
    await service.lockAccount(mockAccount);
    expect(mockConfig.lockAccount).toHaveBeenCalledWith(mockAccount);
    expect(mockConfig.notifyOnLockout).toHaveBeenCalledWith(mockAccount);
  });

  it("lockAccount does not notify if notifyOnLockout is not defined", async () => {
    mockConfig.notifyOnLockout = undefined;
    await service.lockAccount(mockAccount);
    expect(mockConfig.lockAccount).toHaveBeenCalledWith(mockAccount);
  });

  it("hasAccountLockExpired returns expected value", async () => {
    mockConfig.hasAccountLockExpired.mockResolvedValue(true);
    await expect(service.hasAccountLockExpired(mockAccount)).resolves.toBe(
      true
    );
  });

  it("removeAccountLock calls the correct method", async () => {
    await service.removeAccountLock(mockAccount);
    expect(mockConfig.removeAccountLock).toHaveBeenCalledWith(mockAccount);
  });

  it("logFailedAttempt logs action and handles error if logging fails", async () => {
    mockConfig.logFailedAttempt.mockRejectedValue(new Error("Logging failed"));
    await service.logFailedAttempt("LOGIN_ATTEMPT", mockAccount, {});
    expect(mockLogger.error).toHaveBeenCalled();
  });
});
