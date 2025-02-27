import * as Soap from "@soapjs/soap";
import { AuthThrottleConfig } from "../types";
import { AccountLockedError } from "../errors";

export class AuthThrottleService {
  constructor(
    private config: AuthThrottleConfig,
    private logger: Soap.Logger
  ) {}
  /**
   * Checks if the user has exceeded the allowed number of failed login attempts.
   * If the threshold is reached, the account is temporarily locked.
   *
   * @param {string} identifier - The user's unique identifier.
   * @throws {AccountLockedError} If the maximum number of failed attempts is exceeded.
   */

  public async checkFailedAttempts(identifier: string) {
    let failedAttempts;
    if (this.config?.maxFailedAttempts) {
      try {
        failedAttempts =
          (await this.config.getFailedAttempts?.(identifier)) || 0;
      } catch (e) {
        this.logger.error("Check failed attempts:", e);
      }
      if (
        Number.isInteger(failedAttempts) &&
        failedAttempts >= this.config.maxFailedAttempts
      ) {
        this.logger.warn(`User ${identifier} is temporarily locked out.`);
        throw new AccountLockedError();
      }
    }
  }

  /**
   * Increments the count of failed login attempts and locks the account if needed.
   *
   * @param {string} account - The user's unique identifier.
   */
  public async incrementFailedAttempts(account: any): Promise<void> {
    if (this.config?.incrementFailedAttempts) {
      await this.config.incrementFailedAttempts(account);

      const failedAttempts =
        (await this.config.getFailedAttempts?.(account)) || 0;

      if (
        this.config?.maxFailedAttempts &&
        failedAttempts >= this.config.maxFailedAttempts
      ) {
        throw new AccountLockedError();
      }
    }
  }

  public async resetFailedAttempts(account: any): Promise<void> {
    await this.config?.resetFailedAttempts?.(account);
  }
}
