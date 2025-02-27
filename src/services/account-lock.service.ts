import * as Soap from "@soapjs/soap";
import { AccountLockConfig } from "../types";
import { AccountLockedError } from "../errors";

export class AccountLockService<TContext = unknown> {
  constructor(
    private config: AccountLockConfig<TContext>,
    private logger: Soap.Logger
  ) {}

  public async isAccountLocked(account: any): Promise<boolean> {
    if (await this.config.isAccountLocked(account)) {
      throw new AccountLockedError();
    }

    return false;
  }

  public async lockAccount(account: any): Promise<void> {
    await this.config.lockAccount(account);

    if (this.config?.notifyOnLockout) {
      await this.config.notifyOnLockout(account);
    }
  }

  public async hasAccountLockExpired(account: any): Promise<boolean> {
    return this.config.hasAccountLockExpired(account);
  }

  public async removeAccountLock(account: any): Promise<void> {
    return this.config.removeAccountLock(account);
  }

  public async logFailedAttempt(id: string, context?: TContext) {
    try {
      await this.config.logFailedAttempt?.(id, context);
    } catch (error) {
      this.logger?.error(error);
    }
  }
}
