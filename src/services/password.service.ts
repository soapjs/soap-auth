import * as Soap from "@soapjs/soap";
import { PasswordPolicyConfig } from "../types";

export class PasswordService {
  constructor(
    private config: PasswordPolicyConfig,
    private logger: Soap.Logger
  ) {}

  async validatePassword(password: string): Promise<boolean> {
    return this.config.validatePassword?.(password);
  }

  async getLastPasswordChange(identifier: string): Promise<Date> {
    return this.config.getLastPasswordChange?.(identifier);
  }

  async generateResetToken(identifier: string): Promise<string> {
    if (!this.config?.generateResetToken) {
      throw new Soap.NotImplementedError("generateResetToken");
    }
    return this.config.generateResetToken?.(identifier);
  }

  async sendResetEmail(identifier: string, token: string): Promise<void> {
    if (!this.config?.sendResetEmail) {
      throw new Soap.NotImplementedError("sendResetEmail");
    }
    return this.config.sendResetEmail?.(identifier, token);
  }

  async validateResetToken(token: string): Promise<boolean> {
    if (!this.config?.validateResetToken) {
      throw new Soap.NotImplementedError("validateResetToken");
    }
    return this.config.validateResetToken?.(token);
  }

  async updatePassword(identifier: string, newPassword: string): Promise<void> {
    if (!this.config?.updatePassword) {
      throw new Soap.NotImplementedError("updatePassword");
    }
    return this.config.updatePassword?.(identifier, newPassword);
  }

  async isPasswordChangeRequired(identifier: string): Promise<boolean> {
    if (this.config.passwordExpirationDays) {
      if (!this.config.getLastPasswordChange) {
        throw new Soap.NotImplementedError("getLastPasswordChange");
      }
      const lastChanged = await this.config.getLastPasswordChange(identifier);
      return (
        lastChanged &&
        Date.now() - Number(lastChanged) >
          this.config.passwordExpirationDays * 86400000
      );
    }

    return false;
  }
}
