import * as Soap from "@soapjs/soap";
import { MfaConfig } from "../types";

export class MfaService<TContext = unknown, TUser = unknown> {
  constructor(private config: MfaConfig, private logger: Soap.Logger) {}

  public async checkMfa(user: TUser, context: TContext): Promise<void> {
    try {
      if (this.config.isMfaRequired?.(user)) {
        const mfaCode = this.config.extractMfaCode?.(context);

        if (!mfaCode) {
          await this.config.sendMfaCode?.(user, context);
          throw new Error("2FA required. A verification code has been sent.");
        }

        const attempts = (await this.getMfaAttempts(user)) || 0;

        if (
          this.config.maxMfaAttempts &&
          attempts >= this.config.maxMfaAttempts
        ) {
          this.logger?.warn(`User ${user} exceeded maximum MFA attempts.`);
          await this.lockMfaOnFailure(user);
          throw new Error(
            "Your account has been temporarily locked due to too many failed 2FA attempts."
          );
        }

        const isValidMfa = await this.config.validateMfaCode?.(user, mfaCode);
        if (!isValidMfa) {
          this.logger?.warn(`Invalid MFA code attempt for user: ${user}`);
          await this.incrementMfaAttempts(user);
          throw new Error("Invalid 2FA code provided.");
        }

        await this.resetMfaAttempts(user);

        this.logger?.info(`2FA successfully validated for user: ${user}`);
      }
    } catch (error) {
      this.logger?.error(`2FA validation error for user: ${user}`, error);
      throw error;
    }
  }

  protected lockMfaOnFailure(user: TUser) {
    try {
      this.config.lockMfaOnFailure?.(user);
    } catch (error) {
      this.logger?.error(error);
    }
  }

  protected async getMfaAttempts(user: TUser) {
    try {
      return this.config.getMfaAttempts?.(user);
    } catch (error) {
      this.logger?.error(error);
    }
  }

  protected incrementMfaAttempts(user: TUser) {
    try {
      this.config.incrementMfaAttempts?.(user);
    } catch (error) {
      this.logger?.error(error);
    }
  }

  protected resetMfaAttempts(user: TUser) {
    try {
      this.config.resetMfaAttempts?.(user);
    } catch (error) {
      this.logger?.error(error);
    }
  }
}
