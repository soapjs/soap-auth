import * as Soap from "@soapjs/soap";
import bcrypt from "bcrypt";
import crypto from "crypto";
import {
  NewPasswordOptions,
  PasswordInfo,
  PasswordPolicyConfig,
} from "../types";
import { ValidationUtils, ValidationError } from "../utils/validation";
import { ExpiredResetTokenError } from "../errors";

export class PasswordService {
  constructor(
    private config: PasswordPolicyConfig,
    private logger: Soap.Logger
  ) {
    // Validate configuration
    this.validateConfig(config);
  }

  /**
   * Validates PasswordService configuration
   */
  private validateConfig(config: PasswordPolicyConfig): void {
    try {
      ValidationUtils.required(config, "config");
      ValidationUtils.object(config, "config");

    } catch (error) {
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new ValidationError(`Invalid PasswordService configuration: ${error.message}`);
    }
  }

  async validatePassword(
    password: string,
    previousPassword?: string
  ): Promise<void> {
    // Validate inputs
    ValidationUtils.nonEmptyString(password, "password");
    if (previousPassword !== undefined) {
      ValidationUtils.nonEmptyString(previousPassword, "previousPassword");
    }
    
    return this.config.validatePassword?.(password, previousPassword);
  }

  async getPasswordPasswordInfo(identifier: string): Promise<PasswordInfo> {
    // Validate input
    ValidationUtils.nonEmptyString(identifier, "identifier");
    
    return this.config.getPasswordPasswordInfo?.(identifier);
  }

  async generateResetToken(identifier: string): Promise<string> {
    // Validate input
    ValidationUtils.nonEmptyString(identifier, "identifier");
    
    if (!this.config?.generateResetToken) {
      throw new Soap.NotImplementedError("generateResetToken");
    }
    return this.config.generateResetToken?.(identifier);
  }

  async sendResetEmail(identifier: string, token: string): Promise<void> {
    // Validate inputs
    ValidationUtils.nonEmptyString(identifier, "identifier");
    ValidationUtils.nonEmptyString(token, "token");
    
    if (!this.config?.sendPasswordResetEmail) {
      throw new Soap.NotImplementedError("sendResetEmail");
    }
    return this.config.sendPasswordResetEmail?.(identifier, token);
  }

  async validateResetToken(token: string): Promise<void> {
    // Validate input
    ValidationUtils.nonEmptyString(token, "token");
    
    if (!this.config?.validatePasswordResetToken) {
      throw new Soap.NotImplementedError("validateResetToken");
    }
    
    const isValid = await this.config.validatePasswordResetToken(token);
    if (isValid === false) {
      throw new ExpiredResetTokenError();
    }
  }

  async updatePassword(
    identifier: string,
    newPassword: string,
    passwordOptions?: NewPasswordOptions
  ): Promise<void> {
    // Validate inputs
    ValidationUtils.nonEmptyString(identifier, "identifier");
    ValidationUtils.nonEmptyString(newPassword, "newPassword");
    
    if (passwordOptions) {
      ValidationUtils.object(passwordOptions, "passwordOptions");
      if (passwordOptions.type) {
        ValidationUtils.oneOf(passwordOptions.type, "passwordOptions.type", ["default", "one-time", "temporary"]);
      }
    }
    
    if (!this.config?.updatePassword) {
      throw new Soap.NotImplementedError("updatePassword");
    }
    return this.config.updatePassword?.(
      identifier,
      newPassword,
      passwordOptions
    );
  }

  async isPasswordChangeRequired(identifier: string): Promise<boolean> {
    // Validate input
    ValidationUtils.nonEmptyString(identifier, "identifier");
    
    const passwordInfo = await this.config.getPasswordPasswordInfo?.(
      identifier
    );

    if (
      passwordInfo &&
      (passwordInfo.type === "one-time" ||
        (passwordInfo.type === "temporary" &&
          Number.isInteger(passwordInfo.expiresIn) &&
          Date.now() - passwordInfo.lastChangeDate.getTime() >
            passwordInfo.expiresIn))
    ) {
      return true;
    }

    return false;
  }

  async generatePassword(
    identifier: string,
    options: NewPasswordOptions
  ): Promise<string> {
    // Validate inputs
    ValidationUtils.nonEmptyString(identifier, "identifier");
    ValidationUtils.required(options, "options");
    ValidationUtils.object(options, "options");
    ValidationUtils.oneOf(options.type, "options.type", ["default", "one-time", "temporary"]);
    
    let plaintext: string;

    if (this.config.generatePassword) {
      plaintext = await this.config.generatePassword(identifier, options);
    } else {
      plaintext = crypto.randomBytes(12).toString("base64url");
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(plaintext, salt);

    await this.updatePassword(identifier, hashedPassword, options);

    return plaintext;
  }
}
