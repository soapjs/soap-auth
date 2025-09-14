import * as Soap from "@soapjs/soap";

/**
 * Validation error class for input validation failures
 */
export class ValidationError extends Error {
  constructor(message: string, public field?: string) {
    super(message);
    this.name = "ValidationError";
  }
}

/**
 * Validation utility class for common validation patterns
 */
export class ValidationUtils {
  /**
   * Validates that a value is not null or undefined
   */
  static required(value: any, fieldName: string): void {
    if (value === null || value === undefined) {
      throw new ValidationError(`${fieldName} is required`, fieldName);
    }
  }

  /**
   * Validates that a string is not empty
   */
  static nonEmptyString(value: any, fieldName: string): string {
    this.required(value, fieldName);
    if (typeof value !== "string" || value.trim().length === 0) {
      throw new ValidationError(`${fieldName} must be a non-empty string`, fieldName);
    }
    return value.trim();
  }

  /**
   * Validates email format
   */
  static email(value: any, fieldName: string): string {
    const email = this.nonEmptyString(value, fieldName);
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw new ValidationError(`${fieldName} must be a valid email address`, fieldName);
    }
    return email;
  }

  /**
   * Validates password strength
   */
  static password(value: any, fieldName: string, minLength: number = 8): string {
    const password = this.nonEmptyString(value, fieldName);
    if (password.length < minLength) {
      throw new ValidationError(`${fieldName} must be at least ${minLength} characters long`, fieldName);
    }
    return password;
  }

  /**
   * Validates that a value is a positive number
   */
  static positiveNumber(value: any, fieldName: string): number {
    this.required(value, fieldName);
    const num = Number(value);
    if (isNaN(num) || num <= 0) {
      throw new ValidationError(`${fieldName} must be a positive number`, fieldName);
    }
    return num;
  }

  /**
   * Validates that a value is within a range
   */
  static range(value: any, fieldName: string, min: number, max: number): number {
    const num = this.positiveNumber(value, fieldName);
    if (num < min || num > max) {
      throw new ValidationError(`${fieldName} must be between ${min} and ${max}`, fieldName);
    }
    return num;
  }

  /**
   * Validates that a value is one of the allowed values
   */
  static oneOf<T>(value: any, fieldName: string, allowedValues: T[]): T {
    this.required(value, fieldName);
    if (!allowedValues.includes(value)) {
      throw new ValidationError(`${fieldName} must be one of: ${allowedValues.join(", ")}`, fieldName);
    }
    return value;
  }

  /**
   * Validates that a value is a valid URL
   */
  static url(value: any, fieldName: string): string {
    const url = this.nonEmptyString(value, fieldName);
    try {
      new URL(url);
      return url;
    } catch {
      throw new ValidationError(`${fieldName} must be a valid URL`, fieldName);
    }
  }

  /**
   * Validates that a value is a valid JWT token format
   */
  static jwtToken(value: any, fieldName: string): string {
    const token = this.nonEmptyString(value, fieldName);
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new ValidationError(`${fieldName} must be a valid JWT token`, fieldName);
    }
    return token;
  }

  /**
   * Validates that a value is a valid UUID
   */
  static uuid(value: any, fieldName: string): string {
    const uuid = this.nonEmptyString(value, fieldName);
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(uuid)) {
      throw new ValidationError(`${fieldName} must be a valid UUID`, fieldName);
    }
    return uuid;
  }

  /**
   * Validates that a value is a valid object
   */
  static object(value: any, fieldName: string): object {
    this.required(value, fieldName);
    if (typeof value !== "object" || Array.isArray(value)) {
      throw new ValidationError(`${fieldName} must be an object`, fieldName);
    }
    return value;
  }

  /**
   * Validates that a value is a valid array
   */
  static array(value: any, fieldName: string): any[] {
    this.required(value, fieldName);
    if (!Array.isArray(value)) {
      throw new ValidationError(`${fieldName} must be an array`, fieldName);
    }
    return value;
  }

  /**
   * Validates that a value is a valid function
   */
  static function(value: any, fieldName: string): Function {
    this.required(value, fieldName);
    if (typeof value !== "function") {
      throw new ValidationError(`${fieldName} must be a function`, fieldName);
    }
    return value;
  }

  /**
   * Validates configuration object structure
   */
  static validateConfig(config: any, requiredFields: string[], fieldName: string = "config"): void {
    this.object(config, fieldName);
    for (const field of requiredFields) {
      this.required(config[field], `${fieldName}.${field}`);
    }
  }

  /**
   * Validates that a value matches a regular expression
   */
  static pattern(value: any, fieldName: string, regex: RegExp, message?: string): string {
    const str = this.nonEmptyString(value, fieldName);
    if (!regex.test(str)) {
      throw new ValidationError(message || `${fieldName} does not match required pattern`, fieldName);
    }
    return str;
  }

  /**
   * Validates that a value is a valid date
   */
  static date(value: any, fieldName: string): Date {
    this.required(value, fieldName);
    const date = new Date(value);
    if (isNaN(date.getTime())) {
      throw new ValidationError(`${fieldName} must be a valid date`, fieldName);
    }
    return date;
  }

  /**
   * Validates that a value is a valid boolean
   */
  static boolean(value: any, fieldName: string): boolean {
    this.required(value, fieldName);
    if (typeof value !== "boolean") {
      throw new ValidationError(`${fieldName} must be a boolean`, fieldName);
    }
    return value;
  }
}
