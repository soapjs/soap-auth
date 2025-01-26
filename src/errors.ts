/**
 * Error thrown when the user does not have the required role.
 */
export class UnauthorizedRoleError extends Error {
  constructor() {
    super("User does not have the required role.");
    this.name = "UnauthorizedRoleError";
  }
}

export class MissingAuthorizationCodeError extends Error {
  constructor() {
    super("Authorization code is required.");
    this.name = "MissingAuthorizationCodeError";
  }
}

/**
 * Error thrown when the request exceeds the rate limit.
 */
export class RateLimitExceededError extends Error {
  constructor() {
    super("Rate limit exceeded for the provided credentials.");
    this.name = "RateLimitExceededError";
  }
}

/**
 * Error thrown when an account is locked due to too many failed attempts.
 */
export class AccountLockedError extends Error {
  constructor() {
    super("Account is locked due to too many failed attempts.");
    this.name = "AccountLockedError";
  }
}

export class MissingCredentialsError extends Error {
  constructor() {
    super("Missing credentials: Username and password are required.");
    this.name = "MissingCredentialsError";
  }
}

export class UserNotFoundError extends Error {
  constructor() {
    super("User not found.");
    this.name = "UserNotFound";
  }
}

export class InvalidCredentialsError extends Error {
  constructor() {
    super("Invalid credentials: Authentication failed.");
    this.name = "InvalidCredentialsError";
  }
}

export class MissingTokenError extends Error {
  constructor(public readonly tokenType: "Access" | "Refresh" = "Access") {
    super(`${tokenType} token is empty or not defined`);
  }
}

export class EmptyPayloadError extends Error {
  constructor() {
    super(`Payload is empty or not defined`);
  }
}

export class UndefinedTokenError extends Error {
  constructor(public readonly tokenType: "Access" | "Refresh" = "Access") {
    super(`${tokenType} token not defined`);
  }
}

export class InvalidTokenError extends Error {
  constructor(public readonly tokenType: "Access" | "Refresh" = "Access") {
    super(`Invalid ${tokenType} token`);
  }
}

export class UndefinedTokenSecretError extends Error {
  constructor(public readonly tokenType: "Access" | "Refresh" = "Access") {
    super(`${tokenType} token secret not defined`);
  }
}

export class UndefinedTokenHandlerError extends Error {
  constructor(
    public readonly tokenType: "Access" | "Refresh" = "Access",
    public readonly handler: string
  ) {
    super(`${tokenType} token "${handler}" not defined`);
  }
}

export class ExpiredTokenError extends Error {
  constructor(public readonly tokenType: "Access" | "Refresh" = "Access") {
    super(`${tokenType} token expired`);
  }
}

export class AuthError extends Error {
  constructor(public readonly error: Error, message: string) {
    super(message || error.message);
    this.name = "AuthError";
  }
}
