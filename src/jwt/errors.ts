export class EmptyPayloadError extends Error {
  constructor() {
    super(`Payload is empty or not defined`);
  }
}

export class UndefinedAccessTokenError extends Error {
  constructor() {
    super(`Access token not defined`);
  }
}

export class UndefinedRefreshTokenError extends Error {
  constructor() {
    super(`Refresh token not defined`);
  }
}

export class UndefinedAccessTokenSecretOrKeyError extends Error {
  constructor() {
    super(`Access token nsecret or key ot defined`);
  }
}

export class UndefinedRefreshTokenSecretOrKeyError extends Error {
  constructor() {
    super(`Refresh token secret or key not defined`);
  }
}