export class InvalidSessionError extends Error {
  constructor() {
    super("Session is invalid or expired.");
  }
}

export class MissingSessionIdError extends Error {
  constructor() {
    super("Session ID is missing.");
  }
}
