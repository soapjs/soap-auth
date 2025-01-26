/**
 * Error thrown when an API key is missing from the request.
 */
export class MissingApiKeyError extends Error {
  constructor() {
    super("API Key is missing in the request context.");
    this.name = "MissingApiKeyError";
  }
}

/**
 * Error thrown when an API key provided is invalid or not recognized.
 */
export class InvalidApiKeyError extends Error {
  constructor() {
    super("Invalid API Key provided.");
    this.name = "InvalidApiKeyError";
  }
}

export class ExpiredApiKeyError extends Error {
  constructor() {
    super("Expired API Key.");
    this.name = "InvalidApiKeyError";
  }
}
