export class InvalidNonceError extends Error {}
export class InvalidStateError extends Error {}
export class InvalidIdTokenError extends Error {}
export class UnsupportedGrantTypeError extends Error {
  constructor(type: string) {
    super(`Unsupported grant type: ${type}`);
  }
}
export class MissingCodeVerifierError extends Error {
  constructor() {
    super("Missing PKCE code verifier in context.");
  }
}
