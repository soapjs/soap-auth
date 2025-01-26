import crypto from "crypto";

export class OAuth2Tools {
  /**
   * Generates a secure random string for PKCE.
   */
  static generateCodeVerifier(): string {
    return crypto.randomBytes(32).toString("hex");
  }

  /**
   * Generates a code challenge based on the code verifier using SHA256.
   *
   * @param {string} codeVerifier - The original code verifier.
   * @returns {string} The base64url-encoded SHA256 hash.
   */
  static generateCodeChallenge(codeVerifier: string): string {
    return crypto
      .createHash("sha256")
      .update(codeVerifier)
      .digest("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }
}
