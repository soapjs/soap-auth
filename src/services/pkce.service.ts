import crypto from "crypto";
import { generateRandomString } from "../tools";
import { PKCEConfig } from "../types";

/**
 * A service for handling PKCE (Proof Key for Code Exchange) operations,
 * including code verifier/challenge generation, storage, retrieval, and expiration.
 *
 * @template TContext - The context type used by the application (e.g., Express request, custom object, etc.)
 */
export class PKCEService<TContext> {
  constructor(private config: PKCEConfig<TContext>) {}

  /**
   * Default method for generating a code challenge if a custom method is not provided.
   * It applies SHA256 to the code verifier, encodes in base64url format, and removes padding.
   *
   * @private
   * @param {string} verifier - The code verifier string.
   * @returns {string} - The derived code challenge.
   */
  private defaultGenerateCodeChallenge(verifier: string): string {
    return crypto
      .createHash("sha256")
      .update(verifier)
      .digest("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  /**
   * Generates a code verifier, embeds it in the context, and stores it in persistence with an optional expiration.
   *
   * @param {TContext} context - The request or application context.
   * @returns {Promise<string>} - The generated code verifier.
   */
  async generateCodeVerifier(context: TContext): Promise<string> {
    const cv = this.config.verifier.generate?.() || generateRandomString();
    this.config.verifier.embed(context, cv);

    const expirationTime =
      Date.now() + (this.config.verifier.expiresIn ?? 300) * 1000;

    await this.config.verifier.persistence?.store(cv, {
      expiration: expirationTime,
    });

    return cv;
  }

  /**
   * Retrieves the code verifier from the context.
   *
   * @param {TContext} context - The request or application context.
   * @returns {string | undefined} - The stored code verifier, if any.
   */
  extractCodeVerifier(context: TContext): string | undefined {
    return this.config.verifier.extract(context);
  }

  /**
   * Generates a code challenge from the provided code verifier, embeds it into the context,
   * and stores it in persistence with an optional expiration.
   *
   * @param {string} codeVerifier - The code verifier.
   * @param {TContext} context - The request or application context.
   * @returns {Promise<string>} - The generated code challenge.
   */
  async generateCodeChallenge(
    codeVerifier: string,
    context: TContext
  ): Promise<string> {
    const challenge =
      this.config.challenge.generate?.(codeVerifier) ||
      this.defaultGenerateCodeChallenge(codeVerifier);

    this.config.challenge.embed(context, challenge);

    const expirationTime =
      Date.now() + (this.config.challenge.expiresIn ?? 300) * 1000;

    await this.config.challenge.persistence?.store?.(challenge, {
      expiration: expirationTime,
    });

    return challenge;
  }

  /**
   * Retrieves the code challenge from the context.
   *
   * @param {TContext} context - The request or application context.
   * @returns {string | undefined} - The stored code challenge, if any.
   */
  extractCodeChallenge(context: TContext): string | undefined {
    return this.config.challenge.extract(context);
  }

  /**
   * Checks if the code verifier is expired by reading metadata from persistence.
   *
   * @param {TContext} context - The request or application context.
   * @returns {Promise<boolean>} - True if expired or not found, false otherwise.
   */
  async isCodeVerifierExpired(context: TContext): Promise<boolean> {
    const codeVerifier = this.extractCodeVerifier(context);
    if (!codeVerifier) return true;

    const stored = await this.config.verifier?.persistence?.read?.(
      codeVerifier
    );

    if (!stored || !stored.expiration) return true;

    return Date.now() > stored.expiration;
  }

  /**
   * Checks if the code challenge is expired by reading metadata from persistence.
   *
   * @param {TContext} context - The request or application context.
   * @returns {Promise<boolean>} - True if expired or not found, false otherwise.
   */
  async isCodeChallengeExpired(context: TContext): Promise<boolean> {
    const challenge = this.extractCodeChallenge(context);
    if (!challenge) return true;

    const stored = await this.config.challenge?.persistence?.read?.(challenge);
    if (!stored || !stored.expiration) return true;

    return Date.now() > stored.expiration;
  }

  /**
   * Clears the code verifier from both persistence and the context.
   *
   * @param {TContext} context - The request or application context.
   */
  async clearCodeVerifier(context: TContext): Promise<void> {
    const cv = this.config.verifier.extract(context);
    if (cv) {
      await this.config.verifier.persistence?.remove?.(cv);
      this.config.verifier.embed(context, "");
    }
  }

  /**
   * Clears the code challenge from both persistence and the context.
   *
   * @param {TContext} context - The request or application context.
   */
  async clearCodeChallenge(context: TContext): Promise<void> {
    const challenge = this.config.challenge.extract(context);
    if (challenge) {
      await this.config.challenge.persistence?.remove?.(challenge);
      this.config.challenge.embed(context, "");
    }
  }
}
