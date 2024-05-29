import JWT from "jsonwebtoken";
import {
  EmptyPayloadError,
  UndefinedAccessTokenError,
  UndefinedAccessTokenSecretOrKeyError,
  UndefinedRefreshTokenError,
  UndefinedRefreshTokenSecretOrKeyError,
} from "./errors";
import { TokenConfig } from "./types";

/**
 * Class for managing JWT authentication.
 */
export class JwtTools {
  constructor(public readonly config: TokenConfig) {}

  generateToken(payload: any): string {
    if (!payload) {
      throw new EmptyPayloadError();
    }

    if (!this.config.secretOrKey) {
      throw new UndefinedAccessTokenSecretOrKeyError();
    }

    return JWT.sign(payload, this.config.secretOrKey, {
      expiresIn: this.config.expiresIn,
    });
  }

  async verifyToken(token: string) {
    if (!token) {
      throw new UndefinedAccessTokenError();
    }

    if (!this.config.secretOrKey) {
      throw new UndefinedAccessTokenSecretOrKeyError();
    }

    return JWT.verifyAsync(token, this.config.secretOrKey);
  }

  generateRefreshToken(payload: any): string {
    if (!payload) {
      throw new EmptyPayloadError();
    }

    if (!this.config.refreshSecretOrKey) {
      throw new UndefinedRefreshTokenSecretOrKeyError();
    }

    return JWT.sign(payload, this.config.refreshSecretOrKey, {
      expiresIn: this.config.refreshExpiresIn,
    });
  }

  async verifyRefreshToken(token: string) {
    if (!token) {
      throw new UndefinedRefreshTokenError();
    }

    if (!this.config.refreshSecretOrKey) {
      throw new UndefinedRefreshTokenSecretOrKeyError();
    }

    return JWT.verifyAsync(token, this.config.refreshSecretOrKey);
  }
}
