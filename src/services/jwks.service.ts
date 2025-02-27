import jwt, { JwtPayload } from "jsonwebtoken";
import jwksClient from "jwks-rsa";
import { InvalidIdTokenError } from "../strategies/oauth2/oauth2.errors";
import { JwksConfig } from "../strategies/oauth2/oauth2.types";

export class JwtService {
  private client;
  constructor(private config: JwksConfig) {
    this.client = jwksClient({ jwksUri: this.config.jwksUri });
  }

  async verify(idToken: string): Promise<Record<string, any> | null> {
    try {
      const decodedHeader = jwt.decode(idToken, { complete: true });
      if (!decodedHeader?.header?.kid) {
        throw new InvalidIdTokenError("Invalid ID Token structure.");
      }

      const key = await this.client.getSigningKey(decodedHeader.header.kid);
      const publicKey = key.getPublicKey();

      const payload = jwt.verify(idToken, publicKey, {
        algorithms: this.config.algorithms || ["RS256"],
        issuer: this.config.issuer,
        audience: this.config.audience,
      }) as JwtPayload;

      if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
        throw new InvalidIdTokenError("ID Token has expired");
      }

      return payload;
    } catch (error) {
      console.error("JWT verification failed:", error);
      throw error;
    }
  }
}
