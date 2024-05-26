import passport from "passport";
import {
  Strategy as JwtStrategy,
  ExtractJwt,
  StrategyOptions,
} from "passport-jwt";
import JWT from "jsonwebtoken";
import { JwtConfig } from "../config";

/**
 * Class for managing JWT authentication.
 */
export class JwtTools {
  private jwtConfig: JwtConfig;

  constructor(jwtConfig: JwtConfig) {
    this.jwtConfig = jwtConfig;
  }

  initStrategy(): void {
    const opts: StrategyOptions = {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: this.jwtConfig.secretOrKey,
    };

    passport.use(
      new JwtStrategy(opts, async (jwtPayload, done) => {
        try {
          const isValid = await this.jwtConfig.validate(jwtPayload);
          if (isValid) {
            return done(null, jwtPayload);
          } else {
            return done(null, false);
          }
        } catch (error) {
          return done(error, false);
        }
      })
    );
  }

  authenticate(): (...args: unknown[]) => void {
    return passport.authenticate("jwt", { session: false });
  }

  generateToken(payload: any): string {
    if (!this.jwtConfig.secretOrKey) {
      throw new Error("Secret or key is not defined");
    }
    return JWT.sign(payload, this.jwtConfig.secretOrKey, {
      expiresIn: this.jwtConfig.expiresIn,
    });
  }

  async verifyToken(token: string) {
    if (!this.jwtConfig.secretOrKey) {
      throw new Error("Secret or key is not defined");
    }
    return JWT.verifyAsync(token, this.jwtConfig.secretOrKey);
  }

  generateRefreshToken(payload: any): string {
    if (!this.jwtConfig.refreshSecretOrKey) {
      throw new Error("Refresh secret or key is not defined");
    }
    return JWT.sign(payload, this.jwtConfig.refreshSecretOrKey, {
      expiresIn: this.jwtConfig.refreshExpiresIn,
    });
  }

  async verifyRefreshToken(token: string) {
    if (!this.jwtConfig.refreshSecretOrKey) {
      throw new Error("Refresh secret or key is not defined");
    }
    return JWT.verifyAsync(token, this.jwtConfig.refreshSecretOrKey);
  }
}
