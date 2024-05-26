import session, { SessionOptions } from "express-session";
import { SessionConfig } from "../config";

/**
 * Class for managing sessions.
 */
export class SessionTools {
  private sessionConfig: SessionConfig;

  constructor(sessionConfig: SessionConfig) {
    this.sessionConfig = sessionConfig;
  }

  initSession(): any {
    return session(this.sessionConfig as SessionOptions);
  }

  serializeUser(user: any, done: (err: any, id?: any) => void): void {
    if (this.sessionConfig.serializeUser) {
      this.sessionConfig.serializeUser(user, done);
    } else {
      done(null, user.id);
    }
  }

  deserializeUser(id: any, done: (err: any, user?: any) => void): void {
    if (this.sessionConfig.deserializeUser) {
      this.sessionConfig.deserializeUser(id, done);
    } else {
      done(null, { id });
    }
  }
}
