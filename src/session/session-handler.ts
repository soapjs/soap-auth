import * as Soap from "@soapjs/soap";
import { v4 as uuidv4 } from "uuid";
import {
  SessionConfig,
  SessionData,
  SessionInfo,
  SessionStore,
} from "../types";
import { MissingSessionIdError } from "./session.errors";

/**
 * Handles session operations such as retrieving, storing, and generating session IDs.
 */
export class SessionHandler<
  TContext = unknown,
  TUser = unknown,
  TData = SessionData
> {
  private store: SessionStore;
  private sessionKey: string;
  private headerKey: string;

  constructor(private config: SessionConfig, private logger?: Soap.Logger) {
    if (!config.store) {
      throw new Error("Session store is required.");
    }
    this.store = config.store;
    this.sessionKey = config.sessionKey || "SESSIONID";
    this.headerKey = config.sessionHeader || "x-session-id";
  }

  /**
   * Stores the session ID in the response context.
   *
   * @param context - The authentication context.
   * @param sessionId - The session ID to be stored.
   */
  setSessionId(context: TContext, sessionId: string): void {
    try {
      if (this.config.embedSessionId) {
        this.config.embedSessionId(context, sessionId);
        return;
      }

      if (context && typeof context === "object") {
        if ("res" in context && (context as any).res) {
          if ("cookie" in (context as any).res) {
            (context as any).res.cookie(this.sessionKey, sessionId, {
              httpOnly: true,
              secure: true,
              sameSite: "strict",
            });
            this.config.logger?.info(
              `Session ID set in cookie: ${this.sessionKey}`
            );
          } else if ("setHeader" in (context as any).res) {
            (context as any).res.setHeader(this.headerKey, sessionId);
            this.config.logger?.info(
              `Session ID set in header: ${this.headerKey}`
            );
          }
        } else {
          (context as any).sessionId = sessionId;
          this.config.logger?.info(`Session ID set in context object`);
        }
      }
    } catch (error) {
      this.config.logger?.error("Error setting session ID:", error);
    }
  }

  /**
   * Retrieves the session ID from the context.
   *
   * @param context - The authentication context.
   * @returns {string | null} The session ID or null if not found.
   */
  getSessionId(context: TContext): string | null {
    try {
      if (this.config.getSessionId) {
        return this.config.getSessionId(context);
      }

      if (context && typeof context === "object") {
        if ("cookies" in context && (context as any).cookies[this.sessionKey]) {
          return (context as any).cookies[this.sessionKey];
        }
        if ("headers" in context && (context as any).headers[this.headerKey]) {
          return (context as any).headers[this.headerKey];
        }
        if ("sessionId" in context) {
          return (context as any).sessionId;
        }
      }
      return null;
    } catch (error) {
      this.config.logger?.error("Error retrieving session ID:", error);
      return null;
    }
  }

  /**
   * Generates a new session ID if no existing one is provided.
   *
   * @returns {string} A newly generated session ID.
   */
  generateSessionId(): string {
    return this.config.generateSessionId?.() || uuidv4();
  }

  /**
   * Builds initial session data for a new session.
   *
   * @param data - The authenticated user object.
   * @param context - The authentication context.
   * @returns {TData} The generated session data.
   */
  buildSessionData(data: unknown, context?: TContext): TData {
    return this.config.createSessionData
      ? this.config.createSessionData(data, context)
      : ({ user: data } as TData);
  }

  /**
   * Retrieves session data using the session ID from the context.
   *
   * @param sessionId
   * @returns {Promise<TData | null>} The session data or null if not found.
   */
  async getSessionData(sessionId: string): Promise<TData | null> {
    try {
      const data = await this.store.getSession<TData>(sessionId);
      return data;
    } catch (error) {
      this.config.logger?.error("Error retrieving session data:", error);
      return null;
    }
  }

  /**
   * Stores session data in the session store.
   *
   * @param sessionId
   * @param data - The session data to store.
   */
  async setSessionData(sessionId: string, data: TData): Promise<void> {
    try {
      if (!sessionId) {
        this.config.logger?.warn("No session ID found, unable to set session.");
        return;
      }
      await this.store.setSession(sessionId, data);
      this.config.logger?.info(`Session set for ID: ${sessionId}`);
    } catch (error) {
      this.config.logger?.error("Error storing session data:", error);
    }
  }

  /**
   * Updates the session's last modified time or refreshes the session data.
   *
   * @param sessionId
   * @param data - The updated session data.
   */
  async touch(sessionId: string, data?: Partial<TData>): Promise<void> {
    try {
      if (!sessionId) {
        this.config.logger?.warn(
          "No session ID found, unable to touch session."
        );
        return;
      }

      const currentSession = await this.store.getSession<TData>(sessionId);
      if (!currentSession) {
        this.config.logger?.warn(`Session not found for ID: ${sessionId}`);
        return;
      }

      const updatedSession = { ...currentSession, ...data };
      await this.store.touchSession(sessionId, updatedSession);
      this.config.logger?.info(`Session touched for ID: ${sessionId}`);
    } catch (error) {
      this.config.logger?.error("Error touching session:", error);
    }
  }

  /**
   * Destroys the session data from the store.
   *
   * @param sessionId
   */
  async destroy(sessionId: string): Promise<void> {
    try {
      if (sessionId) {
        await this.store.destroySession(sessionId);
        this.config.logger?.info(`Session destroyed for ID: ${sessionId}`);
      }
    } catch (error) {
      this.config.logger?.error("Error destroying session:", error);
    }
  }

  /**
   * Checks if the session has expired based on a configurable timeout.
   *
   * @param sessionData - The session data object.
   * @returns {boolean} - True if the session is expired, false otherwise.
   */
  isSessionExpired(sessionData: TData): boolean {
    if (!sessionData || !(sessionData as any).createdAt) {
      return false;
    }

    const now = Date.now();
    const sessionExpiryMs = this.config.cookie?.maxAge || 3600000;
    return now - (sessionData as any).createdAt > sessionExpiryMs;
  }

  async issueSession(
    user: TUser,
    context: TContext
  ): Promise<SessionInfo<TData>> {
    const sessionId = this.getSessionId(context) || this.generateSessionId();

    const data: any = this.config.createSessionData
      ? this.config.createSessionData(user, context)
      : { user };

    await this.store.setSession(sessionId, data);

    this.config.embedSessionId?.(context, sessionId);

    this.logger?.info(`Stored user session with ID: ${sessionId}`);

    return { sessionId, data };
  }

  async logoutSession(context: TContext): Promise<void> {
    const sessionId = this.getSessionId?.(context);
    if (!sessionId) {
      throw new MissingSessionIdError();
    }
    await this.destroy(sessionId);
    this.logger?.info(`Session destroyed: ${sessionId}`);
  }

  /**
   * Clears all sessions from the session store.
   */
  async clearAllSessions(): Promise<void> {
    try {
      if (typeof this.store.destroySession === "function") {
        const sessionIds = await this.store.getSessionIds();
        for (const sessionId of sessionIds) {
          await this.store.destroySession(sessionId);
        }
        this.config.logger?.info("All sessions have been cleared.");
      }
    } catch (error) {
      this.config.logger?.error("Error clearing all sessions:", error);
    }
  }
}
