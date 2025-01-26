import fs from "fs/promises";
import path from "path";
import { SessionData, SessionStore } from "../types";

/**
 * File-based implementation of SessionStore.
 * Stores session data as JSON files in a directory.
 */
export class FileSessionStore implements SessionStore {
  constructor(private sessionsDir: string) {}

  /**
   * Initializes the session directory.
   * @returns A promise that resolves when the directory is ready.
   */
  async init(): Promise<void> {
    try {
      await fs.mkdir(this.sessionsDir, { recursive: true });
    } catch (error) {
      console.error("Error initializing session directory:", error);
    }
  }

  /**
   * Retrieves session data from a file corresponding to the session ID.
   * @param sid - The session ID.
   * @returns A promise resolving to the session data or null if not found.
   */
  async getSession<SessionData>(sid: string): Promise<SessionData | null> {
    const sessionPath = path.join(this.sessionsDir, sid);
    try {
      const data = await fs.readFile(sessionPath, "utf8");
      return JSON.parse(data);
    } catch (error) {
      console.error("Error getting session:", error);
      return null;
    }
  }

  /**
   * Writes session data to a file corresponding to the session ID.
   * @param sessionId - The session ID.
   * @param sessionData - The session data to store.
   * @returns A promise that resolves when the data is written.
   */
  async setSession<SessionData>(sessionId: string, sessionData: SessionData): Promise<void> {
    const sessionPath = path.join(this.sessionsDir, sessionId);
    try {
      await fs.writeFile(sessionPath, JSON.stringify(sessionData), "utf8");
    } catch (error) {
      console.error("Error writing session file:", error);
      throw error;
    }
  }

  /**
   * Deletes the session file associated with the given session ID.
   * @param sessionId - The session ID.
   * @returns A promise that resolves when the file is deleted.
   */
  async destroySession(sessionId: string): Promise<void> {
    const sessionPath = path.join(this.sessionsDir, sessionId);
    try {
      await fs.unlink(sessionPath);
    } catch (error) {
      if ((error as any).code !== "ENOENT") {
        console.error("Error destroying session:", error);
        throw error;
      }
    }
  }

  /**
   * Updates session data by rewriting the session file.
   * @param sessionId - The session ID.
   * @param session - The updated session data.
   * @returns A promise that resolves when the file is updated.
   */
  async touchSession(sessionId: string, session: SessionData): Promise<void> {
    await this.setSession(sessionId, session);
  }
}
