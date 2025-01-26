import { SessionData, SessionStore } from "../types";

const sessions: { [key: string]: SessionData } = {};

/**
 * In-memory implementation of SessionStore.
 * Stores session data in a local JavaScript object.
 */
export class MemorySessionStore implements SessionStore {
  /**
   * Retrieves session data from memory.
   * @param sessionId - The session ID.
   * @returns A promise resolving to the session data or null if not found.
   */
  async getSession<SessionData>(
    sessionId: string
  ): Promise<SessionData | null> {
    return (sessions[sessionId] as SessionData) || null;
  }

  /**
   * Stores session data in memory.
   * @param sessionId - The session ID.
   * @param sessionData - The session data to store.
   * @returns A promise that resolves when the data is stored.
   */
  async setSession<SessionData>(
    sessionId: string,
    sessionData: SessionData
  ): Promise<void> {
    sessions[sessionId] = sessionData;
  }

  /**
   * Removes session data from memory.
   * @param sessionId - The session ID.
   * @returns A promise that resolves when the session is removed.
   */
  async destroySession(sessionId: string): Promise<void> {
    delete sessions[sessionId];
  }

  /**
   * Updates session data in memory.
   * @param sessionId - The session ID.
   * @param session - The updated session data.
   * @returns A promise that resolves when the data is updated.
   */
  async touchSession<SessionData>(
    sessionId: string,
    session: SessionData
  ): Promise<void> {
    sessions[sessionId] = session;
  }
}
