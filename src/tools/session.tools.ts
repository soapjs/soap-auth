import { v4 as uuidv4 } from "uuid";
import { SessionData } from "../types";

/**
 * Utility class providing default implementations for session-related operations.
 * @class SessionTools
 */
export class SessionTools {
  /**
   * Default method to generate a new session ID.
   * @returns {string} A new unique session ID.
   */
  static defaultGenerateSessionId(): string {
    return uuidv4();
  }

  /**
   * Default method to create initial session data.
   * @param user - Optional user data.
   * @param context - Optional context to base session data on.
   * @returns {SessionData} An object representing initial session data.
   */
  static defaultCreateSessionData(
    user?: unknown,
    context?: unknown
  ): SessionData {
    // Default implementation: return an empty session data object.
    // This can be extended to use context for initializing session values.
    return {};
  }

  /**
   * Default method to deliver a session ID or token.
   * This default implementation does nothing.
   * @param context - The current request/response context.
   * @param value - The session ID or token to deliver.
   */
  static defaultDeliverSessionId(context: any, value: string): void {
    // No-op: does nothing by default
  }
}
