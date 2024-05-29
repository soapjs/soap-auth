/**
 * Configuration for session
 * @typedef {Object} SessionConfig
 * @property {string} secret - Secret for signing the session ID cookie.
 * @property {boolean} resave - Whether to force save the session on every request.
 * @property {boolean} saveUninitialized - Whether to save uninitialized sessions.
 * @property {any} [store] - Session store (e.g., connect-mongo, connect-redis).
 * @property {function} [serializeData] - Function to serialize user to session.
 * @property {function} [deserializeData] - Function to deserialize user from session.
 */
export interface SessionConfig {
  secret: string;
  resave: boolean;
  saveUninitialized: boolean;
  store?: any;
  serializeData?: (data: any, done: (err: any, id?: any) => void) => void;
  deserializeData?: (id: any, done: (err: any, data?: any) => void) => void;
}
